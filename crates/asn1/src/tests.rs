//! Tests del codec DER: round-trips, casos límite de enteros/longitudes,
//! flags, tiempos y rutas de error. Todo se valida byte a byte.

use crate::*;

// ---------- helpers ----------

fn rt(bytes: &[u8]) -> Element<'_> {
    let mut r = DerReader::new(bytes);
    let el = r.next().expect("un elemento").expect("no vacío");
    r.finish().expect("sin bytes sobrantes");
    el
}

// ---------- TLV básicos ----------

#[test]
fn roundtrip_integer_edge_cases() {
    let cases: Vec<i64> = vec![
        0, 1, 127, 128, 129, 255, 256, 32767, 32768, 65535, 65536, i32::MAX as i64,
        i32::MAX as i64 + 1, i64::MAX, -1, -2, -128, -129, -32768, -32769, i32::MIN as i64 - 1,
        i64::MIN, 5_000_000_000,
    ];
    for v in cases {
        let tlv = encode_integer(v);
        let back = rt(&tlv).parse_int_i64().expect("int válido");
        assert_eq!(back, v, "round-trip de {v}");
        // Minimidad DER: un 0x00 inicial solo es legítimo si el siguiente
        // byte tiene el bit alto (p. ej. 128 = 00 80).
        let el = rt(&tlv);
        if v >= 0 && el.content.len() > 1 {
            assert!(
                el.content[0] != 0x00 || el.content[1] >= 0x80,
                "entero {v} no canónico"
            );
        }
    }
}

#[test]
fn integer_known_encodings() {
    // Vectores X.690 clásicos.
    assert_eq!(encode_integer(0), vec![0x02, 0x01, 0x00]);
    assert_eq!(encode_integer(127), vec![0x02, 0x01, 0x7F]);
    assert_eq!(encode_integer(128), vec![0x02, 0x02, 0x00, 0x80]);
    assert_eq!(encode_integer(256), vec![0x02, 0x02, 0x01, 0x00]);
    assert_eq!(encode_integer(-128), vec![0x02, 0x01, 0x80]);
    assert_eq!(encode_integer(-129), vec![0x02, 0x02, 0xFF, 0x7F]);
}

#[test]
fn integer_rejects_non_representable() {
    // Vacío.
    let err = rt(&[0x02, 0x00]).parse_int_i64();
    assert!(matches!(err, Err(Asn1Error::BadInteger)));
    // 9 bytes: fuera de rango i64.
    let err = rt(&[0x02, 0x09, 1, 2, 3, 4, 5, 6, 7, 8, 9]).parse_int_i64();
    assert!(matches!(err, Err(Asn1Error::BadInteger)));
    // Un entero de 8 bytes con bit alto es exactamente i64::MIN: válido.
    let min = rt(&[0x02, 0x08, 0x80, 0, 0, 0, 0, 0, 0, 0]).parse_int_i64();
    assert_eq!(min.unwrap(), i64::MIN);
}

#[test]
fn integer_accepts_non_minimal_decode() {
    // Leniencia deliberada (ADR-001): algunos KDCs mal codifican.
    // "02 02 00 05" = 5 con byte 0x00 redundante → se decodifica igual.
    let el = rt(&[0x02, 0x02, 0x00, 0x05]);
    assert_eq!(el.parse_int_i64().unwrap(), 5);
}

#[test]
fn length_forms() {
    for len in [0usize, 1, 127, 128, 129, 255, 256, 1000, 65536] {
        let content = vec![0xAB; len];
        let tlv = encode_octets(&content);
        let el = rt(&tlv);
        assert_eq!(el.content.len(), len);
        if len == 128 {
            assert_eq!(&tlv[..3], &[0x04, 0x81, 0x80]);
        }
        if len == 256 {
            assert_eq!(&tlv[..4], &[0x04, 0x82, 0x01, 0x00]);
        }
    }
}

#[test]
fn rejects_indefinite_length() {
    // 30 80 ... 00 00 es BER indefinida: DER la prohíbe.
    let err = DerReader::new(&[0x30, 0x80, 0x02, 0x01, 0x01, 0x00, 0x00]).next();
    assert!(matches!(err, Err(Asn1Error::IndefiniteLength)));
}

#[test]
fn rejects_nonminimal_long_length() {
    // 04 82 00 05 + contenido: forma larga con byte inicial 0x00 → inválida.
    let err = DerReader::new(&[0x04, 0x82, 0x00, 0x05, 1, 2, 3, 4, 5]).next();
    assert!(matches!(err, Err(Asn1Error::BadLengthForm { nbytes: 2 })));
}

// ---------- contexto y secuencias ----------

#[test]
fn context_wrapping_roundtrip() {
    let inner = encode_integer(5);
    let wrapped = encode_context_wrapped(1, &inner).unwrap();
    let mut r = DerReader::new(&wrapped);
    let outer = r.context_child_req(1).unwrap();
    assert_eq!(outer.unwrap_context().unwrap().parse_int_i64().unwrap(), 5);
    r.finish().unwrap();
}

#[test]
fn optional_context_child_leaves_stream() {
    let a = encode_integer(1);
    let b = encode_string("hola");
    let both = encode_sequence(&[
        encode_context_wrapped(2, &a).unwrap(),
        encode_context_wrapped(3, &b).unwrap(),
    ])
    .unwrap();
    let el = rt(&both);
    let mut seq = el.parse_seq().unwrap();
    // El campo [3] aún no llegó en orden de lectura: context_child(3) no
    // debe consumir [2].
    assert!(seq.context_child(3).unwrap().is_none());
    let two = seq.context_child_req(2).unwrap();
    assert_eq!(two.unwrap_context().unwrap().parse_int_i64().unwrap(), 1);
    let three = seq.context_child_req(3).unwrap();
    assert_eq!(three.unwrap_context().unwrap().parse_str().unwrap(), "hola");
    seq.finish().unwrap();
}

#[test]
fn sequence_and_trailing_bytes() {
    let a = encode_integer(1);
    let b = encode_integer(2);
    let seq = encode_sequence(&[a, b]).unwrap();
    let el = rt(&seq);
    let mut r = el.parse_seq().unwrap();
    assert_eq!(r.next_tag(Tag::INTEGER).unwrap().parse_int_i64().unwrap(), 1);
    assert_eq!(r.next_tag(Tag::INTEGER).unwrap().parse_int_i64().unwrap(), 2);
    r.finish().unwrap();

    let bad = [seq.as_slice(), &[0x00u8]].concat();
    let mut r2 = DerReader::new(&bad);
    r2.next().unwrap();
    assert!(matches!(r2.finish(), Err(Asn1Error::TrailingBytes(1))));
}

// ---------- flags (BIT STRING numerada) ----------

fn bit(n: u32) -> u32 {
    // Bit n de un BIT STRING Kerberos: bit 0 = MSB del primer byte.
    if n >= 32 {
        0
    } else {
        1u32 << (31 - n)
    }
}

#[test]
fn flags_roundtrip() {
    let cases: Vec<u32> = vec![
        0,
        bit(1),                          // forwardable
        bit(8),                          // renewable
        bit(1) | bit(8) | bit(22),       // forwardable+renewable+canonicalize
        bit(0),                          // bit más alto posible
        u32::MAX,                        // todos
        bit(31),                         // bit más bajo posible
    ];
    for f in cases {
        let tlv = encode_flags(f);
        assert_eq!(rt(&tlv).parse_flags_u32().unwrap(), f, "round-trip de flags {f:#x}");
    }
}

#[test]
fn flags_minimal_encoding_known_bytes() {
    // bits {1, 8}: el bit más alto es el 8 → 2 bytes, 7 bits sin usar.
    let tlv = encode_flags(bit(1) | bit(8));
    assert_eq!(tlv, vec![0x03, 0x03, 0x07, 0x40, 0x80]);
    // Solo el bit 31 → 4 bytes, 0 bits sin usar.
    let tlv = encode_flags(bit(31));
    assert_eq!(tlv, vec![0x03, 0x05, 0x00, 0x00, 0x00, 0x00, 0x01]);
}

#[test]
fn bitstring_rejects_bad_unused() {
    // 03 02 09 41: bits sin usar = 9 → inválido.
    let err = rt(&[0x03, 0x02, 0x09, 0x41]).parse_bitstring();
    assert!(matches!(err, Err(Asn1Error::BadBitString(9))));
}

// ---------- tiempos ----------

#[test]
fn time_known_values() {
    // Valores epoch verificados con `date -u -d`:
    // 2025-01-15 10:30:45 UTC = 1736937045
    assert_eq!(KrbTime::from_wire("20250115103045Z").unwrap().unix_secs, 1_736_937_045);
    assert_eq!(KrbTime::from_unix(1_736_937_045).to_wire(), "20250115103045Z");
    // Época.
    assert_eq!(KrbTime::from_unix(0).to_wire(), "19700101000000Z");
    assert_eq!(KrbTime::from_wire("19700101000000Z").unwrap().unix_secs, 0);
    // 29 de febrero de 2024 (bisiesto) 23:59:59 = 1709251199
    assert_eq!(KrbTime::from_wire("20240229235959Z").unwrap().unix_secs, 1_709_251_199);
    // 1 de enero de 2024 = 1704067200
    assert_eq!(KrbTime::from_wire("20240101000000Z").unwrap().unix_secs, 1_704_067_200);
}

#[test]
fn time_roundtrip_sweep() {
    // Barre puntos esquineros (fin de día, fin de mes, fin de año, bisiestos).
    for secs in [
        0i64, 86_399, 951_782_400, 1_078_019_999, 1_500_000_000, 1_709_251_199, 2_000_000_000,
        4_102_444_799,
    ] {
        let t = KrbTime::from_unix(secs);
        let s = t.to_wire();
        assert_eq!(KrbTime::from_wire(&s).unwrap(), t, "round-trip {s}");
    }
}

#[test]
fn time_arithmetic() {
    let t = KrbTime::from_wire("20250115103045Z").unwrap();
    assert_eq!(t.plus_secs(60).to_wire(), "20250115103145Z");
    assert_eq!(t.plus_secs(3600 * 24).to_wire(), "20250116103045Z");
    assert_eq!(t.diff_secs(t.plus_secs(90)), 90);
}

#[test]
fn time_rejects_garbage() {
    for bad in [
        "20250115103045",      // sin Z
        "2025-01-15T10:30Z",   // formato ISO
        "20250115103045.123Z", // fracciones: RFC 4120 no las usa
        "20251315103045Z",     // mes 13
        "20250230103045Z",     // 30 de febrero
        "20230229103045Z",     // 29 de febrero no bisiesto
        "2025011510306Z",      // longitud incorrecta
        "20250115103045X",     // terminador incorrecto
        "202501151030450Z",    // longitud incorrecta
        "2025A115103045Z",     // no dígito
    ] {
        assert!(KrbTime::from_wire(bad).is_err(), "debía rechazar '{bad}'");
    }
}

// ---------- muestra canónica (snapshot de compatibilidad) ----------

#[test]
fn canonical_krb_error_sample() {
    // KRB-ERROR mínimo con la numeración no consecutiva de RFC 4120 §5.9.1:
    // pvno [0], msg-type [1], stime [4], susec [5], error-code [6].
    let pvno = encode_context_wrapped(0, &encode_integer(5)).unwrap();
    let msg_type = encode_context_wrapped(1, &encode_integer(30)).unwrap();
    let stime = encode_context_wrapped(4, &encode_time(KrbTime::from_wire("20250115103045Z").unwrap())).unwrap();
    let susec = encode_context_wrapped(5, &encode_integer(123_456)).unwrap();
    let ecode = encode_context_wrapped(6, &encode_integer(25)).unwrap();
    let body = encode_sequence(&[pvno, msg_type, stime, susec, ecode]).unwrap();
    let full = encode_tlv(Tag::application(30, true), &body).unwrap();

    let el = rt(&full);
    assert_eq!(el.tag, Tag::application(30, true));
    // [APPLICATION 30] envuelve una SEQUENCE: desenvolver y leer sus campos.
    let mut outer = el.content_reader();
    let body = outer.next_tag(Tag::SEQUENCE).unwrap();
    outer.finish().unwrap();
    let mut seq = body.parse_seq().unwrap();
    assert_eq!(
        seq.context_child_req(0).unwrap().unwrap_context().unwrap().parse_int_i64().unwrap(),
        5
    );
    assert_eq!(
        seq.context_child_req(1).unwrap().unwrap_context().unwrap().parse_int_i64().unwrap(),
        30
    );
    assert_eq!(
        seq.context_child_req(4).unwrap().unwrap_context().unwrap().parse_time().unwrap(),
        KrbTime::from_wire("20250115103045Z").unwrap()
    );
    assert_eq!(
        seq.context_child_req(5).unwrap().unwrap_context().unwrap().parse_int_u32().unwrap(),
        123_456
    );
    assert_eq!(
        seq.context_child_req(6).unwrap().unwrap_context().unwrap().parse_int_u32().unwrap(),
        25
    );
    seq.finish().unwrap();
}

// ---------- boolean y strings ----------

#[test]
fn boolean_and_string_roundtrip() {
    assert!(rt(&encode_bool(true)).parse_bool().unwrap());
    assert!(!rt(&encode_bool(false)).parse_bool().unwrap());
    // Boolean true canónico DER es 0xFF.
    assert_eq!(encode_bool(true), vec![0x01, 0x01, 0xFF]);

    let s = "LAB.LOCALjdoe";
    assert_eq!(rt(&encode_string(s)).parse_str().unwrap(), s);
    let bytes = [0u8, 1, 254, 255];
    assert_eq!(rt(&encode_octets(&bytes)).parse_bytes().unwrap(), &bytes);
    let aligned = [1u8, 2, 3, 4];
    assert_eq!(
        rt(&encode_bitstring_aligned(&aligned)).parse_bitstring().unwrap(),
        (&aligned[..], 0u8)
    );
}
