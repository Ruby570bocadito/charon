//! Validación cruzada del codec contra `openssl asn1parse` (OpenSSL 3.x).
//!
//! Es el oráculo independiente del codec: los bytes que Charon produce
//! deben ser parseables y describibles por una implementación ASN.1
//! ajena. Si openssl no está instalado, el test se salta a sí mismo
//! (no es un fallo del proyecto, es un entorno sin oráculo).

use charon_asn1::*;

fn openssl_available() -> bool {
    std::process::Command::new("openssl")
        .arg("version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn cross_parse(name: &str, der: &[u8]) -> String {
    let dir = std::env::temp_dir();
    let path = dir.join(format!("charon-asn1-xcheck-{name}.der"));
    std::fs::write(&path, der).expect("escribir muestra DER");
    let out = std::process::Command::new("openssl")
        .args(["asn1parse", "-i", "-inform", "DER", "-in"])
        .arg(&path)
        .output()
        .expect("ejecutar openssl");
    std::fs::remove_file(&path).ok();
    assert!(
        out.status.success(),
        "openssl rechazó {name}: {}\n{}",
        String::from_utf8_lossy(&out.stderr),
        String::from_utf8_lossy(&out.stdout)
    );
    String::from_utf8_lossy(&out.stdout).into_owned()
}

#[test]
fn openssl_parses_charon_output() {
    if !openssl_available() {
        eprintln!("openssl no disponible: test de validación cruzada omitido");
        return;
    }

    // 1) KRB-ERROR canónico (la muestra de los tests unitarios).
    let pvno = encode_context_wrapped(0, &encode_integer(5)).unwrap();
    let msg_type = encode_context_wrapped(1, &encode_integer(30)).unwrap();
    let stime = encode_context_wrapped(
        4,
        &encode_time(KrbTime::from_wire("20250115103045Z").unwrap()),
    )
    .unwrap();
    let susec = encode_context_wrapped(5, &encode_integer(123_456)).unwrap();
    let ecode = encode_context_wrapped(6, &encode_integer(25)).unwrap();
    let body = encode_sequence(&[pvno, msg_type, stime, susec, ecode]).unwrap();
    let krb_error = encode_tlv(Tag::application(30, true), &body).unwrap();
    let text = cross_parse("krb-error", &krb_error);
    assert!(text.contains("SEQUENCE"), "falta SEQUENCE en openssl:\n{text}");
    assert!(text.contains("[4]"), "falta stime [4] en openssl:\n{text}");
    assert!(
        text.contains("GENERALIZEDTIME") || text.contains("Genera"),
        "falta el tiempo en openssl:\n{text}"
    );

    // 2) Flags (BIT STRING numerada con relleno).
    let bits = (1u32 << 30) | (1u32 << 23); // forwardable + renewable
    let flags = encode_flags(bits);
    let text = cross_parse("flags", &flags);
    assert!(text.contains("BIT STRING"), "flags no reconocidas:\n{text}");

    // 3) Enteros esquineros.
    let ints = encode_sequence(&[
        encode_integer(-129),
        encode_integer(256),
        encode_integer(i64::MIN),
    ])
    .unwrap();
    let text = cross_parse("integers", &ints);
    assert!(text.contains("INTEGER"), "enteros no reconocidos:\n{text}");

    // 4) Longitudes multibyte (contenido > 127 bytes).
    let big = encode_octets(&vec![0x41u8; 300]);
    cross_parse("big-octets", &big);
}
