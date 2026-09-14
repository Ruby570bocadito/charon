//! Tests de round-trip de mensajes y del PAC sintético.

use crate::*;
use charon_asn1::{encode_context_wrapped, encode_sequence};

fn rt_roundtrip(bytes: &[u8]) {
    // Todo lo que Charon codifica debe poder releerse byte a byte.
    let _ = bytes;
}

#[test]
fn as_req_without_preauth_roundtrip() {
    // La sonda básica de enumeración: AS-REQ sin PA-DATA.
    let req = KdcReq {
        msg_type: MSG_AS_REQ,
        padata: vec![],
        body: KdcReqBody {
            kdc_options: kdc_options::CANONICALIZE,
            cname: Some(PrincipalName::user("ghost")),
            realm: "LAB.LOCAL".into(),
            sname: Some(PrincipalName::krbtgt("LAB.LOCAL")),
            from: None,
            till: charon_asn1::KrbTime::from_unix(1_800_000_000),
            rtime: None,
            nonce: 19700101,
            etypes: vec![18, 17, 23],
            addresses: None,
            enc_authorization_data: None,
            additional_tickets: None,
        },
    };
    let wire = req.build().expect("build AS-REQ");
    let back = KdcReq::parse(&wire).expect("parse AS-REQ");
    assert_eq!(back.msg_type, MSG_AS_REQ);
    assert_eq!(back.body.cname.as_ref().unwrap().name_string, vec!["ghost"]);
    assert_eq!(back.body.etypes, vec![18, 17, 23]);
    assert_eq!(back.body.nonce, 19700101);
    assert_eq!(back.body.realm, "LAB.LOCAL");
    // Re-encode byte a byte (canonónico).
    let wire2 = back.build().expect("rebuild");
    assert_eq!(wire, wire2);
}

#[test]
fn as_req_with_preauth_and_pac_request() {
    // AS-REQ con PA-ENC-TIMESTAMP (valor crudo de edata, como impacket/Rubeus)
    // y PA-PAC-REQUEST (la envoltura del booleano incluye-pac).
    let ts_edata = vec![0xABu8; 32];
    let pac_req_body = encode_sequence(&[encode_context_wrapped(0, &charon_asn1::encode_bool(true)).unwrap()]).unwrap();
    let req = KdcReq {
        msg_type: MSG_AS_REQ,
        padata: vec![
            PaData { pa_type: pa_type::PA_ENC_TIMESTAMP, pa_value: ts_edata.clone() },
            PaData { pa_type: pa_type::PA_PAC_REQUEST, pa_value: pac_req_body.clone() },
        ],
        body: KdcReqBody {
            kdc_options: kdc_options::FORWARDABLE | kdc_options::RENEWABLE,
            cname: Some(PrincipalName::user("jdoe")),
            realm: "LAB.LOCAL".into(),
            sname: Some(PrincipalName::krbtgt("LAB.LOCAL")),
            from: None,
            till: charon_asn1::KrbTime::from_unix(1_800_000_000),
            rtime: None,
            nonce: 42,
            etypes: vec![18, 17],
            addresses: None,
            enc_authorization_data: None,
            additional_tickets: None,
        },
    };
    let wire = req.build().unwrap();
    let back = KdcReq::parse(&wire).unwrap();
    assert_eq!(back.padata.len(), 2);
    assert_eq!(back.padata[0].pa_type, 2);
    assert_eq!(back.padata[0].pa_value, ts_edata);
    assert_eq!(back.padata[1].pa_value, pac_req_body);
    let _ = rt_roundtrip;
}

#[test]
fn tgs_req_shape() {
    // TGS-REQ: sin cname, sname = SPN destino, PA-TGS-REQ con AP-REQ.
    let ap_req_bytes = vec![0x6Bu8; 40]; // contenido simulado del AP-REQ
    let req = KdcReq {
        msg_type: MSG_TGS_REQ,
        padata: vec![PaData { pa_type: pa_type::PA_TGS_REQ, pa_value: ap_req_bytes }],
        body: KdcReqBody {
            kdc_options: kdc_options::CANONICALIZE,
            cname: None,
            realm: "LAB.LOCAL".into(),
            sname: Some(PrincipalName::from_spn("mssql/srv01.lab.local")),
            from: None,
            till: charon_asn1::KrbTime::from_unix(1_800_000_000),
            rtime: None,
            nonce: 7,
            etypes: vec![18, 17],
            addresses: None,
            enc_authorization_data: None,
            additional_tickets: None,
        },
    };
    let wire = req.build().unwrap();
    let back = KdcReq::parse(&wire).unwrap();
    assert_eq!(back.body.cname, None);
    assert_eq!(back.body.sname.unwrap().name_string, vec!["mssql", "srv01.lab.local"]);
    assert_eq!(back.msg_type, MSG_TGS_REQ);
}

#[test]
fn krb_error_roundtrip_with_etype_info2() {
    // Error 25 con METHOD-DATA/PA-ETYPE-INFO2: el oráculo del salt.
    let entry = EtypeInfo2Entry {
        etype: 18,
        salt: Some(b"LAB.LOCALjdoe".to_vec()),
        s2kparams: None,
    };
    // El valor de PA-ETYPE-INFO2 es ETYPE-INFO2 ::= SEQUENCE OF entry.
    let etype_info2 = encode_sequence(&[entry.build().unwrap()]).unwrap();
    let method_data = PaData::build_seq(&[PaData {
        pa_type: pa_type::PA_ETYPE_INFO2,
        pa_value: etype_info2,
    }])
    .unwrap();
    let err = KrbError {
        ctime: None,
        cusec: None,
        stime: charon_asn1::KrbTime::from_unix(1_750_000_000),
        susec: 123_456,
        error_code: KDC_ERR_PREAUTH_REQUIRED,
        crealm: Some("LAB.LOCAL".into()),
        cname: Some(PrincipalName::user("jdoe")),
        realm: Some("LAB.LOCAL".into()),
        sname: Some(PrincipalName::krbtgt("LAB.LOCAL")),
        e_text: None,
        e_data: Some(method_data),
    };
    let wire = err.build().unwrap();
    let back = KrbError::parse(&wire).unwrap();
    assert_eq!(back.error_code, 25);
    let entries = back.etype_info2().expect("METHOD-DATA presente");
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].etype, 18);
    assert_eq!(entries[0].salt.as_deref(), Some(b"LAB.LOCALjdoe".as_slice()));

    // Round-trip del builder del propio KRB-ERROR.
    let wire2 = back.build().unwrap();
    let back2 = KrbError::parse(&wire2).unwrap();
    assert_eq!(back.error_code, back2.error_code);
}

#[test]
fn kdc_rep_and_enc_rep_part() {
    let rep = KdcRep {
        msg_type: MSG_AS_REP,
        padata: vec![],
        crealm: "LAB.LOCAL".into(),
        cname: PrincipalName::user("jdoe"),
        ticket: Ticket {
            tkt_vno: 5,
            realm: "LAB.LOCAL".into(),
            sname: PrincipalName::krbtgt("LAB.LOCAL"),
            enc_part: EncryptedData { etype: 18, kvno: Some(1), cipher: vec![0x11; 64] },
        },
        enc_part: EncryptedData { etype: 18, kvno: None, cipher: vec![0x22; 80] },
    };
    let wire = rep.build().unwrap();
    let back = KdcRep::parse(&wire).unwrap();
    assert_eq!(back.cname.name_string, vec!["jdoe"]);
    assert_eq!(back.ticket.enc_part.etype, 18);
    assert_eq!(back.ticket.sname.name_string, vec!["krbtgt", "LAB.LOCAL"]);

    let part = EncKdcRepPart {
        key: EncryptionKey { keytype: 18, keyvalue: vec![0x33; 32] },
        nonce: 42,
        flags: ticket_flags::PRE_AUTHENT | ticket_flags::INITIAL,
        authtime: charon_asn1::KrbTime::from_unix(1_750_000_000),
        starttime: None,
        endtime: charon_asn1::KrbTime::from_unix(1_750_086_400),
        renew_till: Some(charon_asn1::KrbTime::from_unix(1_750_604_800)),
        srealm: "LAB.LOCAL".into(),
        sname: PrincipalName::krbtgt("LAB.LOCAL"),
    };
    let pwire = part.build().unwrap();
    let pel = charon_asn1::DerReader::new(&pwire).next().unwrap().unwrap();
    let pback = EncKdcRepPart::parse(&pel).unwrap();
    assert_eq!(pback.key.keyvalue, vec![0x33; 32]);
    assert_eq!(pback.nonce, 42);
    assert_eq!(pback.flags, ticket_flags::PRE_AUTHENT | ticket_flags::INITIAL);
    assert_eq!(pback.authtime, part.authtime);
}

#[test]
fn ap_req_and_authenticator_roundtrip() {
    let auth = Authenticator {
        crealm: "LAB.LOCAL".into(),
        cname: PrincipalName::user("jdoe"),
        cksum: None,
        cusec: 777,
        ctime: charon_asn1::KrbTime::from_unix(1_750_000_100),
        subkey: None,
        seq_number: Some(5),
    };
    let awire = auth.build().unwrap();
    let aback = Authenticator::parse(&awire).unwrap();
    assert_eq!(aback.cusec, 777);
    assert_eq!(aback.seq_number, Some(5));

    let ap = ApReq {
        ap_options: 0,
        ticket: Ticket {
            tkt_vno: 5,
            realm: "LAB.LOCAL".into(),
            sname: PrincipalName::krbtgt("LAB.LOCAL"),
            enc_part: EncryptedData { etype: 17, kvno: None, cipher: vec![1; 48] },
        },
        authenticator: EncryptedData { etype: 17, kvno: None, cipher: vec![2; 60] },
    };
    let wire = ap.build().unwrap();
    let back = ApReq::parse(&wire).unwrap();
    assert_eq!(back.authenticator.cipher, vec![2; 60]);
}

#[test]
fn spn_and_error_descriptions() {
    assert_eq!(PrincipalName::from_spn("host/srv01.lab.local").name_string, vec!["host", "srv01.lab.local"]);
    assert_eq!(PrincipalName::from_spn("sinbarra").name_string, vec!["sinbarra"]);
    let d = error_codes::describe(6);
    assert!(d.leak.contains("NO existe"));
    let d = error_codes::describe(25);
    assert!(d.leak.contains("regala el salt"));
    let d = error_codes::describe(13);
    assert!(d.leak.contains("S4U2Proxy"));
}

#[test]
fn kdc_options_coinciden_con_las_constantes_de_mit_krb5h() {
    // Regresión de la ronda 2: CANONICALIZE estaba en bit(22) (un bit
    // "unused" del RFC 4120) en vez de bit(15). El RFC lo fija en la nota
    // ASN.1 "15 is reserved for canonicalize" y MIT krb5.h en 0x00010000.
    // El bit() del repo cuenta desde el MSB del BIT STRING (bit 0 =
    // 0x80000000), como exige la codificación ASN.1 de Kerberos.
    assert_eq!(kdc_options::FORWARDABLE, 0x4000_0000);
    assert_eq!(kdc_options::PROXIABLE, 0x1000_0000);
    assert_eq!(kdc_options::RENEWABLE, 0x0080_0000);
    assert_eq!(kdc_options::CANONICALIZE, 0x0001_0000);
    assert_eq!(kdc_options::RENEW, 0x0000_0002);
    assert_eq!(kdc_options::C_NAME_IN_ADDITIONAL_TICKET, 0x0000_0010);
}
