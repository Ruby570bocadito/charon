//! Tests de integración contra un KDC MIT krb5 real (lab/setup-mit-kdc.sh).
//!
//! Son las pruebas de fuego del proyecto: bytes construidos por Charon,
//! aceptados por una implementación de referencia. Si el KDC no está
//! levantado, se saltan con instrucciones (no son fallos del código).

use charon_client::*;
use charon_krb5::kdc_options;
use charon_kcrypto::{etype, KerberosKey};

const HOST: &str = "127.0.0.1";
const PORT: u16 = 1088;
const REALM: &str = "LAB.LOCAL";

fn kdc_available() -> bool {
    let conn = KdcConnection::new(HOST, PORT);
    conn.send_udp(&[0x00; 8]).is_ok() || conn.send_tcp(&[0x00; 8]).is_ok()
}

fn conn() -> KdcConnection {
    KdcConnection::new(HOST, PORT)
}

#[test]
fn t01_unknown_user_returns_error_6() {
    if !kdc_available() {
        eprintln!("SKIP: KDC no disponible — ejecuta lab/setup-mit-kdc.sh");
        return;
    }
    let probe = probe_as_no_preauth(&conn(), "ghost-inexistente", REALM, &[23]).unwrap();
    match probe {
        AsProbe::PrincipalUnknown { .. } => {}
        other => panic!("esperaba PrincipalUnknown, obtuve {:?}", other_desc(&other)),
    }
}

#[test]
fn t02_existing_user_returns_25_and_salt() {
    if !kdc_available() {
        eprintln!("SKIP: KDC no disponible");
        return;
    }
    let probe = probe_as_no_preauth(&conn(), "jdoe", REALM, &[18, 17]).unwrap();
    match probe {
        AsProbe::PreauthRequired { salts, .. } => {
            let salt = salts
                .iter()
                .find(|s| s.etype == etype::AES256_CTS_HMAC_SHA1_96)
                .expect("el error 25 regala el salt AES");
            assert_eq!(salt.salt.as_deref(), Some(b"LAB.LOCALjdoe".as_slice()));
        }
        other => panic!("esperaba PreauthRequired, obtuve {:?}", other_desc(&other)),
    }
}

#[test]
fn t03_nopreauth_account_is_roasteable() {
    if !kdc_available() {
        eprintln!("SKIP: KDC no disponible");
        return;
    }
    let probe = probe_as_no_preauth(&conn(), "nopreauth", REALM, &[18, 23]).unwrap();
    match probe {
        AsProbe::NoPreauth { reply, .. } => {
            assert!(reply.enc_part.cipher.len() > 16);
            let et = reply.enc_part.etype;
            assert!(et == 18 || et == 17 || et == 23, "etype inesperado {et}");
        }
        other => panic!("esperaba NoPreauth, obtuve {:?}", other_desc(&other)),
    }
}

#[test]
fn t04_tgt_with_rc4() {
    if !kdc_available() {
        eprintln!("SKIP: KDC no disponible");
        return;
    }
    let key = KerberosKey::from_password("Jdoe!Pass42", "LAB.LOCALjdoe", etype::RC4_HMAC).unwrap();
    let tgt = request_tgt(&conn(), "jdoe", REALM, &key, &[23], kdc_options::FORWARDABLE | kdc_options::RENEWABLE).unwrap();
    assert_eq!(tgt.crealm, REALM);
    assert_eq!(tgt.cname, "jdoe");
    assert_eq!(tgt.ticket.sname.name_string, vec!["krbtgt", "LAB.LOCAL"]);
    assert_eq!(tgt.session_key.keytype, 18, "MIT emite sesión AES256 por defecto");
    assert!(tgt.flags & charon_krb5::ticket_flags::INITIAL != 0);
}

#[test]
fn t05_tgt_with_aes256() {
    if !kdc_available() {
        eprintln!("SKIP: KDC no disponible");
        return;
    }
    // La clave AES se deriva del salt aprendido en el error 25 (t02):
    // el flujo real de un analista.
    let key = KerberosKey::from_password("Jdoe!Pass42", "LAB.LOCALjdoe", etype::AES256_CTS_HMAC_SHA1_96).unwrap();
    let tgt = request_tgt(&conn(), "jdoe", REALM, &key, &[18], kdc_options::FORWARDABLE).unwrap();
    assert_eq!(tgt.session_key.keytype, 18);
    // El preauth con clave AES aceptado = toda la cadena PBKDF2+DK+CTS+HMAC correcta.
}

#[test]
fn t06_wrong_password_returns_preauth_failed() {
    if !kdc_available() {
        eprintln!("SKIP: KDC no disponible");
        return;
    }
    let key = KerberosKey::from_password("Contrasena!Incorrecta", "LAB.LOCALjdoe", etype::RC4_HMAC).unwrap();
    let err = request_tgt(&conn(), "jdoe", REALM, &key, &[23], 0).unwrap_err();
    assert!(format!("{err}").contains("PREAUTH_FAILED"), "error inesperado: {err}");
}

#[test]
fn t07_pass_the_key_with_nt_hash() {
    if !kdc_available() {
        eprintln!("SKIP: KDC no disponible");
        return;
    }
    // NT hash de "Jdoe!Pass42" (MD4 de UTF-16LE) usado directamente:
    // sin contraseña, sin cracking.
    let utf16: Vec<u8> = "Jdoe!Pass42".encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
    let nt = charon_kcrypto::rc4hmac::nt_hash(&utf16);
    let key = KerberosKey::from_raw(etype::RC4_HMAC, &nt).unwrap();
    let tgt = request_tgt(&conn(), "jdoe", REALM, &key, &[23], 0).unwrap();
    assert_eq!(tgt.cname, "jdoe");
}

#[test]
fn t08_tgs_aes_first_and_rc4_only() {
    if !kdc_available() {
        eprintln!("SKIP: KDC no disponible");
        return;
    }
    let key = KerberosKey::from_password("Jdoe!Pass42", "LAB.LOCALjdoe", etype::AES256_CTS_HMAC_SHA1_96).unwrap();
    let tgt = request_tgt(&conn(), "jdoe", REALM, &key, &[18], kdc_options::FORWARDABLE).unwrap();

    // AES-first contra una cuenta de servicio con AES: el ticket sale en
    // etype 18 — sin downgrade (la OPSEC que diferencia a Charon).
    let st = request_service_ticket(&conn(), &tgt, "mssql/srv01.lab.local", &[18, 17], kdc_options::CANONICALIZE | kdc_options::FORWARDABLE).unwrap();
    assert_eq!(st.ticket.sname.name_string, vec!["mssql", "srv01.lab.local"]);
    assert_eq!(st.ticket.enc_part.etype, etype::AES256_CTS_HMAC_SHA1_96, "ticket debe salir en AES256 (sin downgrade)");

    // Pidiendo el rango completo contra la cuenta RC4-only: el KDC
    // responde con el etype que la cuenta soporta (23).
    let st2 = request_service_ticket(&conn(), &tgt, "legacy", &[18, 17, 23], 0).unwrap();
    assert_eq!(st2.ticket.enc_part.etype, etype::RC4_HMAC, "legacy solo tiene RC4");

    // SPN inexistente → error 7 del KDC.
    let err = request_service_ticket(&conn(), &tgt, "noexiste/svc", &[18, 23], 0).unwrap_err();
    assert!(format!("{err}").contains("S_PRINCIPAL_UNKNOWN"), "error inesperado: {err}");
}

#[test]
fn t09_pac_extractable_from_service_ticket() {
    if !kdc_available() {
        eprintln!("SKIP: KDC no disponible");
        return;
    }
    // Pedimos el ticket de servicio de nuestra propia cuenta de servicio
    // (cuya clave larga conocemos en el lab) y desciframos el ticket con
    // ella (usage 2) para leer el PAC de jdoe: el flujo de análisis de PAC.
    let svc_key = KerberosKey::from_password("Mssql!Svc01", "LAB.LOCALmssql/srv01.lab.local", etype::AES256_CTS_HMAC_SHA1_96).unwrap();
    let user_key = KerberosKey::from_password("Jdoe!Pass42", "LAB.LOCALjdoe", etype::AES256_CTS_HMAC_SHA1_96).unwrap();
    let user_tgt = request_tgt(&conn(), "jdoe", REALM, &user_key, &[18], 0).unwrap();
    let st = request_service_ticket(&conn(), &user_tgt, "mssql/srv01.lab.local", &[18, 17], 0).unwrap();
    let pac = charon_krb5::pac::extract_pac(&st.ticket, &svc_key);
    match pac {
        Ok(p) => {
            let info = p.logon_info().expect("el PAC debe llevar LOGON_INFO");
            assert_eq!(info.account, "jdoe", "el PAC identifica al usuario autenticado");
            assert!(info.user_rid > 1000);
            assert!(!info.groups.is_empty());
        }
        Err(e) => panic!("no se pudo extraer el PAC: {e}"),
    }
}

#[test]
fn t10_udp_tcp_strategy_and_response_sizes() {
    if !kdc_available() {
        eprintln!("SKIP: KDC no disponible");
        return;
    }
    let key = KerberosKey::from_password("Jdoe!Pass42", "LAB.LOCALjdoe", etype::AES256_CTS_HMAC_SHA1_96).unwrap();
    let req = build_as_req("jdoe", REALM, Some(&key), &[18], true, 0).unwrap();
    let (reply, transport) = conn().exchange(&req.build().unwrap()).unwrap();
    assert!(matches!(transport, Transport::Udp | Transport::Tcp));
    assert!(reply.len() > 100, "respuesta demasiado corta");
}

fn other_desc(p: &AsProbe) -> String {
    match p {
        AsProbe::PreauthRequired { .. } => "PreauthRequired".to_string(),
        AsProbe::NoPreauth { .. } => "NoPreauth".to_string(),
        AsProbe::PrincipalUnknown { .. } => "PrincipalUnknown".to_string(),
        AsProbe::PreauthFailed { .. } => "PreauthFailed".to_string(),
        AsProbe::Error { code, .. } => format!("Error({code})"),
    }
}
