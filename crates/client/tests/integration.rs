//! Tests de integración contra un KDC MIT krb5 real (lab/setup-mit-kdc.sh).
//!
//! Son las pruebas de fuego del proyecto: bytes construidos por Charon,
//! aceptados por una implementación de referencia. Si el KDC no está
//! levantado, se saltan con instrucciones (no son fallos del código).

use std::sync::Mutex;

use charon_client::*;
use charon_krb5::kdc_options;
use charon_krb5::Krb5Error;

// El KDC del laboratorio es de un solo hilo y su detector de replay de
// preauth es sensible a la concurrencia: la batería corre en serie.
static KDC_LOCK: Mutex<()> = Mutex::new(());
use charon_kcrypto::{etype, KerberosKey};

const HOST: &str = "127.0.0.1";
const PORT: u16 = 1088;
const REALM: &str = "LAB.LOCAL";

fn kdc_available() -> bool {
    // Sondea con un AS-REQ REAL (a un usuario inexistente): enviar basura
    // no sirve porque el KDC no responde a mensajes inválidos.
    let conn = KdcConnection::new(HOST, PORT);
    match charon_client::probe_as_no_preauth(&conn, "kdc-disponible-sonda", REALM, &[18]) {
        Ok(_) => true,
        Err(ClientError::Krb5(Krb5Error::BadReply(_))) => true,
        Err(_) => false,
    }
}

fn conn() -> KdcConnection {
    KdcConnection::new(HOST, PORT)
}

fn lock() -> std::sync::MutexGuard<'static, ()> {
    KDC_LOCK.lock().unwrap_or_else(|e| e.into_inner())
}

#[test]
fn t01_unknown_user_returns_error_6() {
    let _guard = lock();
    if !kdc_available() {
        eprintln!("SKIP: KDC no disponible — ejecuta lab/setup-mit-kdc.sh");
        return;
    }
    let probe = probe_as_no_preauth(&conn(), "ghost-inexistente", REALM, &[18, 23]).unwrap();
    match probe {
        AsProbe::PrincipalUnknown { .. } => {}
        other => panic!("esperaba PrincipalUnknown, obtuve {:?}", other_desc(&other)),
    }
}

#[test]
fn t02_existing_user_returns_25_and_salt() {
    let _guard = lock();
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
    let _guard = lock();
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
    let _guard = lock();
    if !kdc_available() {
        eprintln!("SKIP: KDC no disponible");
        return;
    }
    let key = KerberosKey::from_password("Jdoe!Pass42", "LAB.LOCALjdoe", etype::RC4_HMAC).unwrap();
    // El preauth viaja cifrado con la clave RC4 (etype 23 en el
    // EncryptedData); pedimos también 18 porque MIT 1.21 exige un etype
    // de sesión no deprecado en la lista.
    let tgt = request_tgt(&conn(), "jdoe", REALM, &key, &[23, 18], kdc_options::FORWARDABLE | kdc_options::RENEWABLE).unwrap();
    assert_eq!(tgt.crealm, REALM);
    assert_eq!(tgt.cname, "jdoe");
    assert_eq!(tgt.ticket.sname.name_string, vec!["krbtgt", "LAB.LOCAL"]);
    assert_eq!(tgt.session_key.keytype, 18, "MIT emite sesión AES256 por defecto");
    assert!(tgt.flags & charon_krb5::ticket_flags::INITIAL != 0);
}

#[test]
fn t05_tgt_with_aes256() {
    let _guard = lock();
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
    let _guard = lock();
    if !kdc_available() {
        eprintln!("SKIP: KDC no disponible");
        return;
    }
    let key = KerberosKey::from_password("Contrasena!Incorrecta", "LAB.LOCALjdoe", etype::AES256_CTS_HMAC_SHA1_96).unwrap();
    let err = request_tgt(&conn(), "jdoe", REALM, &key, &[18], 0).unwrap_err();
    assert!(format!("{err}").contains("PREAUTH_FAILED"), "error inesperado: {err}");
}

#[test]
fn t07_pass_the_key_with_nt_hash() {
    let _guard = lock();
    if !kdc_available() {
        eprintln!("SKIP: KDC no disponible");
        return;
    }
    // NT hash de "Jdoe!Pass42" (MD4 de UTF-16LE) usado directamente:
    // sin contraseña, sin cracking.
    let utf16: Vec<u8> = "Jdoe!Pass42".encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
    let nt = charon_kcrypto::rc4hmac::nt_hash(&utf16);
    let key = KerberosKey::from_raw(etype::RC4_HMAC, &nt).unwrap();
    let tgt = request_tgt(&conn(), "jdoe", REALM, &key, &[23, 18], 0).unwrap();
    assert_eq!(tgt.cname, "jdoe");
}

#[test]
fn t08_tgs_aes_first_and_rc4_only() {
    let _guard = lock();
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
    let _guard = lock();
    if !kdc_available() {
        eprintln!("SKIP: KDC no disponible");
        return;
    }
    // Pedimos el ticket de servicio de nuestra propia cuenta de servicio
    // (cuya clave larga conocemos en el lab) y desciframos el ticket con
    // ella (usage 2) para leer el PAC de jdoe: el flujo de análisis de PAC.
    let svc_key = KerberosKey::from_password("Mssql!Svc01", "LAB.LOCALmssqlsrv01.lab.local", etype::AES256_CTS_HMAC_SHA1_96).unwrap();
    let user_key = KerberosKey::from_password("Jdoe!Pass42", "LAB.LOCALjdoe", etype::AES256_CTS_HMAC_SHA1_96).unwrap();
    let user_tgt = request_tgt(&conn(), "jdoe", REALM, &user_key, &[18], 0).unwrap();
    let st = request_service_ticket(&conn(), &user_tgt, "mssql/srv01.lab.local", &[18, 17], 0).unwrap();
    let pac = charon_krb5::pac::extract_pac(&st.ticket, &svc_key);
    match pac {
        Ok(p) => {
            // MIT 1.21 emite un PAC minimalista (client-info + checksums,
            // SIN LOGON_INFO): fingerprint vs AD, que siempre lo incluye.
            // Lo que debe haber SIEMPRE es la identidad del cliente.
            let (_, name) = p.client_info().expect("el PAC debe llevar CLIENT INFO");
            assert_eq!(name, "jdoe", "el PAC identifica al usuario autenticado");
            assert!(!p.signatures().is_empty(), "el PAC debe llevar firmas");
            // LOGON_INFO con RID/grupos existe en AD; MIT la omite.
            if let Some(info) = p.logon_info() {
                assert_eq!(info.account, "jdoe");
            }
        }
        Err(e) => panic!("no se pudo extraer el PAC: {e}"),
    }
}

#[test]
fn t10_udp_tcp_strategy_and_response_sizes() {
    let _guard = lock();
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

/// Ronda 2 del sistema de agentes: TGT renovable + renovación real
/// (RFC 4120 §3.3.3). La renovación se distingue de un TGS normal
/// porque el KDC CONSERVA la authtime; el flag RENEWABLE del ticket
/// renovado se concede porque se pide (RFC 4120 §3.1.3).
#[test]
fn t11_renewable_tgt_and_renew() {
    let _guard = lock();
    if !kdc_available() {
        eprintln!("SKIP: KDC no disponible");
        return;
    }
    let key = KerberosKey::from_password("Jdoe!Pass42", "LAB.LOCALjdoe", etype::AES256_CTS_HMAC_SHA1_96).unwrap();
    let till = charon_asn1::KrbTime::now().plus_secs(7 * 86_400);
    let tgt = request_tgt_renewable(&conn(), "jdoe", REALM, &key, &[18], till).unwrap();
    assert_eq!(
        tgt.flags & charon_krb5::ticket_flags::RENEWABLE,
        charon_krb5::ticket_flags::RENEWABLE,
        "el KDC debe conceder RENEWABLE (max_renewable_life=7d en el lab)"
    );
    let renew_till = tgt.renew_till.expect("un TGT renovable trae renew-till");
    assert!(renew_till.unix_secs <= till.plus_secs(60).unix_secs, "el KDC recorta rtime a max_renewable_life (7d)");

    let renewed = renew_tgt(&conn(), &tgt, till).expect("la renovación debe aceptarse");
    assert_eq!(renewed.authtime, tgt.authtime, "la renovación conserva la authtime original (prueba de que el KDC aplicó RENEW)");
    assert_eq!(renewed.cname, "jdoe");
    assert_eq!(renewed.ticket.sname.name_string, vec!["krbtgt", "LAB.LOCAL"]);
    assert!(
        renewed.flags & charon_krb5::ticket_flags::RENEWABLE != 0,
        "el ticket renovado sigue renovable (RENEWABLE pedido: RFC 4120 §3.1.3)"
    );
    assert!(renewed.endtime.unix_secs <= renewed.renew_till.unwrap_or(renew_till).unix_secs, "endtime dentro de la ventana");
    assert_ne!(
        renewed.session_key.keyvalue, tgt.session_key.keyvalue,
        "una renovación emite una clave de sesión fresca"
    );
}

/// La renovación de un TGT NO renovable debe ser rechazada: pedimos un
/// TGT normal (sin RENEWABLE) y renueva → KDC_ERR_BADOPTION (13).
#[test]
fn t12_renew_rejected_for_non_renewable_tgt() {
    let _guard = lock();
    if !kdc_available() {
        eprintln!("SKIP: KDC no disponible");
        return;
    }
    let key = KerberosKey::from_password("Jdoe!Pass42", "LAB.LOCALjdoe", etype::AES256_CTS_HMAC_SHA1_96).unwrap();
    let tgt = request_tgt(&conn(), "jdoe", REALM, &key, &[18], kdc_options::FORWARDABLE).unwrap();
    let till = charon_asn1::KrbTime::now().plus_secs(7 * 86_400);
    let err = renew_tgt(&conn(), &tgt, till).expect_err("renovar un TGT no renovable debe fallar");
    let msg = err.to_string();
    assert!(msg.contains("BADOPTION") || msg.contains("13"), "el KDC debe responder BADOPTION(13): {msg}");
}

/// El ciclo de persistencia completo: TGT renovable → ccache FILE v4 →
/// recarga SIN credenciales → renovación por el cable → el TGT renovado
/// se re-persiste. Verifica además el round-trip exacto del material
/// (clave de sesión, flags, tiempos, ticket) y que el fichero resultante
/// lo parsea de nuevo Charon (la interoperabilidad con klist/kinit de MIT
/// se verificó en vivo en la ronda 3 y se documenta en el informe).
#[test]
fn t13_ccache_save_load_and_renew_without_credentials() {
    let _guard = lock();
    if !kdc_available() {
        eprintln!("SKIP: KDC no disponible");
        return;
    }
    let key = KerberosKey::from_password("Jdoe!Pass42", "LAB.LOCALjdoe", etype::AES256_CTS_HMAC_SHA1_96).unwrap();
    let till = charon_asn1::KrbTime::now().plus_secs(7 * 86_400);
    let tgt = request_tgt_renewable(&conn(), "jdoe", REALM, &key, &[18], till).unwrap();

    let path = std::env::temp_dir().join(format!("charon-t13-{}.ccache", std::process::id()));
    let path = path.to_str().unwrap();
    ccache::save_tgt(path, &tgt).expect("guarda el TGT en ccache");

    // Permisos 0600: el fichero lleva la clave de sesión en claro.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "el ccache debe quedar en 0600");
    }

    let loaded = ccache::load_tgt(path).expect("recarga sin credenciales");
    assert_eq!(loaded.crealm, tgt.crealm);
    assert_eq!(loaded.cname, tgt.cname);
    assert_eq!(loaded.session_key, tgt.session_key, "clave de sesión intacta en el round-trip");
    assert_eq!(loaded.flags, tgt.flags);
    assert_eq!(loaded.authtime, tgt.authtime);
    assert_eq!(loaded.endtime, tgt.endtime);
    assert_eq!(loaded.renew_till, tgt.renew_till);
    assert_eq!(loaded.ticket, tgt.ticket, "el ticket DER re-parseado es idéntico");

    // Renovación SIN contraseña desde el material persistido.
    let renewed = renew_tgt(&conn(), &loaded, till).expect("renueva el TGT cargado del ccache");
    assert_eq!(renewed.authtime, loaded.authtime, "authtime conservada");
    assert_ne!(renewed.session_key.keyvalue, loaded.session_key.keyvalue, "clave fresca");

    // Re-persiste el renovado (lo que hace el CLI) y vuelve a cargarlo.
    ccache::save_tgt(path, &renewed).expect("reescribe el ccache con el renovado");
    let reloaded = ccache::load_tgt(path).expect("el ccache actualizado sigue cargándose");
    assert_eq!(reloaded.session_key, renewed.session_key);
    std::fs::remove_file(path).ok();
}

/// S4U2Proxy de extremo a extremo hasta el límite REAL del KDC del lab.
///
/// (1) El TGT de svc-api se pide FORWARDABLE: MIT 1.21 recorta FORWARDABLE
/// del ticket emitido si el TGT cabecera no lo trae (kdc_util.c
/// get_ticket_flags). (2) Con ok_to_auth_as_delegate (script de lab), el
/// evidence ticket de S4U2Self sale forwardable. (3) La petición S4U2Proxy
/// es aceptada por el parser del KDC y llega a la evaluación de política —
/// que con el backend db2 NO PUEDE autorizar ninguna delegación
/// (check_allowed_to_delegate solo lo implementan los KDB LDAP/test; se
/// verificó en el código fuente de MIT 1.21): responde KDC_ERR_BADOPTION
/// con UNSUPPORTED_S4U2PROXY_REQUEST. El test fija ese contrato de cable:
/// una regresión en la opción C_NAME_IN_ADDL_TKT haría que el KDC emitiere
/// un TGS PLANO (éxito, cliente=svc-api) en vez del BADOPTION — exactamente
/// el bug de bit que esta ronda corrigió.
#[test]
fn t14_s4u2proxy_evidence_and_kdc_policy_boundary() {
    let _guard = lock();
    if !kdc_available() {
        eprintln!("SKIP: KDC no disponible");
        return;
    }
    // Fixture del lab: principals del script de delegación.
    let api_key = match probe_as_no_preauth(&conn(), "svc-api", REALM, &[18]) {
        Ok(AsProbe::PrincipalUnknown { .. }) => {
            eprintln!("SKIP: fixture de delegación ausente — scripts/lab_setup_delegation.sh");
            return;
        }
        Ok(_) => KerberosKey::from_password("SvcApiPass2026", "LAB.LOCALsvc-api", etype::AES256_CTS_HMAC_SHA1_96).unwrap(),
        Err(e) => panic!("sonda del fixture falló: {e}"),
    };
    let tgt = request_tgt(&conn(), "svc-api", REALM, &api_key, &[18], kdc_options::FORWARDABLE).unwrap();
    assert!(
        tgt.flags & charon_krb5::ticket_flags::FORWARDABLE != 0,
        "el TGT del servicio debe ser forwardable (pedido en el AS-REQ)"
    );

    let evidence = s4u2self(&conn(), &tgt, "svc-api", "jdoe", REALM).unwrap();
    assert_eq!(evidence.cname, "jdoe", "el evidence ticket es para el suplantado");
    assert!(
        evidence.flags & charon_krb5::ticket_flags::FORWARDABLE != 0,
        "MIT concede FORWARDABLE al evidence ticket con ok_to_auth_as_delegate (MS-SFU)"
    );

    let err = s4u2proxy(&conn(), &tgt, &evidence.ticket, "svc-db", "jdoe", REALM, &[18, 23])
        .expect_err("db2 no autoriza delegación: debe fallar en política");
    let msg = err.to_string();
    assert!(
        msg.contains("BADOPTION"),
        "la política del KDC responde BADOPTION (no un error de formato): {msg}"
    );
    assert!(
        msg.contains("UNSUPPORTED_S4U2PROXY_REQUEST"),
        "el status confirma que la petición llegó a la evaluación de política S4U2Proxy: {msg}"
    );
}

/// TGT con la clave leída de un keytab REAL de MIT (`charon as --keytab`,
/// el flujo del analista con material exportado por ktadd/ktutil).
///
/// El fixture (`krb5/tests/fixtures/lab-jdoe.keytab`) fue producido por
/// `ktutil addent` de MIT 1.21.3 con la clave AES256 de jdoe del lab
/// (contraseña desechable documentada en `lab/setup-mit-kdc.sh`): si el
/// parser v2 del keytab o nuestra string2key se desvían una sola-byte de
/// MIT, el KDC responde PREAUTH_FAILED y el test lo caza.
#[test]
fn t15_tgt_con_la_clave_de_un_keytab_real() {
    let _guard = lock();
    if !kdc_available() {
        eprintln!("SKIP: KDC no disponible");
        return;
    }
    let bytes = include_bytes!("../../krb5/tests/fixtures/lab-jdoe.keytab");
    let entries = charon_krb5::keytab::parse(bytes).expect("el keytab del fixture parsea");
    let entry = entries
        .iter()
        .find(|e| e.qualified() == "jdoe@LAB.LOCAL")
        .expect("el fixture trae la entrada de jdoe");
    assert_eq!(entry.enctype, etype::AES256_CTS_HMAC_SHA1_96);

    let key = KerberosKey::from_raw(entry.enctype, &entry.key).unwrap();
    let tgt = request_tgt(&conn(), "jdoe", REALM, &key, &[entry.enctype], kdc_options::FORWARDABLE)
        .expect("el KDC debe aceptar el preauth cifrado con la clave del keytab");
    assert_eq!(tgt.crealm, REALM);
    assert_eq!(tgt.cname, "jdoe");
    assert_eq!(tgt.ticket.sname.name_string, vec!["krbtgt", "LAB.LOCAL"]);
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

// ---------- segundo KDC: módulo test KDB (lab/setup-test-kdb.sh) ----------

const DELEG_PORT: u16 = 1190;
const DELEG_REALM: &str = "DELEG.LAB";

/// Keytabs exportados por el setup (`ktadd -norandkey`) en el estado
/// desechable del lab, fuera del repo. La env var permite apuntar a otra
/// instalación; por defecto, la ubicación que escribe el script.
fn deleg_keytab(name: &str) -> Option<std::path::PathBuf> {
    let dir =
        std::env::var_os("CHARON_DELEG_KEYTABS").map_or_else(dirs_home, std::path::PathBuf::from);
    let p = dir.join(name);
    if p.is_file() {
        Some(p)
    } else {
        None
    }
}

fn dirs_home() -> std::path::PathBuf {
    // El lab vive en $HOME/charon-lab (lab/setup-test-kdb.sh).
    std::env::var_os("HOME")
        .map(std::path::PathBuf::from)
        .unwrap_or_default()
        .join("charon-lab/deleg/keytabs")
}

fn deleg_kdc_available() -> bool {
    // Misma sonda que kdc_available(): un AS-REQ real a un usuario
    // inexistente del realm DELEG; cualquier respuesta del KDC sirve.
    let conn = KdcConnection::new(HOST, DELEG_PORT);
    match charon_client::probe_as_no_preauth(&conn, "kdc-deleg-sonda", DELEG_REALM, &[18]) {
        Ok(_) => true,
        Err(ClientError::Krb5(Krb5Error::BadReply(_))) => true,
        Err(_) => false,
    }
}

/// S4U2Proxy END-TO-END contra el segundo KDC (módulo test KDB de MIT con
/// tabla `delegation`): TGT de service/1 por keytab → evidence ticket
/// forwardable de S4U2Self → ticket delegado para user hacia service/2 →
/// descifrado con la clave del DESTINO (keytab) y PAC del suplantado.
///
/// Es la prueba que cierra el ciclo MS-SFU completo del proyecto: política
/// allowed_to_delegate REAL (db2 no la implementa), claves reales exportadas
/// por ktadd y el PAC que demuestra la suplantación sin participación del
/// usuario. Sin el lab deleg (lab/setup-test-kdb.sh) el test se salta.
#[test]
fn t16_s4u2proxy_end_to_end_con_test_kdb() {
    let _guard = lock();
    if !deleg_kdc_available() {
        eprintln!("SKIP: KDC test-KDB no disponible (lab/setup-test-kdb.sh, puerto {DELEG_PORT})");
        return;
    }
    let (Some(kt1), Some(kt2)) = (deleg_keytab("service1.keytab"), deleg_keytab("service2.keytab"))
    else {
        eprintln!("SKIP: keytabs del realm deleg ausentes (lab/setup-test-kdb.sh)");
        return;
    };
    let key1 = {
        let entries = charon_krb5::keytab::parse(&std::fs::read(&kt1).expect("keytab de service/1 legible"))
            .expect("el keytab del lab deleg parsea");
        let e = entries
            .iter()
            .find(|e| e.qualified() == "service/1@DELEG.LAB")
            .expect("service/1 en el keytab del lab deleg");
        KerberosKey::from_raw(e.enctype, &e.key).unwrap()
    };
    let key2 = {
        let entries = charon_krb5::keytab::parse(&std::fs::read(&kt2).expect("keytab de service/2 legible"))
            .expect("el keytab del lab deleg parsea");
        let e = entries
            .iter()
            .find(|e| e.qualified() == "service/2@DELEG.LAB")
            .expect("service/2 en el keytab del lab deleg");
        KerberosKey::from_raw(e.enctype, &e.key).unwrap()
    };

    let dconn = KdcConnection::new(HOST, DELEG_PORT);
    // 1) TGT del servicio que delega, con la clave del keytab.
    let tgt = request_tgt(&dconn, "service/1", DELEG_REALM, &key1, &[etype::AES256_CTS_HMAC_SHA1_96], kdc_options::FORWARDABLE)
        .expect("TGT de service/1 con la clave hash del módulo test");
    assert_eq!(tgt.cname, "service/1");

    // 2) Evidence ticket: forwardable exige ok_to_auth_as_delegate.
    let evidence = s4u2self(&dconn, &tgt, "service/1", "user", DELEG_REALM)
        .expect("S4U2Self contra el KDC test");
    assert_eq!(evidence.cname, "user", "el evidence ticket es del suplantado");
    assert!(
        evidence.flags & charon_krb5::ticket_flags::FORWARDABLE != 0,
        "el módulo test concede FORWARDABLE con ok_to_auth_as_delegate"
    );

    // 3) S4U2Proxy AUTORIZADO (la tabla delegation: service/1 → service/2).
    let final_st = s4u2proxy(&dconn, &tgt, &evidence.ticket, "service/2", "user", DELEG_REALM, &[18, 23])
        .expect("la delegación debe estar autorizada por la tabla delegation");
    assert_eq!(final_st.cname, "user", "el ticket delegado es del usuario suplantado");
    assert_eq!(final_st.ticket.sname.flat(), "service/2");

    // 4) Prueba final: el ticket va cifrado con la clave larga del DESTINO
    // y su PAC muestra al suplantado — la evidencia de la delegación.
    let pac = charon_krb5::pac::extract_pac(&final_st.ticket, &key2)
        .expect("el ticket final se descifra con la clave de service/2");
    let (_, client) = pac.client_info().expect("el PAC lleva CLIENT INFO");
    assert_eq!(client, "user", "el PAC del ticket delegado acredita al usuario suplantado");
}

/// Clave larga de un principal del realm deleg, desde SU keytab del lab.
fn deleg_key(name: &str, qualified: &str) -> Option<KerberosKey> {
    let kt = deleg_keytab(name)?;
    let entries = charon_krb5::keytab::parse(&std::fs::read(&kt).expect("keytab del lab deleg legible"))
        .expect("el keytab del lab deleg parsea");
    let e = entries
        .iter()
        .find(|e| e.qualified() == qualified)
        .unwrap_or_else(|| panic!("{qualified} en el keytab del lab deleg"));
    Some(KerberosKey::from_raw(e.enctype, &e.key).unwrap())
}

/// t17 — RBCD puro END-TO-END (MS-KILE §2.2.10): S4U2Proxy con el padata
/// PA-PAC-OPTIONS y el bit resource-based, autorizado por la política del
/// RECURSO (tabla `rbcd` del módulo test, kdb_test.c 748-778).
///
/// La prueba distingue la vía RBCD de la tradicional POR CONSTRUCCIÓN: el
/// destino del ticket delegado es `service/1`, que NO figura como destino
/// en la tabla `delegation` (solo service/1 → service/2) — la autorización
/// solo puede venir de la entrada `rbcd: service/1@DELEG.LAB =
/// service/1@DELEG.LAB` consultada PORQUE el cable lleva el bit. Sin el
/// lab deleg (lab/setup-test-kdb.sh) el test se salta.
#[test]
fn t17_rbcd_end_to_end_con_tabla_rbcd() {
    let _guard = lock();
    if !deleg_kdc_available() {
        eprintln!("SKIP: KDC test-KDB no disponible (lab/setup-test-kdb.sh, puerto {DELEG_PORT})");
        return;
    }
    let Some(key1) = deleg_key("service1.keytab", "service/1@DELEG.LAB") else {
        eprintln!("SKIP: keytabs del realm deleg ausentes (lab/setup-test-kdb.sh)");
        return;
    };

    let dconn = KdcConnection::new(HOST, DELEG_PORT);
    // 1) TGT del impersonador.
    let tgt = request_tgt(&dconn, "service/1", DELEG_REALM, &key1, &[etype::AES256_CTS_HMAC_SHA1_96], kdc_options::FORWARDABLE)
        .expect("TGT de service/1 con la clave hash del módulo test");
    // 2) Evidence ticket del suplantado.
    let evidence = s4u2self(&dconn, &tgt, "service/1", "user", DELEG_REALM)
        .expect("S4U2Self contra el KDC test");
    assert_eq!(evidence.cname, "user");
    // 3) S4U2Proxy RBCD: el recurso service/1 autoriza (tabla rbcd), la
    // tradicional NO cubre este destino — si el KDC respondió, fue por el
    // bit del cable.
    let final_st = s4u2proxy_rbcd(&dconn, &tgt, &evidence.ticket, "service/1", "user", DELEG_REALM, &[18, 23])
        .expect("la delegación RBCD debe estar autorizada por la tabla rbcd del recurso");
    assert_eq!(final_st.cname, "user", "el ticket delegado es del usuario suplantado");
    assert_eq!(final_st.ticket.sname.flat(), "service/1", "el destino es el RECURSO de la tabla rbcd");
    // 4) El ticket delegado se descifra con la clave del RECURSO y su PAC
    // acredita al suplantado — el ciclo MS-SFU completo por la vía RBCD.
    let pac = charon_krb5::pac::extract_pac(&final_st.ticket, &key1)
        .expect("el ticket final se descifra con la clave de service/1 (recurso)");
    let (_, client) = pac.client_info().expect("el PAC lleva CLIENT INFO");
    assert_eq!(client, "user", "el PAC del ticket RBCD acredita al usuario suplantado");
}

/// t18 — el espejo negativo del t17: la MISMA petición (destino service/1,
/// no cubierto por la tabla tradicional) SIN el bit RBCD en el cable es
/// rechazada con KDC_ERR_BADOPTION. Si el KDC la autorizara, el bit no
/// conmutaría nada; si fallara por otra razón (formato, preauth), el
/// mensaje no sería BADOPTION. El par t17+t18 demuestra que Charon emite
/// un cable PA-PAC-OPTIONS que el KDC de referencia interpreta.
#[test]
fn t18_s4u2proxy_sin_bit_rbcd_rechazado_por_política() {
    let _guard = lock();
    if !deleg_kdc_available() {
        eprintln!("SKIP: KDC test-KDB no disponible (lab/setup-test-kdb.sh, puerto {DELEG_PORT})");
        return;
    }
    let Some(key1) = deleg_key("service1.keytab", "service/1@DELEG.LAB") else {
        eprintln!("SKIP: keytabs del realm deleg ausentes (lab/setup-test-kdb.sh)");
        return;
    };

    let dconn = KdcConnection::new(HOST, DELEG_PORT);
    let tgt = request_tgt(&dconn, "service/1", DELEG_REALM, &key1, &[etype::AES256_CTS_HMAC_SHA1_96], kdc_options::FORWARDABLE)
        .expect("TGT de service/1");
    let evidence = s4u2self(&dconn, &tgt, "service/1", "user", DELEG_REALM).expect("S4U2Self");

    // S4U2Proxy TRADICIONAL hacia service/1: la tabla delegation no lo
    // cubre y el cable no lleva el bit → el KDC niega la política.
    let err = s4u2proxy(&dconn, &tgt, &evidence.ticket, "service/1", "user", DELEG_REALM, &[18, 23])
        .expect_err("sin bit RBCD el KDC debe negar la delegación hacia service/1");
    let msg = err.to_string();
    assert!(
        msg.contains("BADOPTION"),
        "la negación debe venir de la política (KDC_ERR_BADOPTION), no de otro fallo: {msg}"
    );
}
