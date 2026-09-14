//! Tests de integración de password spraying contra el KDC del lab
//! (MIT krb5 1.21.3). Se saltan solos si no hay KDC: el sondeo es una
//! petición real (no basura) que clasifica la respuesta.

use charon_attacks::{spray_password, SprayResult};
use charon_client::{probe_as_no_preauth, AsProbe, KdcConnection};

const REALM: &str = "LAB.LOCAL";
const PORT: u16 = 1088;
/// Contraseña de jdoe en el lab (ver lab/setup-mit-kdc.sh).
const JDOE_PASSWORD: &str = "Jdoe!Pass42";

fn conn() -> KdcConnection {
    KdcConnection::new("127.0.0.1", PORT)
}

/// Hay KDC si un principal imposible responde con error 6.
fn kdc_available() -> bool {
    matches!(
        probe_as_no_preauth(&conn(), "kdc-disponible-sonda", REALM, &[18]),
        Ok(AsProbe::PrincipalUnknown { .. })
    )
}

macro_rules! skip_if_no_kdc {
    () => {
        if !kdc_available() {
            eprintln!("SKIP: KDC no disponible");
            return;
        }
    };
}

#[test]
fn t_spray_right_password_gets_tgt() {
    skip_if_no_kdc!();
    let r = spray_password(&conn(), "jdoe", REALM, JDOE_PASSWORD, &[18, 17]).unwrap();
    assert_eq!(r.result, SprayResult::Valid, "jdoe con su contraseña real debe dar Valid");
}

#[test]
fn t_spray_wrong_password_is_24() {
    skip_if_no_kdc!();
    let r = spray_password(&conn(), "jdoe", REALM, "Contrasena!Incorrecta", &[18, 17]).unwrap();
    assert_eq!(r.result, SprayResult::WrongPassword, "jdoe con contraseña errónea debe dar 24");
}

#[test]
fn t_spray_unknown_user_is_6() {
    skip_if_no_kdc!();
    let r = spray_password(&conn(), "ghost-spray", REALM, "loquesea", &[18, 17]).unwrap();
    assert_eq!(r.result, SprayResult::UnknownUser, "un principal inexistente debe dar UnknownUser");
}

#[test]
fn t_spray_nopreauth_account() {
    skip_if_no_kdc!();
    // Cuenta DONT_REQUIRE_PREAUTH: el spray ni siquiera consume la contraseña.
    let r = spray_password(&conn(), "nopreauth", REALM, "whatever", &[18, 17]).unwrap();
    assert_eq!(r.result, SprayResult::NoPreauth);
}
