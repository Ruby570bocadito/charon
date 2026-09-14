//! # charon-kcrypto — crypto de Kerberos según los RFC
//!
//! Implementa las **construcciones del protocolo** (string-to-key,
//! derivación de claves por usage, perfiles de cifrado/checksum) sobre
//! primitivos auditados de RustCrypto. La frontera exacta está en
//! ADR-003: los primitivos (AES, SHA1, HMAC, MD4, MD5, RC4, PBKDF2) son
//! externos; las construcciones son este crate, validadas con:
//!
//! 1. Vectores de RFC 3961 App. A (n-fold), RFC 3962 App. B
//!    (string-to-key AES) y Ap. A (CTS), y valores públicos de NT hash.
//! 2. Un KDC real (MIT krb5 en el lab): el KDC acepta el pre-auth
//!    producido por este crate y Charon descifra sus respuestas.
//!
//! API central: [`KerberosKey`] + [`encrypt`] / [`decrypt`] /
//! [`checksum`], desplazando por etype. El campo `cipher` de
//! `EncryptedData` es exactamente lo que entra y sale de estas funciones.

pub mod aes;
pub mod error;
pub mod nfold;
pub mod rc4hmac;

pub use error::{CryptoError, Result};

/// Tipos de cifrado (etypes) soportados, con sus números IANA.
pub mod etype {
    pub const AES128_CTS_HMAC_SHA1_96: i32 = 17;
    pub const AES256_CTS_HMAC_SHA1_96: i32 = 18;
    pub const RC4_HMAC: i32 = 23;
}

/// Key usages de RFC 4120 §7.5.1 que usa Charon.
pub mod usage {
    /// AS-REQ PA-ENC-TIMESTAMP, con la clave del cliente.
    pub const AS_REQ_PA_ENC_TS: u32 = 1;
    /// Ticket (AS-REP/TGS-REP), con la clave del servicio.
    pub const KDC_REP_TICKET: u32 = 2;
    /// AS-REP enc-part, con la clave del cliente.
    pub const AS_REP_ENCPART: u32 = 3;
    /// Authenticator del AP-REQ dentro del TGS-REQ, con la clave de sesión del TGT.
    pub const TGS_REQ_AUTH: u32 = 7;
    /// Checksum del authenticator en el TGS-REQ, con la clave de sesión
    /// del TGT (MIT 1.21 y Windows lo exigen).
    pub const TGS_REQ_AUTH_CKSUM: u32 = 6;
    /// Checksum de datos de aplicación (el del PA-FOR-USER de MS-SFU).
    pub const APP_DATA_CKSUM: u32 = 17;
    /// TGS-REP enc-part, con la clave de sesión del TGT.
    pub const TGS_REP_ENCPART_SESSKEY: u32 = 8;
    /// TGS-REP enc-part, con el subkey del authenticator (raro; errata RC4 8/9).
    pub const TGS_REP_ENCPART_SUBKEY: u32 = 9;
    /// Authenticator del AP-REQ de aplicación, con la clave de sesión.
    pub const AP_REQ_AUTH: u32 = 11;
}

/// Clave Kerberos de largo plazo o de sesión.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum KerberosKey {
    /// etype 23: el NT hash (MD4 de la contraseña en UTF-16LE).
    Rc4([u8; 16]),
    /// etype 17.
    Aes128([u8; 16]),
    /// etype 18.
    Aes256([u8; 32]),
}

impl KerberosKey {
    pub fn etype(&self) -> i32 {
        match self {
            KerberosKey::Rc4(_) => etype::RC4_HMAC,
            KerberosKey::Aes128(_) => etype::AES128_CTS_HMAC_SHA1_96,
            KerberosKey::Aes256(_) => etype::AES256_CTS_HMAC_SHA1_96,
        }
    }

    pub fn as_bytes(&self) -> &[u8] {
        match self {
            KerberosKey::Rc4(b) => b,
            KerberosKey::Aes128(b) => b,
            KerberosKey::Aes256(b) => b,
        }
    }

    /// Deriva la clave de una contraseña. RC4 = MD4(UTF-16LE(password)),
    /// el NT hash (conversión aplicada aquí). AES = string-to-key de
    /// RFC 3962 con la contraseña en sus bytes crudos (el RFC 3962 no
    /// usa UTF-16: los vectores del Apéndice B van tal cual) y el salt
    /// del dominio, que el KDC regala en el PA-ETYPE-INFO2 del error 25.
    pub fn from_password(password: &str, salt: &str, etype: i32) -> Result<KerberosKey> {
        match etype {
            etype::RC4_HMAC => {
                let utf16: Vec<u8> = password.encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
                Ok(KerberosKey::Rc4(rc4hmac::string_to_key(&utf16).try_into().expect("MD4 son 16 bytes")))
            }
            etype::AES128_CTS_HMAC_SHA1_96 => {
                let k = aes::string_to_key(16, password.as_bytes(), salt.as_bytes(), 4096)?;
                Ok(KerberosKey::Aes128(k.try_into().expect("16 bytes")))
            }
            etype::AES256_CTS_HMAC_SHA1_96 => {
                let k = aes::string_to_key(32, password.as_bytes(), salt.as_bytes(), 4096)?;
                Ok(KerberosKey::Aes256(k.try_into().expect("32 bytes")))
            }
            e => Err(CryptoError::UnsupportedEtype(e)),
        }
    }

    /// Construye la clave directamente desde bytes crudos (pass-the-key:
    /// NT hash o clave AES ya extraída, sin conocer la contraseña).
    pub fn from_raw(etype: i32, bytes: &[u8]) -> Result<KerberosKey> {
        match (etype, bytes.len()) {
            (etype::RC4_HMAC, 16) => Ok(KerberosKey::Rc4(bytes.try_into().unwrap())),
            (etype::AES128_CTS_HMAC_SHA1_96, 16) => Ok(KerberosKey::Aes128(bytes.try_into().unwrap())),
            (etype::AES256_CTS_HMAC_SHA1_96, 32) => Ok(KerberosKey::Aes256(bytes.try_into().unwrap())),
            (etype::RC4_HMAC, n) | (etype::AES128_CTS_HMAC_SHA1_96, n) => {
                Err(CryptoError::BadKeyLength { etype, len: n })
            }
            (etype::AES256_CTS_HMAC_SHA1_96, n) => Err(CryptoError::BadKeyLength { etype, len: n }),
            (e, _) => Err(CryptoError::UnsupportedEtype(e)),
        }
    }
}

/// Cifra con el perfil del etype de la clave. Devuelve el contenido del
/// campo `cipher` de `EncryptedData` (checksum/HMAC incluido).
pub fn encrypt(key: &KerberosKey, usage: u32, plaintext: &[u8]) -> Result<Vec<u8>> {
    match key {
        KerberosKey::Rc4(k) => rc4hmac::encrypt(k, usage, plaintext),
        KerberosKey::Aes128(k) => aes::encrypt(k, usage, plaintext),
        KerberosKey::Aes256(k) => aes::encrypt(k, usage, plaintext),
    }
}

/// Descifra y verifica. Error si el checksum no cuadra (clave/usage mal).
pub fn decrypt(key: &KerberosKey, usage: u32, edata: &[u8]) -> Result<Vec<u8>> {
    match key {
        KerberosKey::Rc4(k) => rc4hmac::decrypt(k, usage, edata),
        KerberosKey::Aes128(k) => aes::decrypt(k, usage, edata),
        KerberosKey::Aes256(k) => aes::decrypt(k, usage, edata),
    }
}

/// Checksum con clave según el etype (HMAC-MD5-ARCFOUR para RC4;
/// HMAC-SHA1 truncado con Kc para AES).
pub fn checksum(key: &KerberosKey, usage: u32, data: &[u8]) -> Result<Vec<u8>> {
    match key {
        KerberosKey::Rc4(k) => rc4hmac::checksum(k, usage, data),
        KerberosKey::Aes128(k) => aes::checksum(k, usage, data),
        KerberosKey::Aes256(k) => aes::checksum(k, usage, data),
    }
}

/// Bytes aleatorios del SO (nonces, confounders, subkeys).
pub fn random_bytes(n: usize) -> Result<Vec<u8>> {
    let mut buf = vec![0u8; n];
    getrandom::fill(&mut buf).map_err(|e| CryptoError::Random(e.to_string()))?;
    Ok(buf)
}

/// u32 aleatorio (nonces de AS-REQ/TGS-REQ).
///
/// Enmascarado a 31 bits a propósito: MIT y Heimdal codifican el nonce
/// como **con signo** ("We and Heimdal incorrectly encode nonces as
/// signed", k5_generate_nonce) y su decodificador rechaza con
/// ASN1_OVERFLOW un INTEGER de 5 bytes. Un nonce con el bit alto puesto
/// provocaría descartes intermitentes del 50% de las peticiones.
pub fn random_u32() -> Result<u32> {
    let b = random_bytes(4)?;
    Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]) & 0x7FFF_FFFF)
}

/// Comparación en tiempo constante para verificar checksums.
pub(crate) fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_from_password_and_raw() {
        let k = KerberosKey::from_password("Passw0rd!", "LAB.LOCALuser", etype::RC4_HMAC).unwrap();
        assert_eq!(k.etype(), 23);
        let k2 = KerberosKey::from_raw(23, k.as_bytes()).unwrap();
        assert_eq!(k, k2);
        assert!(matches!(
            KerberosKey::from_raw(etype::AES256_CTS_HMAC_SHA1_96, &[0u8; 16]),
            Err(CryptoError::BadKeyLength { etype: 18, len: 16 })
        ));
        // Etype inexistente → error claro.
        assert!(matches!(
            KerberosKey::from_raw(9999, &[0u8; 16]),
            Err(CryptoError::UnsupportedEtype(9999))
        ));
    }

    /// Interop entre etypes: la MISMA contraseña produce claves distintas
    /// pero ambas deben cifrar/descifrar coherentemente.
    #[test]
    fn dispatch_roundtrip_all_etypes() {
        for etype in [etype::RC4_HMAC, etype::AES128_CTS_HMAC_SHA1_96, etype::AES256_CTS_HMAC_SHA1_96] {
            let k = KerberosKey::from_password("Mssql!Svc01", "LAB.LOCALmssql/srv01.lab.local", etype).unwrap();
            let ed = encrypt(&k, usage::KDC_REP_TICKET, b"session key material").unwrap();
            let pt = decrypt(&k, usage::KDC_REP_TICKET, &ed).unwrap();
            assert_eq!(pt, b"session key material");
        }
    }
}
