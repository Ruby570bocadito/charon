//! RC4-HMAC (etype 23) — RFC 4757, con la errata de key usage 8/9.
//!
//! Estructura (RFC 4757 §5):
//! - `string-to-key`: MD4(UTF-16LE(password)) — el NT hash de toda la vida.
//! - Cifrado: `ki = HMAC-MD5(key, LE32(usage))`;
//!   `cksum = HMAC-MD5(ki, conf(8) | plaintext)` (16 bytes);
//!   `ke = HMAC-MD5(ki, cksum)`;
//!   `edata = cksum | RC4(ke, conf | plaintext)` (stream continuo).
//! - El checksum cubre confounder+plaintext ANTES de cifrar; el header de
//!   16 bytes va en claro delante del texto cifrado.
//! - Errata de RFC 4757: para el AS-REP el KDC real usa el usage 8 aunque
//!   el RFC asigne el 3; MIT lo implementa en
//!   `krb5int_arcfour_translate_usage` (3 → 8). Charon aplica el mismo
//!   mapa y, además, acepta en decrypt el fallback 9 → 8 como impacket.
//! - Checksum independiente (cksumtype HMAC_MD5, el de los
//!   authenticators): `ks = HMAC-MD5(key, "signaturekey\0")`;
//!   `MD5(LE32(usage) | data)`; `HMAC-MD5(ks, md5)`.

use crate::error::{CryptoError, Result};
use cipher::StreamCipher as _;
use digest::{KeyInit, Mac};
use hmac::Hmac;
use md4::{Digest, Md4};
use md5::Md5;
use rc4::Rc4;

const CONF_SIZE: usize = 8;
const CKSUM_SIZE: usize = 16;

type HmacMd5 = Hmac<Md5>;

fn hmac_md5(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac = <HmacMd5 as KeyInit>::new_from_slice(key).expect("HMAC acepta claves de cualquier longitud");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

/// NT hash: MD4 de la contraseña en UTF-16LE.
pub fn nt_hash(password_utf16le: &[u8]) -> [u8; 16] {
    let mut h = Md4::new();
    h.update(password_utf16le);
    h.finalize().into()
}

/// Traducción de key usages compatible con Microsoft (idéntica a
/// `krb5int_arcfour_translate_usage` de MIT).
pub fn translate_usage(usage: u32) -> u32 {
    match usage {
        3 => 8, // as-rep encrypted part (errata RFC 4757)
        _ => usage,
    }
}

fn rc4_stream(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut cipher = Rc4::new_from_slice(key).expect("clave RC4 de 16 bytes");
    let mut out = data.to_vec();
    cipher.apply_keystream(&mut out);
    out
}

pub fn string_to_key(password_utf16le: &[u8]) -> Vec<u8> {
    nt_hash(password_utf16le).to_vec()
}

pub fn encrypt(key: &[u8], usage: u32, plaintext: &[u8]) -> Result<Vec<u8>> {
    let ki = hmac_md5(key, &translate_usage(usage).to_le_bytes());
    let conf = crate::random_bytes(CONF_SIZE)?;

    let mut covered = Vec::with_capacity(CONF_SIZE + plaintext.len());
    covered.extend_from_slice(&conf);
    covered.extend_from_slice(plaintext);

    let cksum = hmac_md5(&ki, &covered);
    let ke = hmac_md5(&ki, &cksum);
    let cipher = rc4_stream(&ke, &covered);

    let mut edata = Vec::with_capacity(CKSUM_SIZE + cipher.len());
    edata.extend_from_slice(&cksum);
    edata.extend_from_slice(&cipher);
    Ok(edata)
}

pub fn decrypt(key: &[u8], usage: u32, edata: &[u8]) -> Result<Vec<u8>> {
    if edata.len() < CKSUM_SIZE + CONF_SIZE {
        return Err(CryptoError::CiphertextTooShort(edata.len()));
    }
    let decrypt_with = |usage: u32| -> Option<Vec<u8>> {
        let ki = hmac_md5(key, &usage.to_le_bytes());
        let cksum = &edata[..CKSUM_SIZE];
        let ke = hmac_md5(&ki, cksum);
        let plain = rc4_stream(&ke, &edata[CKSUM_SIZE..]);
        let expected = hmac_md5(&ki, &plain);
        if crate::ct_eq(&expected, cksum) {
            Some(plain[CONF_SIZE..].to_vec())
        } else {
            None
        }
    };
    let mapped = translate_usage(usage);
    if let Some(pt) = decrypt_with(mapped) {
        return Ok(pt);
    }
    // Errata 8/9 del TGS-REP: si el KDC cifró con el otro usage, reintenta.
    let alt = if mapped == 8 { 9 } else { 8 };
    decrypt_with(alt).ok_or(CryptoError::ChecksumMismatch)
}

/// Checksum HMAC-MD5-ARCFOUR (cksumtype -138, el de los authenticators):
/// construcción "signaturekey" de MS, idéntica a MIT
/// `krb5int_hmacmd5_checksum`.
pub fn checksum(key: &[u8], usage: u32, data: &[u8]) -> Result<Vec<u8>> {
    let ks = hmac_md5(key, b"signaturekey\0");
    let ms_usage = translate_usage(usage);
    let mut md5 = Md5::new();
    md5.update(ms_usage.to_le_bytes());
    md5.update(data);
    let md5_out = md5.finalize();
    Ok(hmac_md5(&ks, &md5_out))
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex;

    #[test]
    fn nt_hash_known_values() {
        let utf16 = |s: &str| -> Vec<u8> { s.encode_utf16().flat_map(|u| u.to_le_bytes()).collect() };
        // NT hash de "password": 8846f7eaee8fb117ad06bdd830b7586c (vector público).
        assert_eq!(hex::encode(nt_hash(&utf16("password"))), "8846f7eaee8fb117ad06bdd830b7586c");
        // "" → 31d6cfe0d16ae931b73c59d7e0c089c0 (NT hash de contraseña vacía).
        assert_eq!(hex::encode(nt_hash(&utf16(""))), "31d6cfe0d16ae931b73c59d7e0c089c0");
        // La clave RC4 es exactamente el NT hash.
        assert_eq!(string_to_key(&utf16("password")), nt_hash(&utf16("password")));
    }

    #[test]
    fn profile_roundtrip_and_tamper() {
        let key = [0x88u8; 16];
        for len in [0usize, 1, 7, 8, 9, 100, 1000] {
            let pt: Vec<u8> = (0..len).map(|i| (i * 3) as u8).collect();
            let ed = encrypt(&key, 3, &pt).unwrap();
            assert_eq!(ed.len(), len + CKSUM_SIZE + CONF_SIZE);
            assert_eq!(decrypt(&key, 3, &ed).unwrap(), pt, "round-trip {len}");
        }
        // Manipulación del texto cifrado → fallo de checksum.
        let mut ed = encrypt(&key, 3, b"kerberoasting aes-first").unwrap();
        let n = ed.len();
        ed[n - 1] ^= 0x80;
        assert!(matches!(decrypt(&key, 3, &ed), Err(CryptoError::ChecksumMismatch)));
        // Un plaintext cifrado con usage 1 no abre con usage 8 sin mapa.
        // (1 y 8 tienen derivaciones distintas.)
        let ed = encrypt(&key, 1, b"x").unwrap();
        assert!(matches!(decrypt(&key, 2, &ed), Err(CryptoError::ChecksumMismatch)));
    }

    #[test]
    fn translate_usage_map() {
        assert_eq!(translate_usage(3), 8);
        assert_eq!(translate_usage(1), 1);
        assert_eq!(translate_usage(8), 8);
        assert_eq!(translate_usage(11), 11);
    }

    #[test]
    fn decrypt_fallback_errata_8_9() {
        // Si los datos se produjeron con usage 9 (variante errata) y se
        // piden como 8, el fallback debe recuperarlos.
        let key = [0x42u8; 16];
        let ki9 = hmac_md5(&key, &9u32.to_le_bytes());
        let conf = vec![0u8; CONF_SIZE];
        let pt = b"con subkey";
        let mut covered = conf.clone();
        covered.extend_from_slice(pt);
        let cksum = hmac_md5(&ki9, &covered);
        let ke = hmac_md5(&ki9, &cksum);
        let mut edata = cksum.clone();
        edata.extend(rc4_stream(&ke, &covered));
        // decrypt con usage 8 debe caer al 9 y verificar.
        assert_eq!(decrypt(&key, 8, &edata).unwrap(), pt);
    }
}
