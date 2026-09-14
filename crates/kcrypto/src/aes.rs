//! AES-CTS-HMAC-SHA1-96 (etypes 17 y 18) — RFC 3961 (perfil simplificado)
//! y RFC 3962 (AES para Kerberos 5).
//!
//! Piezas y su origen:
//! - `string_to_key`: PBKDF2-HMAC-SHA1(UTF-16LE(password), salt, iters)
//!   seguido de `DK(tempkey, "kerberos")` — RFC 3962 §4. Las iteraciones
//!   por defecto son 4096.
//! - `DK`/`DR`: derivación de clave RFC 3961 §5.1 — n-fold de la constante
//!   a 128 bits y cifrado ECB iterado encadenado.
//! - CTS: CBC con robo de cifrado sobre los dos últimos bloques
//!   (RFC 3962 §5, equivalente a MIT krb5 y a los vectores de su Ap. A).
//! - Perfil de cifrado: confounder de 16 bytes, HMAC-SHA1 truncado a 12
//!   bytes sobre el plaintext (antes de cifrar), edata = C || H
//!   (RFC 3961 §5.3). SIN padding: el tamaño de mensaje de AES es 1
//!   porque CTS maneja el bloque final parcial.
//! - Claves derivadas por key usage: Kc = DK(u‖0x99), Ke = DK(u‖0xAA),
//!   Ki = DK(u‖0x55), con el usage en 4 bytes big-endian + 1 octeto
//!   (RFC 3961 §5.3, tabla "key-derivation function").

use crate::error::{CryptoError, Result};
use crate::nfold::nfold;
use cipher::{BlockCipherDecrypt, BlockCipherEncrypt, KeyInit};
use digest::Mac as _;
use hmac::Hmac;
use sha1::Sha1;

pub const AES_BLOCK: usize = 16;
pub const AES_MAC_SIZE: usize = 12; // 96 bits (h)

type HmacSha1 = Hmac<Sha1>;

fn hmac_sha1(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac = <HmacSha1 as KeyInit>::new_from_slice(key).expect("HMAC acepta claves de cualquier longitud");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

fn aes_ecb_encrypt_block(key: &[u8], block: &[u8; AES_BLOCK]) -> [u8; AES_BLOCK] {
    if key.len() == 16 {
        let c = aes::Aes128::new_from_slice(key).expect("clave AES-128 de 16 bytes");
        let mut out: cipher::Block<aes::Aes128> = (*block).into();
        c.encrypt_block(&mut out);
        out.into()
    } else {
        let c = aes::Aes256::new_from_slice(key).expect("clave AES-256 de 32 bytes");
        let mut out: cipher::Block<aes::Aes256> = (*block).into();
        c.encrypt_block(&mut out);
        out.into()
    }
}

fn aes_ecb_decrypt_block(key: &[u8], block: &[u8; AES_BLOCK]) -> [u8; AES_BLOCK] {
    if key.len() == 16 {
        let c = aes::Aes128::new_from_slice(key).expect("clave AES-128 de 16 bytes");
        let mut out: cipher::Block<aes::Aes128> = (*block).into();
        c.decrypt_block(&mut out);
        out.into()
    } else {
        let c = aes::Aes256::new_from_slice(key).expect("clave AES-256 de 32 bytes");
        let mut out: cipher::Block<aes::Aes256> = (*block).into();
        c.decrypt_block(&mut out);
        out.into()
    }
}

/// DK/DR de RFC 3961 §5.1: n-fold de la constante a un bloque y cifrado
/// ECB iterado (cada salida es la entrada del siguiente) hasta llenar
/// `keylen` bytes.
pub fn derive_random_rfc3961(key: &[u8], constant: &[u8], keylen: usize) -> Vec<u8> {
    let mut block: [u8; AES_BLOCK] = if constant.len() == AES_BLOCK {
        constant.try_into().expect("constante de 16 bytes")
    } else {
        nfold(constant, AES_BLOCK * 8)
            .try_into()
            .expect("n-fold a 128 bits")
    };
    let mut out = Vec::with_capacity(keylen + AES_BLOCK);
    loop {
        block = aes_ecb_encrypt_block(key, &block);
        out.extend_from_slice(&block);
        if out.len() >= keylen {
            break;
        }
    }
    out.truncate(keylen);
    out
}

/// Deriva la clave de uso `usage || octeto` (0x99 checksum, 0xAA cifrado,
/// 0x55 integridad) según RFC 3961 §5.3.
fn derive_usage_key(base: &[u8], usage: u32, octet: u8, keylen: usize) -> Vec<u8> {
    let mut constant = Vec::with_capacity(5);
    constant.extend_from_slice(&usage.to_be_bytes());
    constant.push(octet);
    derive_random_rfc3961(base, &constant, keylen)
}

/// string-to-key de RFC 3962 §4: PBKDF2-HMAC-SHA1 sobre la contraseña y
/// el salt TAL CUAL (RFC 3962 no especifica UTF-16 para AES: los vectores
/// del Apéndice B usan los bytes en claro), y después DK(tempkey,
/// "kerberos"). La conversión a UTF-16LE es cosa de RC4/NT-hash, no de AES.
pub fn string_to_key(keylen: usize, password_utf16le: &[u8], salt: &[u8], iterations: u32) -> Result<Vec<u8>> {
    if iterations == 0 || iterations >= 0x0100_0000 {
        // MIT rechaza 0 (significaría 2^32) y ≥ 2^24 (límite de
        // implementación); Charon replica la política.
        return Err(CryptoError::BadIterationCount(iterations));
    }
    let mut tkey = vec![0u8; keylen];
    pbkdf2::pbkdf2_hmac::<Sha1>(password_utf16le, salt, iterations, &mut tkey);
    Ok(derive_random_rfc3961(&tkey, b"kerberos", keylen))
}

// ---------- CTS (robo de cifrado) ----------

/// CBC-CTS de RFC 3962 §5 (equivalente a MIT `krb5int_aes_encrypt`):
/// CBC normal para todos los bloques salvo los dos últimos; esos se
/// cifran y se devuelven en orden inverso, truncando el bloque cifrado
/// penúltimo cuando el último es parcial.
pub fn cts_encrypt(key: &[u8], ivec: &[u8; AES_BLOCK], plaintext: &[u8]) -> Vec<u8> {
    let len = plaintext.len();
    let nblocks = len.div_ceil(AES_BLOCK);
    if nblocks == 1 {
        // Bloque único: relleno con ceros (el relleno es indefinido según
        // el RFC; Kerberos nunca lo usa porque siempre hay confounder).
        let mut block = [0u8; AES_BLOCK];
        block[..len].copy_from_slice(plaintext);
        let c = aes_ecb_encrypt_block(key, &block);
        return c[..len].to_vec();
    }

    let mut out = vec![0u8; len];
    let mut iv = *ivec;
    // CBC de los n-2 primeros bloques.
    let head_blocks = nblocks - 2;
    for i in 0..head_blocks {
        let mut b = [0u8; AES_BLOCK];
        b.copy_from_slice(&plaintext[i * AES_BLOCK..(i + 1) * AES_BLOCK]);
        for j in 0..AES_BLOCK {
            b[j] ^= iv[j];
        }
        let c = aes_ecb_encrypt_block(key, &b);
        out[i * AES_BLOCK..(i + 1) * AES_BLOCK].copy_from_slice(&c);
        iv = c;
    }

    // Los dos últimos bloques de ENTRADA: penúltimo completo y último
    // (posiblemente parcial, rellenado con ceros).
    let pos = head_blocks * AES_BLOCK;
    let mut p_n1 = [0u8; AES_BLOCK];
    p_n1.copy_from_slice(&plaintext[pos..pos + AES_BLOCK]);
    let mut p_n = [0u8; AES_BLOCK];
    let last = &plaintext[pos + AES_BLOCK..];
    p_n[..last.len()].copy_from_slice(last);

    let mut c_n1 = p_n1;
    for j in 0..AES_BLOCK {
        c_n1[j] ^= iv[j];
    }
    let c_n1 = aes_ecb_encrypt_block(key, &c_n1);

    let mut c_n = p_n;
    for j in 0..AES_BLOCK {
        c_n[j] ^= c_n1[j];
    }
    let c_n = aes_ecb_encrypt_block(key, &c_n);

    // Orden inverso: Cn' primero (siempre completo), luego C_{n-1}'
    // truncado a los bytes que faltan para no expandir el mensaje.
    let mut o = pos;
    out[o..o + AES_BLOCK].copy_from_slice(&c_n);
    o += AES_BLOCK;
    let avail = len - o;
    out[o..].copy_from_slice(&c_n1[..avail]);
    out
}

/// Inverso exacto de `cts_encrypt`.
pub fn cts_decrypt(key: &[u8], ivec: &[u8; AES_BLOCK], ciphertext: &[u8]) -> Vec<u8> {
    let len = ciphertext.len();
    let nblocks = len.div_ceil(AES_BLOCK);
    if nblocks == 1 {
        let mut block = [0u8; AES_BLOCK];
        block[..len].copy_from_slice(ciphertext);
        let p = aes_ecb_decrypt_block(key, &block);
        return p[..len].to_vec();
    }

    let head_blocks = nblocks - 2;
    let pos = head_blocks * AES_BLOCK;
    // last_len: bytes del último bloque (1..16); con bloques completos es 16.
    let last_len = len - (nblocks - 1) * AES_BLOCK;

    let mut c_n = [0u8; AES_BLOCK];
    c_n.copy_from_slice(&ciphertext[pos..pos + AES_BLOCK]);
    // C_{n-1}' llega truncado a last_len bytes al final del buffer.
    let c_n1_head = &ciphertext[len - last_len..];

    // Reconstrucción: D(Cn') = Pn' ⊕ C_{n-1}'. Como Pn'[last_len..] son los
    // ceros de relleno, los bytes perdidos de C_{n-1}' se recuperan ahí.
    let d_cn = aes_ecb_decrypt_block(key, &c_n);
    let mut c_n1 = [0u8; AES_BLOCK];
    c_n1[..last_len].copy_from_slice(c_n1_head);
    c_n1[last_len..].copy_from_slice(&d_cn[last_len..]);

    // Bloque penúltimo en claro.
    let mut p_n1 = aes_ecb_decrypt_block(key, &c_n1);
    if head_blocks > 0 {
        // XOR con el último bloque cifrado del tramo CBC.
        let prev = &ciphertext[pos - AES_BLOCK..pos];
        for j in 0..AES_BLOCK {
            p_n1[j] ^= prev[j];
        }
    } else {
        for j in 0..AES_BLOCK {
            p_n1[j] ^= ivec[j];
        }
    }

    // Último bloque en claro: D(Cn') ⊕ C_{n-1}', truncado a last_len.
    let mut p_n = d_cn;
    for j in 0..AES_BLOCK {
        p_n[j] ^= c_n1[j];
    }

    // CBC inverso de los n-2 primeros bloques.
    let mut out = vec![0u8; len];
    let mut iv = *ivec;
    for i in 0..head_blocks {
        let mut c = [0u8; AES_BLOCK];
        c.copy_from_slice(&ciphertext[i * AES_BLOCK..(i + 1) * AES_BLOCK]);
        let mut p = aes_ecb_decrypt_block(key, &c);
        for j in 0..AES_BLOCK {
            p[j] ^= iv[j];
        }
        out[i * AES_BLOCK..(i + 1) * AES_BLOCK].copy_from_slice(&p);
        iv = c;
    }
    out[pos..pos + AES_BLOCK].copy_from_slice(&p_n1);
    out[pos + AES_BLOCK..].copy_from_slice(&p_n[..last_len]);
    out
}

// ---------- Perfil de cifrado RFC 3961 §5.3 ----------

/// Cifra con el perfil simplificado: edata = CTS(Ke, conf|plain) || HMAC(Ki, conf|plain)[:12].
/// El confounder de 16 bytes se genera aleatoriamente.
pub fn encrypt(key: &[u8], usage: u32, plaintext: &[u8]) -> Result<Vec<u8>> {
    let keylen = key.len();
    let ke = derive_usage_key(key, usage, 0xAA, keylen);
    let ki = derive_usage_key(key, usage, 0x55, keylen);

    let conf = crate::random_bytes(AES_BLOCK)?;
    let mut data = Vec::with_capacity(AES_BLOCK + plaintext.len());
    data.extend_from_slice(&conf);
    data.extend_from_slice(plaintext);

    let mac = hmac_sha1(&ki, &data);
    let cipher = cts_encrypt(&ke, &[0u8; AES_BLOCK], &data);

    let mut edata = cipher;
    edata.extend_from_slice(&mac[..AES_MAC_SIZE]);
    Ok(edata)
}

/// Descifra y verifica la integridad. Devuelve el plaintext sin confounder.
pub fn decrypt(key: &[u8], usage: u32, edata: &[u8]) -> Result<Vec<u8>> {
    if edata.len() < AES_BLOCK + AES_MAC_SIZE {
        return Err(CryptoError::CiphertextTooShort(edata.len()));
    }
    let keylen = key.len();
    let ke = derive_usage_key(key, usage, 0xAA, keylen);
    let ki = derive_usage_key(key, usage, 0x55, keylen);

    let split = edata.len() - AES_MAC_SIZE;
    let (cipher, mac) = edata.split_at(split);

    let plain = cts_decrypt(&ke, &[0u8; AES_BLOCK], cipher);
    let expected = hmac_sha1(&ki, &plain);
    if !crate::ct_eq(&expected[..AES_MAC_SIZE], mac) {
        return Err(CryptoError::ChecksumMismatch);
    }
    Ok(plain[AES_BLOCK..].to_vec())
}

/// Checksum del perfil simplificado (RFC 3961 §5.4): HMAC-SHA1(Kc, data)[:12]
/// con Kc = DK(key, usage‖0x99).
pub fn checksum(key: &[u8], usage: u32, data: &[u8]) -> Result<Vec<u8>> {
    let kc = derive_usage_key(key, usage, 0x99, key.len());
    Ok(hmac_sha1(&kc, data)[..AES_MAC_SIZE].to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex;

    const KEY128: &str = "636869636b656e207465726979616b69"; // "chicken teriyaki"

    /// Vectores de CBC-CTS del Apéndice A de RFC 3962 (extraídos
    /// programáticamente del texto del RFC).
    #[test]
    fn cts_vectors_rfc3962() {
        let key = hex::decode(KEY128).unwrap();
        let iv = [0u8; AES_BLOCK];
        let vectors: Vec<(usize, &str, &str)> = vec![
            (17, "4920776f756c64206c696b652074686520", "c6353568f2bf8cb4d8a580362da7ff7f97"),
            (31, "4920776f756c64206c696b65207468652047656e6572616c20476175277320", "fc00783e0efdb2c1d445d4c8eff7ed2297687268d6ecccc0c07b25e25ecfe5"),
            (32, "4920776f756c64206c696b65207468652047656e6572616c2047617527732043", "39312523a78662d5be7fcbcc98ebf5a897687268d6ecccc0c07b25e25ecfe584"),
            (47, "4920776f756c64206c696b65207468652047656e6572616c20476175277320436869636b656e2c20706c656173652c", "97687268d6ecccc0c07b25e25ecfe584b3fffd940c16a18c1b5549d2f838029e39312523a78662d5be7fcbcc98ebf5"),
            (48, "4920776f756c64206c696b65207468652047656e6572616c20476175277320436869636b656e2c20706c656173652c20", "97687268d6ecccc0c07b25e25ecfe5849dad8bbb96c4cdc03bc103e1a194bbd839312523a78662d5be7fcbcc98ebf5a8"),
            (64, "4920776f756c64206c696b65207468652047656e6572616c20476175277320436869636b656e2c20706c656173652c20616e6420776f6e746f6e20736f75702e", "97687268d6ecccc0c07b25e25ecfe58439312523a78662d5be7fcbcc98ebf5a84807efe836ee89a526730dbc2f7bc8409dad8bbb96c4cdc03bc103e1a194bbd8"),
        ];
        for (len, input, expected) in vectors {
            let pt = hex::decode(input).unwrap();
            assert_eq!(pt.len(), len);
            let ct = cts_encrypt(&key, &iv, &pt);
            assert_eq!(hex::encode(&ct), expected, "CTS encrypt de {len} bytes");
            let back = cts_decrypt(&key, &iv, &ct);
            assert_eq!(back, pt, "CTS round-trip de {len} bytes");
        }
    }

    /// Vectores de string-to-key del Apéndice B de RFC 3962. Validan la
    /// cadena completa PBKDF2 + n-fold + DK ("kerberos").
    #[test]
    fn string_to_key_vectors_rfc3962() {
        let long_x = "X".repeat(64);
        let cases: Vec<(&str, &str, u32, &str, &str)> = vec![
            // (password, salt, iteraciones, clave AES128, clave AES256)
            ("password", "ATHENA.MIT.EDUraeburn", 1,
             "42263c6e89f4fc28b8df68ee09799f15",
             "fe697b52bc0d3ce14432ba036a92e65bbb52280990a2fa27883998d72af30161"),
            ("password", "ATHENA.MIT.EDUraeburn", 2,
             "c651bf29e2300ac27fa469d693bdda13",
             "a2e16d16b36069c135d5e9d2e25f896102685618b95914b467c67622225824ff"),
            ("password", "ATHENA.MIT.EDUraeburn", 1200,
             "4c01cd46d632d01e6dbe230a01ed642a",
             "55a6ac740ad17b4846941051e1e8b0a7548d93b0ab30a8bc3ff16280382b8c2a"),
            ("password", "\u{1234}\u{5678}\u{7856}\u{3412}", 5,
             "e9b23d52273747dd5c35cb55be619d8e",
             "97a4e786be20d81a382d5ebc96d5909cabcdadc87ca48f574504159f16c36e31"),
            (long_x.as_str(), "pass phrase equals block size", 1200,
             "59d1bb789a828b1aa54ef9c2883f69ed",
             "89adee3608db8bc71f1bfbfe459486b05618b70cbae22092534e56c553ba4b34"),
        ];
        for (pass, salt, iters, k128, k256) in cases {
            // RFC 3962 Ap. B: los bytes de la contraseña van tal cual
            // (no UTF-16LE: eso es el etype RC4).
            let pass_bytes = pass.as_bytes();
            let salt_bytes: Vec<u8> = if salt == "\u{1234}\u{5678}\u{7856}\u{3412}" {
                hex::decode("1234567878563412").unwrap() // salt binario del vector
            } else {
                salt.as_bytes().to_vec()
            };
            let k = string_to_key(16, pass_bytes, &salt_bytes, iters).unwrap();
            assert_eq!(hex::encode(&k), k128, "AES128 iters={iters}");
            let k = string_to_key(32, pass_bytes, &salt_bytes, iters).unwrap();
            assert_eq!(hex::encode(&k), k256, "AES256 iters={iters}");
        }
    }

    #[test]
    fn profile_roundtrip_and_tamper() {
        let key = hex::decode(KEY128).unwrap();
        for len in [0usize, 1, 15, 16, 17, 31, 32, 100, 1000] {
            let pt: Vec<u8> = (0..len).map(|i| (i * 7) as u8).collect();
            let ed = encrypt(&key, 3, &pt).unwrap();
            assert_eq!(ed.len(), len + AES_BLOCK + AES_MAC_SIZE);
            let back = decrypt(&key, 3, &ed).unwrap();
            assert_eq!(back, pt, "round-trip de {len} bytes");
        }
        // Manipulación: un byte del cifrado rompe la verificación.
        let pt = b"laboratorio kerberos";
        let mut ed = encrypt(&key, 3, pt).unwrap();
        let n = ed.len();
        ed[n - 13] ^= 0xFF; // toca el último byte del ciphertext
        assert!(matches!(decrypt(&key, 3, &ed), Err(CryptoError::ChecksumMismatch)));
        // Manipular con otro usage también rompe (las claves derivadas cambian).
        let ed = encrypt(&key, 3, pt).unwrap();
        assert!(matches!(decrypt(&key, 8, &ed), Err(CryptoError::ChecksumMismatch)));
    }

    #[test]
    fn rejects_bad_iterations() {
        assert!(matches!(string_to_key(16, b"p", b"s", 0), Err(CryptoError::BadIterationCount(0))));
        assert!(matches!(string_to_key(16, b"p", b"s", 0x0100_0000), Err(CryptoError::BadIterationCount(_))));
    }
}
