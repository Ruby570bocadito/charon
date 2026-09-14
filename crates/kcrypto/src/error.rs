//! Errores de la capa crypto de Kerberos.

use thiserror::Error;

#[derive(Error, Debug, PartialEq, Eq)]
pub enum CryptoError {
    #[error("etype {0} no soportado")]
    UnsupportedEtype(i32),

    #[error("longitud de clave inválida para el etype {etype}: {len} bytes")]
    BadKeyLength { etype: i32, len: usize },

    #[error("clave AES inválida: longitud {0} (solo 16 o 32)")]
    BadAesKeyLength(usize),

    #[error("los datos cifrados son demasiado cortos ({0} bytes)")]
    CiphertextTooShort(usize),

    #[error("la longitud del texto cifrado no es múltiplo del tamaño de bloque")]
    BadCiphertextLength,

    #[error("fallo de integridad: el checksum HMAC no coincide (¿clave o key usage incorrectos?)")]
    ChecksumMismatch,

    #[error("iteración PBKDF2 inválida ({0}): debe estar entre 1 y 16.777.215")]
    BadIterationCount(u32),

    #[error("el generador aleatorio del sistema falló: {0}")]
    Random(String),
}

pub type Result<T> = std::result::Result<T, CryptoError>;
