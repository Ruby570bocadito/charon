//! Errores del codec DER. Mensajes en español, orientados a explicar
//! exactamente qué byte/estructura falló (Charon es una herramienta de
//! análisis: el error también es observación).

use crate::Tag;
use thiserror::Error;

#[derive(Error, Debug, PartialEq, Eq)]
pub enum Asn1Error {
    #[error("DER truncado: se necesitan {needed} bytes y hay {available}")]
    Truncated { needed: usize, available: usize },

    #[error("longitud indefinida (0x80): prohibida en DER")]
    IndefiniteLength,

    #[error("longitud DER malformada ({nbytes} bytes de longitud, máx. 8)")]
    BadLengthForm { nbytes: usize },

    #[error("longitud DER excesiva ({len} bytes, máx. {max})")]
    LengthTooLarge { len: usize, max: usize },

    #[error("clase de tag inválida ({0})")]
    BadClass(u8),

    #[error("tag de forma larga (número {0}): Kerberos no lo usa y DER de Charon no lo soporta")]
    LongTag(u32),

    #[error("tag inesperado: se esperaba {expected:?}, se encontró {found:?}")]
    TagMismatch { expected: Tag, found: Tag },

    #[error("INTEGER vacío o con signo imposible de decodificar")]
    BadInteger,

    #[error("BIT STRING inválida (bits sin usar = {0}, debe ser 0..7)")]
    BadBitString(u8),

    #[error("BIT STRING vacía sin byte de bits sin usar: forma BER, no DER")]
    EmptyBitString,

    #[error("BOOLEAN inválido (longitud != 1)")]
    BadBoolean,

    #[error("tiempo Kerberos (GeneralizedTime) inválido: '{0}'")]
    BadTime(String),

    #[error("UTF-8 inválido en string Kerberos")]
    BadUtf8,

    #[error("sobran {0} bytes al final del elemento (DER debe consumirlo todo)")]
    TrailingBytes(usize),

    #[error("se esperaba un tag construido [contexto] para envolver el elemento real")]
    NotConstructed,
}
