//! Tiempo Kerberos (`KerberosTime`): GeneralizedTime en formato
//! "AAAAMMDDHHMMSSZ" (UTC, con segundos, sin fracciones — RFC 4120 §5.2.8).
//!
//! Se implementa conversión civil↔epoch propia (algoritmo de Howard Hinnant)
//! para no depender de una librería de fechas: Charon solo necesita
//! precisión de segundos y formato estricto.

use crate::{Asn1Error, Result};

/// Punto en tiempo con precisión de segundos, representado como segundos
/// desde la época UNIX en UTC.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct KrbTime {
    pub unix_secs: i64,
}

const SECS_PER_DAY: i64 = 86_400;

impl KrbTime {
    pub fn from_unix(secs: i64) -> Self {
        KrbTime { unix_secs: secs }
    }

    pub fn now() -> Self {
        let secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            // Un reloj anterior a 1970 no ocurre en la práctica; -1 lo hace
            // visible en los traces en lugar de fallar silenciosamente.
            .unwrap_or(-1);
        KrbTime { unix_secs: secs }
    }

    /// Devuelve `self` avanzado `secs` segundos (admite negativos).
    pub fn plus_secs(&self, secs: i64) -> KrbTime {
        KrbTime {
            unix_secs: self.unix_secs + secs,
        }
    }

    /// Diferencia en segundos (`other - self`).
    pub fn diff_secs(&self, other: KrbTime) -> i64 {
        other.unix_secs - self.unix_secs
    }

    fn civil(&self) -> (i64, u32, u32, u32, u32, u32) {
        let secs = self.unix_secs;
        let days = secs.div_euclid(SECS_PER_DAY);
        let rem = secs.rem_euclid(SECS_PER_DAY);
        let (y, m, d) = civil_from_days(days);
        let h = (rem / 3600) as u32;
        let mi = ((rem % 3600) / 60) as u32;
        let s = (rem % 60) as u32;
        (y, m, d, h, mi, s)
    }

    /// Formato de cable: "AAAAMMDDHHMMSSZ".
    pub fn to_wire(&self) -> String {
        let (y, m, d, h, mi, s) = self.civil();
        format!("{y:04}{m:02}{d:02}{h:02}{mi:02}{s:02}Z")
    }

    /// Parseo estricto de GeneralizedTime Kerberos: 15 caracteres,
    /// terminado en 'Z', sin fracciones.
    pub fn from_wire(s: &str) -> Result<Self> {
        let bad = || Asn1Error::BadTime(s.to_string());
        let b = s.as_bytes();
        if b.len() != 15 || b[14] != b'Z' {
            return Err(bad());
        }
        for &c in &b[..14] {
            if !c.is_ascii_digit() {
                return Err(bad());
            }
        }
        let num = |from: usize, to: usize| -> i64 {
            s.get(from..to)
                .and_then(|x| x.parse::<i64>().ok())
                .unwrap_or(-1)
        };
        let (y, mo, d, h, mi, se) = (num(0, 4), num(4, 6), num(6, 8), num(8, 10), num(10, 12), num(12, 14));
        if !(1..=12).contains(&mo) {
            return Err(bad());
        }
        if d < 1 || d > days_in_month(y, mo as u32) {
            return Err(bad());
        }
        if h > 23 || mi > 59 || se > 60 {
            return Err(bad());
        }
        let days = days_from_civil(y, mo as u32, d as u32);
        Ok(KrbTime {
            unix_secs: days * SECS_PER_DAY + h * 3600 + mi * 60 + se,
        })
    }
}

impl std::fmt::Display for KrbTime {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_wire())
    }
}

fn is_leap(y: i64) -> bool {
    (y % 4 == 0 && y % 100 != 0) || y % 400 == 0
}

fn days_in_month(y: i64, m: u32) -> i64 {
    match m {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 => {
            if is_leap(y) {
                29
            } else {
                28
            }
        }
        _ => 0,
    }
}

/// Días desde la época UNIX → (año, mes, día). Algoritmo civil de Hinnant.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32; // [1, 12]
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// (año, mes, día) → días desde la época UNIX. Inverso de `civil_from_days`.
fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400; // [0, 399]
    let mp = if m > 2 { m - 3 } else { m + 9 } as i64;
    let doy = (153 * mp + 2) / 5 + d as i64 - 1; // [0, 365]
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy; // [0, 146096]
    era * 146_097 + doe - 719_468
}
