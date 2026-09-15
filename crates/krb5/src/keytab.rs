//! # keytab — formato KEYTAB FILE de MIT krb5 (versiones 1 y 2)
//!
//! Implementación del formato de fichero keytab leído por
//! `lib/krb5/keytab/kt_file.c` de MIT (1.21.3, fuente verificada línea a
//! línea en el lab). Un keytab es un almacén LOCAL de claves largas:
//! servicios (y cualquier principal exportado con `ktadd`) lo usan para
//! autenticar SIN contraseña — Charon lo lee para los mismos flujos.
//!
//! Cabecera: `u16` big-endian con la versión del formato:
//! `0x0501` (v1, compatibilidad DCE) o `0x0502` (v2, estándar).
//!
//! Después del header, una secuencia de entradas. Cada entrada empieza
//! con `i32 size` que cuenta SOLO el cuerpo (los 4 bytes del propio size
//! quedan fuera; la siguiente entrada está en `inicio_del_cuerpo + size`):
//!
//! ```text
//! i32   size        (v2: big-endian; v1: orden NATIVO del escritor — LE
//!                    en la práctica; MIT lee host-order y nosotros LE)
//! u16   ncomp       (v2: BE. v1: LE y ADEMÁS INCLUYE el reino — MIT hace
//!                    `count -= 1` en v1; el reino va como primer campo)
//! data  reino       (u16 len + bytes)
//! ncomp × (u16 len + bytes)   componentes del principal
//! [v2 only] i32 name-type (BE)
//! u32   timestamp   (segundos UNIX; v2 BE, v1 nativo LE)
//! u8    kvno        (versión de clave a 8 bits)
//! u16   enctype     (v2 BE, v1 LE)
//! u16   keylen      (v2 BE, v1 LE) + keylen bytes de clave EN CLARO
//! [opcional] u32 kvno extendido — si quedan ≥4 bytes en el cuerpo se
//!        interpreta como kvno de 32 bits (0 = solo relleno, se ignora)
//! ```
//!
//! Entradas **borradas**: `kdestroy`-style delete reescribe `size` como
//! negativo (con el cuerpo zeroizado); el lector las salta buscando el
//! siguiente registro (mismo criterio que MIT). `size == 0` termina el
//! fichero (KRB5_KT_END de MIT).
//!
//! Seguridad: las claves viajan en claro (es el diseño del formato, igual
//! que un ccache). El parser lee ficheros NO confiables sin panics
//! (lecturas acotadas con offset en el error) y `KeytabEntry` hace
//! zeroize de la clave al soltarla (mismo patrón que `KerberosKey` en
//! kcrypto). El fichero en disco debe estar 0600.

use zeroize::Zeroize;

use crate::{Krb5Error, Result};

/// Firma/versión v1 (compatibilidad DCE).
pub const VNO_1: u16 = 0x0501;
/// Firma/versión v2 (estándar).
pub const VNO_2: u16 = 0x0502;

/// Tope de componentes por principal y de entradas por fichero: un
/// fichero hostil no debe poder provocar reservas enormes.
const MAX_COMPONENTS: usize = 256;
const MAX_ENTRIES: usize = 4096;

/// Una entrada de keytab: la clave larga de un principal con su kvno.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeytabEntry {
    pub realm: String,
    pub components: Vec<String>,
    /// `name-type` del principal (solo lo traen los keytabs v2; en v1 el
    /// formato no lo tiene → `None`).
    pub name_type: Option<i32>,
    /// Versión de la clave (el u8 del formato, ampliado por el u32
    /// opcional cuando el kvno no cabe en 8 bits).
    pub kvno: u32,
    /// Segundos UNIX de creación de la entrada (tal cual el formato).
    pub timestamp: u32,
    /// Tipo de encripción (`charon_kcrypto::etype`).
    pub enctype: i32,
    /// Clave EN CLARO (así es el formato). Se zeroizea al soltar la
    /// entrada; no la imprimas nunca.
    pub key: Vec<u8>,
}

impl Drop for KeytabEntry {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

impl KeytabEntry {
    /// Nombre plano del principal (`jdoe`, `host/fqdn`), sin el reino.
    pub fn flat(&self) -> String {
        self.components.join("/")
    }

    /// `usuario@REINO` (asume un componente; el flat en caso contrario).
    pub fn qualified(&self) -> String {
        format!("{}@{}", self.flat(), self.realm)
    }
}

/// Parsea un keytab completo (v1 o v2). Lecturas acotadas: un fichero
/// truncado o hostil produce `Krb5Error::BadKeytab` con el offset, nunca
/// un panic.
pub fn parse(bytes: &[u8]) -> Result<Vec<KeytabEntry>> {
    if bytes.len() < 2 {
        return Err(Krb5Error::BadKeytab(
            "fichero de menos de 2 bytes: no hay cabecera".into(),
        ));
    }
    let version = u16::from_be_bytes([bytes[0], bytes[1]]);
    if version != VNO_1 && version != VNO_2 {
        return Err(Krb5Error::BadKeytab(format!(
            "versión de keytab {version:#06x} no soportada (0x0501 o 0x0502)"
        )));
    }
    let is_v1 = version == VNO_1;
    let mut r = Reader { buf: bytes, pos: 2 };
    let mut entries = Vec::new();
    loop {
        // `size` es i32 SIGNED: negativo = entrada borrada; 0 = fin. El
        // EOF también es fin limpio (MIT: fread falla → KRB5_KT_END; un
        // keytab no garantiza un 00000000 final).
        if r.remaining() < 4 {
            break;
        }
        let size = if is_v1 { r.i32_le()? } else { r.i32()? };
        if size == 0 {
            break;
        }
        if size < 0 {
            if size == i32::MIN {
                return Err(Krb5Error::BadKeytab(
                    "size i32::MIN en el marcador de borrado: formato roto".into(),
                ));
            }
            // Entrada borrada: salta el cuerpo (|size| bytes desde ya).
            r.skip(size.unsigned_abs() as usize)?;
            if r.pos >= r.buf.len() {
                break;
            }
            continue;
        }
        if size as usize > r.buf.len() {
            return Err(Krb5Error::BadKeytab(format!(
                "entrada de {size} bytes que no caben en el fichero (offset {})",
                r.pos
            )));
        }
        let body = r.take(size as usize)?;
        if entries.len() >= MAX_ENTRIES {
            return Err(Krb5Error::BadKeytab(format!(
                "más de {MAX_ENTRIES} entradas: fichero corrupto o hostil"
            )));
        }
        entries.push(parse_entry(is_v1, body)?);
    }
    Ok(entries)
}

/// Parsea el CUERPO de una entrada (sin el `size` de framing), sobre el
/// slice exacto que delimita el tamaño declarado: cualquier campo que se
/// salga es fichero corrupto.
fn parse_entry(is_v1: bool, body: &[u8]) -> Result<KeytabEntry> {
    let mut r = Reader { buf: body, pos: 0 };
    // u16 con el número de componentes. En v1 el contador INCLUYE el
    // reino (MIT: count -= 1); en v2 no.
    let count = if is_v1 { r.u16_le()? } else { r.u16()? };
    let count = if is_v1 { count.saturating_sub(1) } else { count } as usize;
    if count == 0 || count > MAX_COMPONENTS {
        return Err(Krb5Error::BadKeytab(format!(
            "principal con {count} componentes: corrupto o hostil"
        )));
    }
    let realm = String::from_utf8_lossy(r.data_u16(is_v1)?).into_owned();
    let mut components = Vec::with_capacity(count.min(8));
    for _ in 0..count {
        components.push(String::from_utf8_lossy(r.data_u16(is_v1)?).into_owned());
    }
    // name-type: SOLO existe en v2 (el formato v1 no lo trae).
    let name_type = if is_v1 { None } else { Some(r.i32()?) };
    let timestamp = if is_v1 { r.u32_le()? } else { r.u32()? };
    let kvno8 = r.u8()?;
    let enctype = if is_v1 { r.u16_le()? as i32 } else { r.u16()? as i32 };
    let key_len = if is_v1 { r.u16_le()? as usize } else { r.u16()? as usize };
    if key_len == 0 {
        return Err(Krb5Error::BadKeytab("keyblock de 0 bytes".into()));
    }
    let key = r.take(key_len)?.to_vec();
    // Extensión opcional de kvno a 32 bits: MIT la lee si quedan ≥4
    // bytes de cuerpo; un valor 0 es solo relleno y no pisa el kvno de
    // 8 bits.
    let mut kvno = kvno8 as u32;
    if r.remaining() >= 4 {
        let kvno32 = if is_v1 { r.u32_le()? } else { r.u32()? };
        if kvno32 != 0 {
            kvno = kvno32;
        }
    }
    Ok(KeytabEntry { realm, components, name_type, kvno, timestamp, enctype, key })
}

// ---------- lectura acotada (sin panics) ----------

struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self.pos.checked_add(n).ok_or_else(|| {
            Krb5Error::BadKeytab(format!("longitud absurda en el offset {}", self.pos))
        })?;
        let slice = self.buf.get(self.pos..end).ok_or_else(|| {
            Krb5Error::BadKeytab(format!("fichero truncado en el offset {}", self.pos))
        })?;
        self.pos = end;
        Ok(slice)
    }

    fn skip(&mut self, n: usize) -> Result<()> {
        self.take(n).map(|_| ())
    }

    fn remaining(&self) -> usize {
        self.buf.len().saturating_sub(self.pos)
    }

    fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }

    /// u16 big-endian (v2).
    fn u16(&mut self) -> Result<u16> {
        let b = self.take(2)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }

    /// u16 little-endian (v1 en máquinas LE, el orden nativo del escritor).
    fn u16_le(&mut self) -> Result<u16> {
        let b = self.take(2)?;
        Ok(u16::from_le_bytes([b[0], b[1]]))
    }

    /// i32 big-endian (v2).
    fn i32(&mut self) -> Result<i32> {
        let b = self.take(4)?;
        Ok(i32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }

    /// i32 little-endian (v1).
    fn i32_le(&mut self) -> Result<i32> {
        let b = self.take(4)?;
        Ok(i32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    /// u32 big-endian (v2).
    fn u32(&mut self) -> Result<u32> {
        let b = self.take(4)?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }

    /// u32 little-endian (v1).
    fn u32_le(&mut self) -> Result<u32> {
        let b = self.take(4)?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    /// Campo con longitud u16 (endian según versión): longitud + bytes.
    fn data_u16(&mut self, le: bool) -> Result<&'a [u8]> {
        let len = if le { self.u16_le()? } else { self.u16()? } as usize;
        self.take(len)
    }
}

// ---------- tests ----------

#[cfg(test)]
mod tests {
    use super::*;

    /// Fixture REAL generado con `ktutil` de MIT krb5 1.21.3 (v2):
    /// jdoe@LAB.LOCAL (aes256 kvno 1 + rc4 kvno 1) y
    /// host/demo.lab.local@LAB.LOCAL (aes128, kvno 258 — ejercita la
    /// extensión de kvno a 32 bits). La contraseña del fixture es de
    /// prueba ("FixtureOnly42"): el fichero NO contiene secretos reales.
    const FIXTURE_MIT: &[u8] = include_bytes!("../tests/fixtures/mit-ktutil-v2.keytab");

    #[test]
    fn la_string2key_de_mit_coincide_con_la_nuestra() {
        // El addent de MIT derivó la clave de "FixtureOnly42" con salt
        // LAB.LOCALjdoe: si nuestra derivación RFC 3962 no coincidiera
        // byte a byte, este test falla — dos implementaciones, un RFC.
        let entries = parse(FIXTURE_MIT).expect("fixture MIT parsea");
        let ours = charon_kcrypto::KerberosKey::from_password(
            "FixtureOnly42",
            "LAB.LOCALjdoe",
            charon_kcrypto::etype::AES256_CTS_HMAC_SHA1_96,
        )
        .expect("derivación AES256");
        assert_eq!(entries[0].key, ours.as_bytes(), "string2key de MIT == nuestra RFC 3962");
    }

    #[test]
    fn parsea_el_fichero_real_de_ktutil_de_mit() {
        let entries = parse(FIXTURE_MIT).expect("el keytab de ktutil debe parsear");
        assert_eq!(entries.len(), 3);
        let (jdoe_aes, jdoe_rc4, host) = (&entries[0], &entries[1], &entries[2]);

        assert_eq!(jdoe_aes.realm, "LAB.LOCAL");
        assert_eq!(jdoe_aes.components, vec!["jdoe"]);
        assert_eq!(jdoe_aes.flat(), "jdoe");
        assert_eq!(jdoe_aes.qualified(), "jdoe@LAB.LOCAL");
        assert_eq!(jdoe_aes.name_type, Some(1)); // NT_PRINCIPAL
        assert_eq!(jdoe_aes.kvno, 1);
        assert_eq!(jdoe_aes.enctype, 18);
        assert_eq!(jdoe_aes.key.len(), 32, "clave AES256");
        assert!(jdoe_aes.timestamp > 0);

        assert_eq!(jdoe_rc4.enctype, 23);
        assert_eq!(jdoe_rc4.key.len(), 16, "clave RC4");

        // kvno 258 no cabe en 8 bits: la extensión u32 es obligatoria.
        assert_eq!(host.components, vec!["host", "demo.lab.local"]);
        assert_eq!(host.kvno, 258, "el kvno de 32 bits pisa al u8");
        assert_eq!(host.enctype, 17);
        assert_eq!(host.key.len(), 16, "clave AES128");
    }

    /// Keytab v2 construido a mano, byte a byte según la documentación del
    /// módulo (fuente: kt_file.c de MIT 1.21.3).
    fn v2_sintetico(kvno_ext: Option<u32>) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&1u16.to_be_bytes()); // 1 componente
        body.extend_from_slice(&9u16.to_be_bytes());
        body.extend_from_slice(b"LAB.LOCAL"); // reino
        body.extend_from_slice(&4u16.to_be_bytes());
        body.extend_from_slice(b"jdoe"); // componente
        body.extend_from_slice(&1i32.to_be_bytes()); // name-type
        body.extend_from_slice(&1_789_462_092u32.to_be_bytes()); // timestamp
        body.push(0xff); // kvno de 8 bits saturado
        body.extend_from_slice(&18u16.to_be_bytes()); // enctype
        body.extend_from_slice(&32u16.to_be_bytes()); // keylen
        body.extend_from_slice(&[0xab; 32]); // clave
        if let Some(v) = kvno_ext {
            body.extend_from_slice(&v.to_be_bytes()); // extensión u32
        }

        let mut out = vec![0x05, 0x02];
        out.extend_from_slice(&(body.len() as i32).to_be_bytes());
        out.extend_from_slice(&body);
        out
    }

    #[test]
    fn v2_sintetico_se_parsea_campo_a_campo() {
        let entries = parse(&v2_sintetico(Some(700))).expect("parsea");
        assert_eq!(entries.len(), 1);
        let e = &entries[0];
        assert_eq!(e.realm, "LAB.LOCAL");
        assert_eq!(e.components, vec!["jdoe"]);
        assert_eq!(e.name_type, Some(1));
        assert_eq!(e.timestamp, 1_789_462_092);
        assert_eq!(e.kvno, 700, "la extensión u32 pisa al 0xff");
        assert_eq!(e.enctype, 18);
        assert_eq!(e.key, vec![0xab; 32]);
    }

    #[test]
    fn la_extension_a_ceros_no_pisa_el_kvno_de_8_bits() {
        let entries = parse(&v2_sintetico(None)).expect("sin extensión");
        assert_eq!(entries[0].kvno, 255, "kvno del u8 sin extensión");
        let entries = parse(&v2_sintetico(Some(0))).expect("extensión a 0 = relleno");
        assert_eq!(entries[0].kvno, 255, "un 0 en la extensión NO pisa el kvno");
    }

    /// Keytab v1 (little-endian, contador que INCLUYE el reino, sin
    /// name-type): el formato de compatibilidad DCE.
    #[test]
    fn v1_se_parsea_en_little_endian_y_reino_dentro_del_contador() {
        let mut body = Vec::new();
        body.extend_from_slice(&2u16.to_le_bytes()); // reino + 1 componente
        body.extend_from_slice(&9u16.to_le_bytes());
        body.extend_from_slice(b"LAB.LOCAL");
        body.extend_from_slice(&4u16.to_le_bytes());
        body.extend_from_slice(b"jdoe");
        body.extend_from_slice(&1_789_462_092u32.to_le_bytes()); // timestamp
        body.push(3); // kvno
        body.extend_from_slice(&23u16.to_le_bytes()); // enctype RC4
        body.extend_from_slice(&16u16.to_le_bytes()); // keylen
        body.extend_from_slice(&[0xcd; 16]);

        let mut out = vec![0x05, 0x01];
        out.extend_from_slice(&(body.len() as i32).to_le_bytes());
        out.extend_from_slice(&body);

        let entries = parse(&out).expect("v1 parsea");
        assert_eq!(entries.len(), 1);
        let e = &entries[0];
        assert_eq!(e.components, vec!["jdoe"], "el contador v1 incluía el reino");
        assert_eq!(e.name_type, None, "v1 no trae name-type");
        assert_eq!(e.kvno, 3);
        assert_eq!(e.enctype, 23);
        assert_eq!(e.key, vec![0xcd; 16]);
    }

    #[test]
    fn las_entradas_borradas_se_saltan_hasta_la_siguiente() {
        let mut file = v2_sintetico(None);
        // Entrada borrada: size negativo + cuerpo relleno de ceros.
        let body_borrado = vec![0u8; 40];
        file.extend_from_slice(&(-(body_borrado.len() as i32)).to_be_bytes());
        file.extend_from_slice(&body_borrado);
        // Segunda entrada válida detrás de la borrada.
        let body2 = v2_body();
        file.extend_from_slice(&(body2.len() as i32).to_be_bytes());
        file.extend_from_slice(&body2);

        let entries = parse(&file).expect("las borradas se saltan");
        assert_eq!(entries.len(), 2, "solo las 2 entradas válidas");
    }

    fn v2_body() -> Vec<u8> {
        let v = v2_sintetico(None);
        v[6..].to_vec() // cabecera 2 bytes + size 4 bytes
    }

    #[test]
    fn truncados_y_basura_producen_error_sin_panics() {
        // Basura y cabeceras inválidas.
        assert!(parse(&[]).is_err());
        assert!(parse(&[0x05]).is_err());
        assert!(parse(&[0x05, 0x03]).is_err(), "versión desconocida");
        assert!(parse(&[0x07, 0x02]).is_err());
        // Solo cabecera: fin limpio, cero entradas (no es error).
        assert!(parse(&[0x05, 0x02]).unwrap().is_empty());

        // Truncado progresivo del fixture real: nunca panic; o parsea un
        // prefijo válido (fin limpio) o falla con error con contexto.
        let full = FIXTURE_MIT;
        for cut in [6, 12, 30, 60, 100, 150, full.len() - 8, full.len() - 3] {
            let r = parse(&full[..cut]);
            match r {
                Ok(entries) => assert!(entries.len() <= 3, "corte a {cut}: nunca más entradas que el fichero completo"),
                Err(e) => assert!(e.to_string().contains("keytab") || e.to_string().contains("truncado") || e.to_string().contains("offset"), "corte a {cut}: error con contexto: {e}"),
            }
        }

        // size que anuncia más de lo que hay.
        let mut mentiroso = vec![0x05, 0x02];
        mentiroso.extend_from_slice(&4096i32.to_be_bytes());
        mentiroso.extend_from_slice(&[0u8; 16]);
        assert!(parse(&mentiroso).is_err());
    }

    #[test]
    fn el_size_de_framing_delimita_el_cuerpo_con_precision() {
        // El cuerpo declarado por `size` manda: relleno DENTRO del cuerpo
        // se interpreta como extensión de kvno (aquí a 0: se ignora y el
        // kvno del u8 sobrevive); bytes fuera de todo framing al final
        // del fichero son basura y producen error — el mismo criterio que
        // MIT (KRB5_KT_END al leer las entrañas del siguiente registro).

        // (a) relleno interno: el cuerpo se declara 8 bytes más largos.
        let mut body = v2_body();
        body.extend_from_slice(&[0u8; 8]); // relleno dentro del cuerpo
        let mut out = vec![0x05, 0x02];
        out.extend_from_slice(&(body.len() as i32).to_be_bytes());
        out.extend_from_slice(&body);
        let entries = parse(&out).expect("el relleno interno se tolera");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].kvno, 255, "el relleno a 0 no pisa el kvno");

        // (b) basura externa sin framing: error, como en MIT.
        let mut out = vec![0x05, 0x02];
        let mut body = v2_body();
        out.extend_from_slice(&(body.len() as i32).to_be_bytes());
        out.append(&mut body);
        out.extend_from_slice(b"BASURA-EXTERNA");
        assert!(parse(&out).is_err(), "sin framing, la basura es error");
    }
}

