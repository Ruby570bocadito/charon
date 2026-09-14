//! # charon-asn1 — codec DER mínimo para Kerberos (ADR-001)
//!
//! Kerberos (RFC 4120) codifica sus mensajes en DER (X.690): TLV con
//! longitudes mínimas, indefinidas prohibidas y codificación de enteros
//! mínima. Este crate implementa **solo lo que el protocolo necesita**,
//! decidiendo explícitamente el comportamiento en cada caso:
//!
//! - **Decodificación** deliberadamente *leniente* donde los KDCs reales
//!   difieren (enteros no mínimos se aceptan), porque Charon debe poder
//!   analizar implementaciones imperfectas: un error de parseo es
//!   información, no un fallo interno.
//! - **Codificación** estrictamente conforme (mínima, canónica).
//! - Tags > 30 (forma larga): rechazados, Kerberos no los usa
//!   (el mayor es `[APPLICATION 30]` = KRB-ERROR).
//!
//! El design central es de un solo pase, cero copias sobre `&[u8]`:
//! `DerReader` emite `Element` (tag + contenido + bytes crudos) y los
//! constructores de mensajes componen TLVs con las funciones libres de
//! este módulo.

pub mod time;
pub use time::KrbTime;

mod error;
pub use error::Asn1Error;

pub type Result<T> = std::result::Result<T, Asn1Error>;

#[cfg(test)]
mod tests;

/// Cota defensiva de tamaño (16 MiB): ningún mensaje Kerberos legítimo se
/// acerca; evita allocations absurdas ante entradas corruptas o hostiles.
pub const MAX_DER_LEN: usize = 16 * 1024 * 1024;

/// Cuatro clases ASN.1 relevantes para Kerberos.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Class {
    Universal,
    Application,
    Context,
    Private,
}

impl Class {
    fn from_bits(b: u8) -> Result<Class> {
        match b >> 6 {
            0 => Ok(Class::Universal),
            1 => Ok(Class::Application),
            2 => Ok(Class::Context),
            3 => Ok(Class::Private),
            _ => Err(Asn1Error::BadClass(b >> 6)),
        }
    }

    fn to_bits(self) -> u8 {
        match self {
            Class::Universal => 0,
            Class::Application => 1,
            Class::Context => 2,
            Class::Private => 3,
        }
    }
}

/// Identificador de tag ASN.1 (clase + forma + número).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Tag {
    pub class: Class,
    pub constructed: bool,
    pub number: u32,
}

impl Tag {
    pub const BOOLEAN: Tag = Tag { class: Class::Universal, constructed: false, number: 1 };
    pub const INTEGER: Tag = Tag { class: Class::Universal, constructed: false, number: 2 };
    pub const BIT_STRING: Tag = Tag { class: Class::Universal, constructed: false, number: 3 };
    pub const OCTET_STRING: Tag = Tag { class: Class::Universal, constructed: false, number: 4 };
    pub const NULL: Tag = Tag { class: Class::Universal, constructed: false, number: 5 };
    pub const GENERALIZED_TIME: Tag = Tag { class: Class::Universal, constructed: false, number: 24 };
    pub const SEQUENCE: Tag = Tag { class: Class::Universal, constructed: true, number: 16 };

    /// `[n]` contextual (el tagging de Kerberos es explícito).
    pub const fn context(number: u32, constructed: bool) -> Tag {
        Tag { class: Class::Context, constructed, number }
    }

    /// `[APPLICATION n]` (AS-REQ=10, AS-REP=11, TGS-REQ=12, TGS-REP=13,
    /// AP-REQ=14, AP-REP=15, KRB-ERROR=30, Ticket=1, Authenticator=2...).
    pub const fn application(number: u32, constructed: bool) -> Tag {
        Tag { class: Class::Application, constructed, number }
    }

    fn encode(&self, out: &mut Vec<u8>) -> Result<()> {
        if self.number > 30 {
            // Kerberos no usa forma larga; sostener el límite mantiene el
            // codec mínimo y los errores de codec inmediatos.
            return Err(Asn1Error::LongTag(self.number));
        }
        out.push(self.class.to_bits() << 6 | (self.constructed as u8) << 5 | self.number as u8);
        Ok(())
    }

    /// Descripción humana para traces y errores.
    pub fn describe(&self) -> String {
        let shape = if self.constructed { "construido" } else { "primitivo" };
        match self.class {
            Class::Universal => match (self.number, self.constructed) {
                (1, _) => "BOOLEAN".into(),
                (2, _) => "INTEGER".into(),
                (3, _) => "BIT STRING".into(),
                (4, _) => "OCTET STRING".into(),
                (5, _) => "NULL".into(),
                (16, _) => "SEQUENCE".into(),
                (24, _) => "GeneralizedTime".into(),
                _ => format!("universal #{}, {shape}", self.number),
            },
            Class::Application => format!("[APPLICATION {}] ({shape})", self.number),
            Class::Context => format!("[{}] ({shape})", self.number),
            Class::Private => format!("[PRIVATE {}] ({shape})", self.number),
        }
    }
}

fn encode_length(len: usize, out: &mut Vec<u8>) {
    if len < 0x80 {
        out.push(len as u8);
    } else {
        // Bytes big-endian mínimos de `len`.
        let be = len.to_be_bytes();
        let start = be.iter().position(|&b| b != 0).unwrap_or(be.len() - 1);
        let nbytes = be.len() - start;
        out.push(0x80 | nbytes as u8);
        out.extend_from_slice(&be[start..]);
    }
}

/// Codifica un TLV completo (tag + longitud + contenido).
pub fn encode_tlv(tag: Tag, content: &[u8]) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(content.len() + 8);
    tag.encode(&mut out)?;
    encode_length(content.len(), &mut out);
    out.extend_from_slice(content);
    Ok(out)
}

/// `[n]` PRIMITIVO con contenido directo.
pub fn encode_context(number: u32, content: &[u8]) -> Result<Vec<u8>> {
    encode_tlv(Tag::context(number, false), content)
}

/// `[n]` CONSTRUIDO envolviendo un TLV hijo ya codificado (tagging
/// explícito, la forma usada por todos los campos de RFC 4120).
pub fn encode_context_wrapped(number: u32, child_tlv: &[u8]) -> Result<Vec<u8>> {
    encode_tlv(Tag::context(number, true), child_tlv)
}

/// SEQUENCE a partir de TLV hijos ya codificados.
pub fn encode_sequence(children: &[Vec<u8>]) -> Result<Vec<u8>> {
    let total: usize = children.iter().map(|c| c.len()).sum();
    let mut content = Vec::with_capacity(total);
    for c in children {
        content.extend_from_slice(c);
    }
    encode_tlv(Tag::SEQUENCE, &content)
}

/// BOOLEAN; `true` se codifica 0xFF (forma canónica DER).
pub fn encode_bool(v: bool) -> Vec<u8> {
    encode_tlv(Tag::BOOLEAN, &[if v { 0xFF } else { 0x00 }]).expect("tag universal")
}

/// INTEGER en complemento a dos con longitud mínima.
pub fn encode_integer(v: i64) -> Vec<u8> {
    let be = v.to_be_bytes();
    // Recorta bytes redundantes de signo, conservando al menos uno.
    let mut start = 0;
    while start < be.len() - 1 {
        let (hi, next) = (be[start], be[start + 1]);
        let redundant = (hi == 0x00 && next < 0x80) || (hi == 0xFF && next >= 0x80);
        if !redundant {
            break;
        }
        start += 1;
    }
    encode_tlv(Tag::INTEGER, &be[start..]).expect("tag universal")
}

/// OCTET STRING.
pub fn encode_octets(bytes: &[u8]) -> Vec<u8> {
    encode_tlv(Tag::OCTET_STRING, bytes).expect("tag universal")
}

/// KerberosString (GeneralString: se codifica como octetos UTF-8).
pub fn encode_string(s: &str) -> Vec<u8> {
    encode_octets(s.as_bytes())
}

/// BIT STRING alineada (0 bits sin usar) para contenido arbitrario.
pub fn encode_bitstring_aligned(bytes: &[u8]) -> Vec<u8> {
    let mut content = Vec::with_capacity(bytes.len() + 1);
    content.push(0u8); // bits sin usar
    content.extend_from_slice(bytes);
    encode_tlv(Tag::BIT_STRING, &content).expect("tag universal")
}

/// BIT STRING de flags (KDCOptions / TicketFlags / ApOptions): bits
/// numerados 0..31 con el bit 0 como MSB del primer byte, recortada a
/// longitud mínima (como codifican MIT y Windows).
pub fn encode_flags(bits: u32) -> Vec<u8> {
    if bits == 0 {
        // Un BIT STRING de flags sin bits usados: 1 byte con 0 bits sin usar.
        return encode_tlv(Tag::BIT_STRING, &[0u8]).expect("tag universal");
    }
    // Numeración Kerberos: el bit 0 es el MSB del primer byte, así que el
    // bit numerado más alto puesto es 31 - trailing_zeros (posición u32 más
    // baja ocupada).
    let highest = 31 - bits.trailing_zeros() as usize;
    let nbytes = highest / 8 + 1;
    // Bits de relleno al final del último byte.
    let unused = (nbytes * 8 - 1 - highest) as u8;
    let be = bits.to_be_bytes();
    let mut content = Vec::with_capacity(nbytes + 1);
    content.push(unused);
    content.extend_from_slice(&be[..nbytes]);
    encode_tlv(Tag::BIT_STRING, &content).expect("tag universal")
}

/// GeneralizedTime Kerberos.
pub fn encode_time(t: KrbTime) -> Vec<u8> {
    encode_tlv(Tag::GENERALIZED_TIME, t.to_wire().as_bytes()).expect("tag universal")
}

/// Elemento decodificado: tag, contenido y bytes crudos (tag+long+contenido).
/// Los bytes crudos son lo que un trace muestra.
#[derive(Debug)]
pub struct Element<'a> {
    pub tag: Tag,
    pub content: &'a [u8],
    pub raw: &'a [u8],
}

impl<'a> Element<'a> {
    fn expect_universal(&self, number: u32) -> Result<()> {
        if self.tag.class != Class::Universal || self.tag.number != number {
            return Err(Asn1Error::TagMismatch {
                expected: Tag { class: Class::Universal, constructed: false, number },
                found: self.tag,
            });
        }
        Ok(())
    }

    pub fn parse_int_i64(&self) -> Result<i64> {
        self.expect_universal(2)?;
        let c = self.content;
        if c.is_empty() || c.len() > 8 {
            return Err(Asn1Error::BadInteger);
        }
        let negative = c[0] & 0x80 != 0;
        // Con 8 bytes caben todos los i64 (complemento a dos). Un valor
        // positivo que necesite 9 bytes fue rechazado arriba por longitud.
        // Acumulación en u64 con extensión de signo inicial; los desplazamientos
        // descartan los bits de extensión sobrantes y no hay panic posible.
        let mut acc: u64 = if negative { u64::MAX } else { 0 };
        for &b in c {
            acc = (acc << 8) | b as u64;
        }
        Ok(acc as i64)
    }

    pub fn parse_int_u32(&self) -> Result<u32> {
        let v = self.parse_int_i64()?;
        u32::try_from(v).map_err(|_| Asn1Error::BadInteger)
    }

    pub fn parse_bool(&self) -> Result<bool> {
        self.expect_universal(1)?;
        if self.content.len() != 1 {
            return Err(Asn1Error::BadBoolean);
        }
        Ok(self.content[0] != 0)
    }

    /// Contenido de OCTET STRING / KerberosString como bytes crudos.
    pub fn parse_bytes(&self) -> Result<&'a [u8]> {
        self.expect_universal(4)?;
        Ok(self.content)
    }

    pub fn parse_str(&self) -> Result<&'a str> {
        std::str::from_utf8(self.parse_bytes()?).map_err(|_| Asn1Error::BadUtf8)
    }

    /// BIT STRING → (bytes, bits_sin_usar).
    pub fn parse_bitstring(&self) -> Result<(&'a [u8], u8)> {
        self.expect_universal(3)?;
        let c = self.content;
        if c.is_empty() {
            return Err(Asn1Error::EmptyBitString);
        }
        let unused = c[0];
        if unused > 7 {
            return Err(Asn1Error::BadBitString(unused));
        }
        Ok((&c[1..], unused))
    }

    /// Flags (BIT STRING numerada) como u32; el bit 0 es el MSB del primer
    /// byte. Alinea a 4 bytes y enmascara los bits de relleno del final.
    pub fn parse_flags_u32(&self) -> Result<u32> {
        let (bytes, unused) = self.parse_bitstring()?;
        if bytes.len() > 4 {
            return Err(Asn1Error::BadBitString(unused));
        }
        if bytes.is_empty() {
            // "03 01 00": bit string vacía.
            return Ok(0);
        }
        let mut bits: u32 = 0;
        for &b in bytes {
            bits = (bits << 8) | b as u32;
        }
        bits <<= (4 - bytes.len()) * 8;
        if unused > 0 {
            bits &= !((1u32 << unused) - 1);
        }
        Ok(bits)
    }

    pub fn parse_time(&self) -> Result<KrbTime> {
        self.expect_universal(24)?;
        let s = std::str::from_utf8(self.content).map_err(|_| Asn1Error::BadTime("<no utf8>".into()))?;
        KrbTime::from_wire(s)
    }

    /// Lector sobre el contenido de una SEQUENCE.
    pub fn parse_seq(&self) -> Result<DerReader<'a>> {
        self.expect_universal(16)?;
        Ok(DerReader::new(self.content))
    }

    /// Lector sobre el contenido sin verificar el tag: para los wrappers
    /// `[APPLICATION n]` de RFC 4120, que envuelven una SEQUENCE.
    pub fn content_reader(&self) -> DerReader<'a> {
        DerReader::new(self.content)
    }

    /// Verifica el tag exacto (útil para `[APPLICATION n]`).
    pub fn expect_tag(&self, want: Tag) -> Result<()> {
        if self.tag != want {
            return Err(Asn1Error::TagMismatch { expected: want, found: self.tag });
        }
        Ok(())
    }

    /// Desenvuelve un `[n]` explícito: el contenido debe ser exactamente
    /// un TLV hijo, que se devuelve. Núcleo del tagging de Kerberos.
    pub fn unwrap_context(&self) -> Result<Element<'a>> {
        if self.tag.class != Class::Context || !self.tag.constructed {
            return Err(Asn1Error::NotConstructed);
        }
        let mut r = DerReader::new(self.content);
        let child = r.next()?.ok_or(Asn1Error::Truncated { needed: 2, available: 0 })?;
        r.finish()?;
        Ok(child)
    }
}

/// Lector DER de un solo pase sobre un buffer prestado.
pub struct DerReader<'a> {
    rest: &'a [u8],
}

impl<'a> DerReader<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        DerReader { rest: buf }
    }

    pub fn is_empty(&self) -> bool {
        self.rest.is_empty()
    }

    pub fn remaining(&self) -> usize {
        self.rest.len()
    }

    /// Siguiente TLV o `None` si se agotó el buffer.
    pub fn next(&mut self) -> Result<Option<Element<'a>>> {
        if self.rest.is_empty() {
            return Ok(None);
        }
        let (tag, content_len, header_len) = parse_header(self.rest)?;
        let total = header_len + content_len;
        if total > self.rest.len() {
            return Err(Asn1Error::Truncated {
                needed: total,
                available: self.rest.len(),
            });
        }
        let el = Element {
            tag,
            content: &self.rest[header_len..total],
            raw: &self.rest[..total],
        };
        self.rest = &self.rest[total..];
        Ok(Some(el))
    }

    /// Siguiente TLV, verificando el tag exacto.
    pub fn next_tag(&mut self, want: Tag) -> Result<Element<'a>> {
        let el = self
            .next()?
            .ok_or(Asn1Error::Truncated { needed: 2, available: 0 })?;
        el.expect_tag(want)?;
        Ok(el)
    }

    /// Si el próximo elemento es `[n]` contextual, lo consume y lo devuelve;
    /// si no, no consume nada y devuelve `None` (campos opcionales de
    /// RFC 4120, que aparecen en orden estricto).
    pub fn context_child(&mut self, number: u32) -> Result<Option<Element<'a>>> {
        let el = match peek_element(self.rest)? {
            Some(e) => e,
            None => return Ok(None),
        };
        if el.tag == Tag::context(number, true) {
            self.next()?.expect("presente tras peek");
            Ok(Some(el))
        } else if el.tag == Tag::context(number, false) {
            // Algunas implementaciones codifican [n] primitivo (tagging
            // implícito). Charon lo acepta y lo devuelve tal cual: el
            // caller decide cómo interpretarlo (información de matriz).
            self.next()?.expect("presente tras peek");
            Ok(Some(el))
        } else {
            Ok(None)
        }
    }

    /// Igual que `context_child` pero obligatorio.
    pub fn context_child_req(&mut self, number: u32) -> Result<Element<'a>> {
        self.context_child(number)?.ok_or(Asn1Error::TagMismatch {
            expected: Tag::context(number, true),
            found: peek_element(self.rest)?.map(|e| e.tag).unwrap_or(Tag::NULL),
        })
    }

    /// Error si quedan bytes sin consumir.
    pub fn finish(&mut self) -> Result<()> {
        if !self.rest.is_empty() {
            return Err(Asn1Error::TrailingBytes(self.rest.len()));
        }
        Ok(())
    }
}

/// Parsea el header (tag + longitud) sin consumir: (tag, len_contenido, len_header).
fn parse_header(buf: &[u8]) -> Result<(Tag, usize, usize)> {
    let first = *buf.first().ok_or(Asn1Error::Truncated { needed: 1, available: 0 })?;
    let class = Class::from_bits(first)?;
    let constructed = first & 0x20 != 0;
    let mut number = (first & 0x1F) as u32;
    let mut pos = 1;
    if number == 0x1F {
        // Forma larga de número de tag: primer byte debe ser 0x00..0x7E sin
        // bits altos; Kerberos no la usa, pero se decodifica por completitud.
        let mut acc: u32 = 0;
        loop {
            let b = *buf.get(pos).ok_or(Asn1Error::Truncated { needed: pos + 1, available: buf.len() })?;
            pos += 1;
            acc = (acc << 7) | (b & 0x7F) as u32;
            if b & 0x80 == 0 {
                break;
            }
            if pos > 6 {
                return Err(Asn1Error::LongTag(acc));
            }
        }
        number = acc;
    }
    // Longitud
    let lb = *buf.get(pos).ok_or(Asn1Error::Truncated { needed: pos + 1, available: buf.len() })?;
    pos += 1;
    let content_len;
    if lb < 0x80 {
        content_len = lb as usize;
    } else if lb == 0x80 {
        return Err(Asn1Error::IndefiniteLength);
    } else {
        let nbytes = (lb & 0x7F) as usize;
        if nbytes == 0 || nbytes > 8 {
            return Err(Asn1Error::BadLengthForm { nbytes });
        }
        let mut acc: usize = 0;
        for _ in 0..nbytes {
            let b = *buf.get(pos).ok_or(Asn1Error::Truncated { needed: pos + 1, available: buf.len() })?;
            pos += 1;
            acc = acc
                .checked_shl(8)
                .and_then(|a| a.checked_add(b as usize))
                .ok_or(Asn1Error::LengthTooLarge { len: usize::MAX, max: MAX_DER_LEN })?;
        }
        if acc > MAX_DER_LEN {
            return Err(Asn1Error::LengthTooLarge { len: acc, max: MAX_DER_LEN });
        }
        // DER: la forma larga debe ser mínima (el primer byte no puede ser 0).
        if (acc >> ((nbytes - 1) * 8)) == 0 {
            return Err(Asn1Error::BadLengthForm { nbytes });
        }
        content_len = acc;
    }
    Ok((Tag { class, constructed, number }, content_len, pos))
}

/// Pequeño peek: parsea el header del próximo elemento sin consumir.
fn peek_element<'a>(buf: &'a [u8]) -> Result<Option<Element<'a>>> {
    if buf.is_empty() {
        return Ok(None);
    }
    let (tag, content_len, header_len) = parse_header(buf)?;
    let total = header_len + content_len;
    if total > buf.len() {
        return Err(Asn1Error::Truncated { needed: total, available: buf.len() });
    }
    Ok(Some(Element {
        tag,
        content: &buf[header_len..total],
        raw: &buf[..total],
    }))
}
