//! # charon-krb5 — mensajes Kerberos (RFC 4120 / MS-SFU / MS-PAC)
//!
//! Structs tipados con `build()` (→ DER) y `parse()` (← DER) para todo lo
//! que cruza el cable en los intercambios AS, TGS y AP, más el PAC.
//! Construido directamente sobre `charon-asn1`; cada campo de cada
//! builder está comentado con su tag y su RFC.

pub mod ccache;
pub mod error_codes;
pub mod msgs;
pub mod pac;

#[cfg(test)]
mod tests;

pub use error_codes::*;
pub use msgs::*;
pub use pac::Pac;

use charon_asn1::{Asn1Error, Element, KrbTime, Result as Asn1Result, Tag};

/// Errores del crate de mensajes.
#[derive(thiserror::Error, Debug, PartialEq)]
pub enum Krb5Error {
    #[error(transparent)]
    Asn1(#[from] Asn1Error),

    #[error("pvno inesperado: {0} (RFC 4120 exige 5)")]
    BadPvno(i64),

    #[error("msg-type inesperado: {0}")]
    BadMsgType(i64),

    #[error("no se encontró el PA-DATA esperado (tipo {0})")]
    MissingPaData(i32),

    #[error("PAC malformado: {0}")]
    BadPac(String),

    #[error("la respuesta no es de este realm/principal: {0}")]
    BadReply(String),

    #[error("ccache inválido: {0}")]
    BadCcache(String),
}

pub type Result<T> = std::result::Result<T, Krb5Error>;

// ---------- tipos compartidos ----------

/// `PrincipalName` (RFC 4120 §5.2.2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PrincipalName {
    pub name_type: i32,
    pub name_string: Vec<String>,
}

pub mod name_type {
    pub const NT_UNKNOWN: i32 = 0;
    pub const NT_PRINCIPAL: i32 = 1;
    pub const NT_SRV_INST: i32 = 2;
    pub const NT_SRV_HST: i32 = 3;
    pub const NT_SRV_XHST: i32 = 4;
    pub const NT_UID: i32 = 5;
    pub const NT_ENTERPRISE: i32 = 10;
}

impl PrincipalName {
    /// Nombre simple de usuario (`nt-principal`).
    pub fn user(name: &str) -> PrincipalName {
        PrincipalName {
            name_type: name_type::NT_PRINCIPAL,
            name_string: vec![name.to_string()],
        }
    }

    /// SPN `servicio/host` → `nt-srv-inst` con dos componentes.
    /// Si no hay `/`, se trata como componente única.
    pub fn from_spn(spn: &str) -> PrincipalName {
        let mut parts = spn.splitn(2, '/');
        let svc = parts.next().unwrap_or(spn).to_string();
        let rest = parts.next().map(|r| vec![svc.clone(), r.to_string()]);
        PrincipalName {
            name_type: name_type::NT_SRV_INST,
            name_string: rest.unwrap_or_else(|| vec![svc]),
        }
    }

    /// `krbtgt/<realm>`.
    pub fn krbtgt(realm: &str) -> PrincipalName {
        PrincipalName {
            name_type: name_type::NT_SRV_INST,
            name_string: vec!["krbtgt".into(), realm.to_string()],
        }
    }

    /// Representación plana (`MSSQLSvc/srv01.lab.local`).
    pub fn flat(&self) -> String {
        self.name_string.join("/")
    }

    pub fn build(&self) -> Asn1Result<Vec<u8>> {
        let strings: Vec<Vec<u8>> = self
            .name_string
            .iter()
            .map(|s| charon_asn1::encode_string(s))
            .collect();
        let seq = charon_asn1::encode_sequence(&strings)?;
        let name_type = charon_asn1::encode_context_wrapped(0, &charon_asn1::encode_integer(self.name_type as i64))?;
        let name_string = charon_asn1::encode_context_wrapped(1, &seq)?;
        charon_asn1::encode_sequence(&[name_type, name_string])
    }

    pub(crate) fn parse(el: &Element<'_>) -> Asn1Result<PrincipalName> {
        let mut seq = el.parse_seq()?;
        let name_type = seq
            .context_child(0)?
            .ok_or(Asn1Error::TrailingBytes(0))?
            .unwrap_context()?
            .parse_int_i64()? as i32;
        let mut name_string = Vec::new();
        if let Some(ns) = seq.context_child(1)? {
            let inner = ns.unwrap_context()?;
            let mut r = inner.parse_seq()?;
            while let Some(s) = r.next()? {
                name_string.push(s.parse_str()?.to_string());
            }
        }
        seq.finish()?;
        Ok(PrincipalName { name_type, name_string })
    }
}

/// `EncryptionKey` (clave de sesión).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EncryptionKey {
    pub keytype: i32,
    pub keyvalue: Vec<u8>,
}

impl EncryptionKey {
    pub fn build(&self) -> Asn1Result<Vec<u8>> {
        let keytype = charon_asn1::encode_context_wrapped(0, &charon_asn1::encode_integer(self.keytype as i64))?;
        let keyvalue = charon_asn1::encode_context_wrapped(1, &charon_asn1::encode_octets(&self.keyvalue))?;
        charon_asn1::encode_sequence(&[keytype, keyvalue])
    }

    pub(crate) fn parse(el: &Element<'_>) -> Asn1Result<EncryptionKey> {
        let mut seq = el.parse_seq()?;
        let keytype = seq.context_child_req(0)?.unwrap_context()?.parse_int_i64()? as i32;
        let keyvalue = seq
            .context_child(1)?
            .ok_or(Asn1Error::TrailingBytes(0))?
            .unwrap_context()?
            .parse_bytes()?
            .to_vec();
        seq.finish()?;
        Ok(EncryptionKey { keytype, keyvalue })
    }
}

/// `EncryptedData` (RFC 4120 §5.2.9).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EncryptedData {
    pub etype: i32,
    pub kvno: Option<u32>,
    pub cipher: Vec<u8>,
}

impl EncryptedData {
    pub fn build(&self) -> Asn1Result<Vec<u8>> {
        let etype = charon_asn1::encode_context_wrapped(0, &charon_asn1::encode_integer(self.etype as i64))?;
        let kvno = self
            .kvno
            .map(|k| charon_asn1::encode_context_wrapped(1, &charon_asn1::encode_integer(k as i64)))
            .transpose()?;
        let cipher = charon_asn1::encode_context_wrapped(2, &charon_asn1::encode_octets(&self.cipher))?;
        let children: Vec<Vec<u8>> = [Some(etype), kvno, Some(cipher)].into_iter().flatten().collect();
        charon_asn1::encode_sequence(&children)
    }

    pub(crate) fn parse(el: &Element<'_>) -> Asn1Result<EncryptedData> {
        let mut seq = el.parse_seq()?;
        let etype = seq.context_child_req(0)?.unwrap_context()?.parse_int_i64()? as i32;
        let kvno = seq.context_child(1)?.map(|k| k.unwrap_context().and_then(|e| e.parse_int_u32())).transpose()?;
        let cipher = seq
            .context_child(2)?
            .ok_or(Asn1Error::TrailingBytes(0))?
            .unwrap_context()?
            .parse_bytes()?
            .to_vec();
        seq.finish()?;
        Ok(EncryptedData { etype, kvno, cipher })
    }
}

/// `Checksum` (RFC 4120 §5.2.9).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Checksum {
    pub cksumtype: i32,
    pub checksum: Vec<u8>,
}

impl Checksum {
    pub fn build(&self) -> Asn1Result<Vec<u8>> {
        let t = charon_asn1::encode_context_wrapped(0, &charon_asn1::encode_integer(self.cksumtype as i64))?;
        let c = charon_asn1::encode_context_wrapped(1, &charon_asn1::encode_octets(&self.checksum))?;
        charon_asn1::encode_sequence(&[t, c])
    }

    pub(crate) fn parse(el: &Element<'_>) -> Asn1Result<Checksum> {
        let mut seq = el.parse_seq()?;
        let cksumtype = seq.context_child_req(0)?.unwrap_context()?.parse_int_i64()? as i32;
        let checksum = seq
            .context_child(1)?
            .ok_or(Asn1Error::TrailingBytes(0))?
            .unwrap_context()?
            .parse_bytes()?
            .to_vec();
        seq.finish()?;
        Ok(Checksum { cksumtype, checksum })
    }
}

/// `HostAddress` (RFC 4120 §5.2.5).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HostAddress {
    pub addr_type: i32,
    pub address: Vec<u8>,
}

impl HostAddress {
    pub fn build(&self) -> Asn1Result<Vec<u8>> {
        let t = charon_asn1::encode_context_wrapped(0, &charon_asn1::encode_integer(self.addr_type as i64))?;
        let a = charon_asn1::encode_context_wrapped(1, &charon_asn1::encode_octets(&self.address))?;
        charon_asn1::encode_sequence(&[t, a])
    }
}

/// `PA-DATA` (RFC 4120 §5.2.7).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PaData {
    pub pa_type: i32,
    pub pa_value: Vec<u8>,
}

pub mod pa_type {
    pub const PA_TGS_REQ: i32 = 1;
    pub const PA_ENC_TIMESTAMP: i32 = 2;
    pub const PA_ETYPE_INFO2: i32 = 19;
    pub const PA_PAC_REQUEST: i32 = 128;
    pub const PA_FOR_USER: i32 = 129;
}

impl PaData {
    pub fn build(&self) -> Asn1Result<Vec<u8>> {
        let t = charon_asn1::encode_context_wrapped(1, &charon_asn1::encode_integer(self.pa_type as i64))?;
        let v = charon_asn1::encode_context_wrapped(2, &charon_asn1::encode_octets(&self.pa_value))?;
        charon_asn1::encode_sequence(&[t, v])
    }

    pub(crate) fn parse(el: &Element<'_>) -> Asn1Result<PaData> {
        let mut seq = el.parse_seq()?;
        let pa_type = seq.context_child_req(1)?.unwrap_context()?.parse_int_i64()? as i32;
        let pa_value = seq
            .context_child(2)?
            .ok_or(Asn1Error::TrailingBytes(0))?
            .unwrap_context()?
            .parse_bytes()?
            .to_vec();
        seq.finish()?;
        Ok(PaData { pa_type, pa_value })
    }

    /// Codifica un `SEQUENCE OF PA-DATA`.
    pub fn build_seq(items: &[PaData]) -> Asn1Result<Vec<u8>> {
        let children: Vec<Vec<u8>> = items.iter().map(|p| p.build()).collect::<Asn1Result<_>>()?;
        charon_asn1::encode_sequence(&children)
    }

    /// Decodifica un `SEQUENCE OF PA-DATA` (vacío si no hay bytes).
    pub fn parse_seq(el: &Element<'_>) -> Asn1Result<Vec<PaData>> {
        let mut out = Vec::new();
        let mut r = el.parse_seq()?;
        while let Some(p) = r.next()? {
            out.push(PaData::parse(&p)?);
        }
        Ok(out)
    }
}

/// `Ticket` (RFC 4120 §5.3) — `[APPLICATION 1]`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ticket {
    pub tkt_vno: u32,
    pub realm: String,
    pub sname: PrincipalName,
    pub enc_part: EncryptedData,
}

pub const TAG_TICKET: Tag = Tag::application(1, true);

impl Ticket {
    pub fn build(&self) -> Asn1Result<Vec<u8>> {
        let vno = charon_asn1::encode_context_wrapped(0, &charon_asn1::encode_integer(self.tkt_vno as i64))?;
        let realm = charon_asn1::encode_context_wrapped(1, &charon_asn1::encode_string(&self.realm))?;
        let sname = charon_asn1::encode_context_wrapped(2, &self.sname.build()?)?;
        let enc = charon_asn1::encode_context_wrapped(3, &self.enc_part.build()?)?;
        let body = charon_asn1::encode_sequence(&[vno, realm, sname, enc])?;
        charon_asn1::encode_tlv(TAG_TICKET, &body)
    }

    pub fn parse(bytes: &[u8]) -> Asn1Result<Ticket> {
        let mut r = charon_asn1::DerReader::new(bytes);
        let el = r.next_tag(TAG_TICKET)?;
        r.finish()?;
        // `el` es el wrapper [APPLICATION 1]: from_body ya baja él solo a
        // la SEQUENCE interior (antes se bajaba dos veces: bug latente sin
        // llamador hasta el ccache, que lo destapó con su round-trip).
        Self::from_body(&el)
    }

    pub(crate) fn from_body(el: &Element<'_>) -> Asn1Result<Ticket> {
        // `el` es el wrapper [APPLICATION 1] (desde un campo [5]/[3] con
        // tagging explícito) o el elemento directamente: el contenido es
        // la SEQUENCE del ticket en ambos casos.
        let mut outer = el.content_reader();
        let body = outer.next_tag(Tag::SEQUENCE)?;
        let mut seq = body.parse_seq()?;
        let tkt_vno = seq
            .context_child(0)?
            .ok_or(Asn1Error::TrailingBytes(0))?
            .unwrap_context()?
            .parse_int_u32()?;
        let realm = seq
            .context_child(1)?
            .ok_or(Asn1Error::TrailingBytes(0))?
            .unwrap_context()?
            .parse_str()?
            .to_string();
        let sname = PrincipalName::parse(&seq.context_child_req(2)?.unwrap_context()?)?;
        let enc_part = EncryptedData::parse(&seq.context_child_req(3)?.unwrap_context()?)?;
        seq.finish()?;
        Ok(Ticket { tkt_vno, realm, sname, enc_part })
    }
}

// ---------- flags ----------

/// Convierte un número de bit Kerberos (bit 0 = MSB) en su máscara u32.
pub const fn bit(n: u32) -> u32 {
    1u32 << (31 - n)
}

pub mod kdc_options {
    use super::bit;
    pub const FORWARDABLE: u32 = bit(1);
    pub const PROXIABLE: u32 = bit(3);
    pub const RENEWABLE: u32 = bit(8);
    /// RFC 4120 §5.2.2 (nota ASN.1: "15 is reserved for canonicalize").
    pub const CANONICALIZE: u32 = bit(15);
    /// RFC 4120 §5.2.2: renovación de un ticket RENEWABLE existente.
    pub const RENEW: u32 = bit(30);
    /// S4U2Proxy: el cname va en el additional-ticket (MS-SFU §2.2.3).
    /// krb5.h: KDC_OPT_CNAME_IN_ADDL_TKT = 0x00020000 → bit(14). OJO:
    /// 0x00000010 es KDC_OPT_RENEWABLE_OK — la Ronda 2 fijó aquí ese
    /// literal por una transcripción errónea y el test de regresión la
    /// convalidó; el intento real de S4U2Proxy contra MIT lo destapó (el
    /// KDC ignoraba la opción y emitía un TGS plano).
    pub const C_NAME_IN_ADDITIONAL_TICKET: u32 = bit(14);
    /// krb5.h: KDC_OPT_RENEWABLE_OK = 0x00000010 → bit(27).
    pub const RENEWABLE_OK: u32 = bit(27);
}

pub mod ticket_flags {
    use super::bit;
    pub const FORWARDABLE: u32 = bit(1);
    pub const RENEWABLE: u32 = bit(8);
    pub const INITIAL: u32 = bit(9);
    pub const PRE_AUTHENT: u32 = bit(10);
    pub const HW_AUTHENT: u32 = bit(11);
    pub const TRANSITED_POLICY_CHECKED: u32 = bit(12);
    pub const OK_AS_DELEGATE: u32 = bit(13);
}

pub mod ap_options {
    use super::bit;
    pub const MUTUAL_REQUIRED: u32 = bit(2);
}

// ---------- tiempos ----------

pub(crate) fn build_time_field(n: u32, t: &KrbTime) -> Asn1Result<Vec<u8>> {
    charon_asn1::encode_context_wrapped(n, &charon_asn1::encode_time(*t))
}

pub(crate) fn parse_time_child(seq: &mut charon_asn1::DerReader<'_>, n: u32) -> Asn1Result<Option<KrbTime>> {
    seq.context_child(n)?
        .map(|e| e.unwrap_context().and_then(|i| i.parse_time()))
        .transpose()
}
