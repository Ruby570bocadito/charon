//! PAC (Privileged Attribute Certificate) — MS-PAC.
//!
//! El PAC viaja dentro del enc-part del ticket (usage 2, clave del
//! servicio) como `authorization-data` → AD-IF-RELEVANT → AD-WIN2K-PAC.
//! Estructura raíz (MS-PAC §2.4): cabecera PACTYPE con un array de
//! PAC_INFO_BUFFER {tipo, tamaño, offset} y buffers al final.
//!
//! Charon parsea los tipos relevantes para análisis ofensivo:
//! - 1  LOGON_INFO (KERB_VALIDATION_INFO, NDR): RID, grupos, dominio, UAC.
//! - 3/4 firmas del servidor y del KDC (quién puede forjar qué: la base
//!   teórica de silver/golden tickets).
//! - 5  CLIENT_NAME, 8 UPN_DNS_INFO, 12 S4U_DELEGATION_INFO (conteo).
//!
//! Se incluye un lector NDR mínimo (alineación a 4, strings UTF-16 con
//! punteros únicos diferidos, arrays conformantes) — suficiente para el
//! KERB_VALIDATION_INFO sin traer una librería NDR completa.

use crate::{Krb5Error, Result};

pub mod pac_type {
    pub const LOGON_INFO: u32 = 1;
    pub const SERVER_CHECKSUM: u32 = 3;
    pub const KDC_CHECKSUM: u32 = 4;
    pub const CLIENT_NAME: u32 = 5;
    pub const CLIENT_INFO: u32 = 6;
    pub const UPN_DNS_INFO: u32 = 8;
    pub const S4U_DELEGATION_INFO: u32 = 12;
}

/// Un buffer del PAC, crudo por tipo.
#[derive(Clone, Debug)]
pub struct PacBuffer {
    pub buffer_type: u32,
    pub data: Vec<u8>,
}

/// PAC parseado: cabecera + buffers.
#[derive(Clone, Debug)]
pub struct Pac {
    pub version: u32,
    pub buffers: Vec<PacBuffer>,
}

impl Pac {
    /// Parsea el blob completo del PAC (el valor de AD-WIN2K-PAC).
    pub fn parse(data: &[u8]) -> Result<Pac> {
        if data.len() < 8 {
            return Err(Krb5Error::BadPac("cabecera PACTYPE truncada".into()));
        }
        let rd_u32 = |off: usize| -> Result<u32> {
            data.get(off..off + 4)
                .map(|b| u32::from_le_bytes(b.try_into().unwrap()))
                .ok_or_else(|| Krb5Error::BadPac("PACTYPE truncado".into()))
        };
        let count = rd_u32(0)? as usize;
        let version = rd_u32(4)?;
        let mut buffers = Vec::with_capacity(count);
        for i in 0..count {
            let base = 8 + i * 16;
            let buffer_type = rd_u32(base)?;
            let size = rd_u32(base + 4)? as usize;
            let off64 = data
                .get(base + 8..base + 16)
                .map(|b| u64::from_le_bytes(b.try_into().unwrap()))
                .ok_or_else(|| Krb5Error::BadPac("PAC_INFO_BUFFER truncado".into()))?;
            let off = off64 as usize;
            let payload = data
                .get(off..off + size)
                .ok_or_else(|| Krb5Error::BadPac(format!("buffer tipo {buffer_type} fuera de rango")))?;
            buffers.push(PacBuffer { buffer_type, data: payload.to_vec() });
        }
        Ok(Pac { version, buffers })
    }

    pub fn logon_info(&self) -> Option<LogonInfo> {
        self.buffers
            .iter()
            .find(|b| b.buffer_type == pac_type::LOGON_INFO)
            .and_then(|b| LogonInfo::parse(&b.data).ok())
    }

    pub fn signatures(&self) -> Vec<(u32, PacSignature)> {
        self.buffers
            .iter()
            .filter(|b| b.buffer_type == pac_type::SERVER_CHECKSUM || b.buffer_type == pac_type::KDC_CHECKSUM)
            .filter_map(|b| PacSignature::parse(&b.data).ok().map(|s| (b.buffer_type, s)))
            .collect()
    }

    pub fn client_name(&self) -> Option<(u64, String)> {
        let b = self.buffers.iter().find(|b| b.buffer_type == pac_type::CLIENT_NAME)?;
        if b.data.len() < 12 {
            return None;
        }
        let client_id = u64::from_le_bytes(b.data[0..8].try_into().ok()?);
        let name_len = u32::from_le_bytes(b.data[8..12].try_into().ok()?) as usize;
        let raw = b.data.get(12..12 + name_len)?;
        let name: Vec<u16> = raw.chunks_exact(2).map(|c| u16::from_le_bytes(c.try_into().unwrap())).collect();
        Some((client_id, String::from_utf16_lossy(&name)))
    }
}

/// PAC_SIGNATURE_DATA: tipo (con la convención MS: ¡little-endian del
/// cksumtype con el bit de signo!) y firma.
#[derive(Clone, Debug)]
pub struct PacSignature {
    pub sig_type: i32,
    pub signature: Vec<u8>,
}

impl PacSignature {
    pub fn parse(data: &[u8]) -> Result<PacSignature> {
        if data.len() < 4 {
            return Err(Krb5Error::BadPac("PAC_SIGNATURE_DATA truncada".into()));
        }
        let sig_type = i32::from_le_bytes(data[0..4].try_into().unwrap());
        Ok(PacSignature { sig_type, signature: data[4..].to_vec() })
    }
}

/// Lo interesante del KERB_VALIDATION_INFO (MS-PAC §2.5).
#[derive(Clone, Debug, Default)]
pub struct LogonInfo {
    /// SAM account name (EffectiveName).
    pub account: String,
    /// RID del usuario (UserId).
    pub user_rid: u32,
    /// RID del grupo primario.
    pub primary_group_rid: u32,
    /// (RID, atributos) de los grupos.
    pub groups: Vec<(u32, u32)>,
    /// NetBIOS del dominio (LogonDomainName).
    pub logon_domain: String,
    /// SID del dominio (LogonDomainId).
    pub domain_sid: Option<String>,
    /// UserAccountControl (flags de cuenta).
    pub user_account_control: u32,
}

// ---------- lector NDR mínimo ----------

struct NdrReader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> NdrReader<'a> {
    fn new(data: &'a [u8]) -> Self {
        NdrReader { data, pos: 0 }
    }

    fn align(&mut self, n: usize) {
        let rem = self.pos % n;
        if rem != 0 {
            self.pos += n - rem;
        }
    }

    fn u16le(&mut self) -> Result<u16> {
        self.align(2);
        let b = self
            .data
            .get(self.pos..self.pos + 2)
            .ok_or_else(|| Krb5Error::BadPac("NDR truncado (u16)".into()))?;
        self.pos += 2;
        Ok(u16::from_le_bytes(b.try_into().unwrap()))
    }

    fn u32le(&mut self) -> Result<u32> {
        self.align(4);
        let b = self
            .data
            .get(self.pos..self.pos + 4)
            .ok_or_else(|| Krb5Error::BadPac("NDR truncado (u32)".into()))?;
        self.pos += 4;
        Ok(u32::from_le_bytes(b.try_into().unwrap()))
    }

    /// RPC_UNICODE_STRING: len, maxlen y referent del puntero (los bytes
    /// del string quedan diferidos al final de la estructura).
    fn push_string(&mut self, deferred: &mut Vec<(usize, usize)>) -> Result<()> {
        let len = self.u16le()? as usize;
        let _maxlen = self.u16le()?;
        let _refid = self.u32le()?;
        deferred.push((self.pos, len));
        Ok(())
    }
}

fn sid_from_bytes(bytes: &[u8]) -> Option<String> {
    if bytes.len() < 8 {
        return None;
    }
    let revision = bytes[0];
    let count = bytes[1] as usize;
    if bytes.len() < 8 + count * 4 {
        return None;
    }
    let mut authority: u64 = 0;
    for i in 2..8 {
        authority = (authority << 8) | bytes[i] as u64;
    }
    let mut sid = format!("S{revision}-{authority}");
    for i in 0..count {
        let off = 8 + i * 4;
        let v = u32::from_le_bytes(bytes[off..off + 4].try_into().ok()?);
        sid.push_str(&format!("-{v}"));
    }
    Some(sid)
}

impl LogonInfo {
    /// Parsea el buffer LOGON_INFO (NDR) con los campos de MS-PAC §2.5.
    pub fn parse(data: &[u8]) -> Result<LogonInfo> {
        let mut r = NdrReader::new(data);
        let mut deferred: Vec<(usize, usize)> = Vec::new();

        // 6 FILETIME (8 bytes cada uno): LogonTime..PasswordMustChange.
        for _ in 0..6 {
            r.align(4);
            r.pos += 8;
        }
        // 6 RPC_UNICODE_STRING: EffectiveName, FullName, LogonScript,
        // ProfilePath, HomeDirectory, HomeDirectoryDrive.
        for _ in 0..6 {
            r.push_string(&mut deferred)?;
        }
        let _logon_count = r.u16le()?;
        let _bad_password_count = r.u16le()?;
        let user_rid = r.u32le()?;
        let primary_group_rid = r.u32le()?;
        let group_count = r.u32le()? as usize;
        // Puntero único del array de grupos (diferido).
        let _groups_refid = r.u32le()?;
        let _user_flags = r.u32le()?;
        // UserSessionKey: 16 bytes.
        r.align(4);
        r.pos += 16;
        // LogonServer y LogonDomainName.
        r.push_string(&mut deferred)?;
        r.push_string(&mut deferred)?;
        // PISID LogonDomainId (referent diferido).
        let sid_refid_pos = r.pos;
        let _sid_refid = r.u32le()?;
        // Reserved1[2], UserAccountControl, SubAuthStatus.
        r.pos += 8;
        let user_account_control = r.u32le()?;
        let _sub_auth_status = r.u32le()?;
        // LastSuccessfulILogon/LastFailedILogon (2 FILETIME) + reserved.
        r.pos += 16;

        // ---------- zona diferida ----------
        // Cadenas en orden: los caracteres viven tras la parte fija, cada
        // string alineado a 4 bytes (convención NDR de MS-PAC §2.5).
        let mut cursor = r.pos;
        let mut strings = Vec::with_capacity(deferred.len());
        for &(_, len) in &deferred {
            if cursor % 4 != 0 {
                cursor += 4 - cursor % 4;
            }
            let mut rr = NdrReader { data, pos: cursor };
            let mut chars = Vec::with_capacity(len / 2);
            for _ in 0..len / 2 {
                chars.push(rr.u16le()?);
            }
            strings.push(String::from_utf16_lossy(&chars));
            cursor += len;
        }
        // Array de grupos: contador + elementos {RID, atributos}.
        let mut groups = Vec::new();
        if _groups_refid != 0 {
            cursor = (cursor + 3) & !3;
            let mut rr = NdrReader { data, pos: cursor };
            let n = rr.u32le()? as usize;
            for _ in 0..n.min(group_count.max(n)) {
                let rid = rr.u32le()?;
                let attrs = rr.u32le()?;
                groups.push((rid, attrs));
            }
            cursor = rr.pos;
        }
        // SID del dominio (si el puntero no es NULL).
        let domain_sid = if _sid_refid != 0 {
            cursor = (cursor + 3) & !3;
            let bytes = data.get(cursor.min(data.len())..).unwrap_or(&[]);
            // PISID: revisión, count, autoridad de 6 bytes, count u32.
            let count = bytes.get(1).copied().unwrap_or(0) as usize;
            let end = cursor + 8 + count * 4;
            let sid = sid_from_bytes(data.get(cursor..end.min(data.len())).unwrap_or(&[]));
            r.pos = end;
            sid
        } else {
            None
        };

        Ok(LogonInfo {
            account: strings.first().cloned().unwrap_or_default(),
            user_rid,
            primary_group_rid,
            groups,
            logon_domain: strings.get(7).cloned().unwrap_or_default(),
            domain_sid,
            user_account_control,
        })
    }
}

/// Extrae el PAC del enc-part de un ticket con la clave del servicio
/// (usage 2). Es el flujo S4U2Self y el de los tickets de servicios propios.
pub fn extract_pac(ticket: &crate::Ticket, service_key: &charon_kcrypto::KerberosKey) -> Result<Pac> {
    let plain = charon_kcrypto::decrypt(service_key, charon_kcrypto::usage::KDC_REP_TICKET, &ticket.enc_part.cipher)
        .map_err(|e| Krb5Error::BadPac(format!("no se pudo descifrar el enc-part del ticket: {e}")))?;
    let part = crate::EncTicketPart::parse(&plain)?;
    let ad = part
        .authorization_data
        .ok_or_else(|| Krb5Error::BadPac("el ticket no lleva authorization-data".into()))?;
    for entry in &ad {
        if entry.ad_type == crate::ad_type::AD_IF_RELEVANT {
            // AD-IF-RELEVANT envuelve otra SEQUENCE OF AuthorizationData.
            let mut inner = charon_asn1::DerReader::new(&entry.ad_data);
            if let Ok(Some(el)) = inner.next() {
                if let Ok(mut seq) = el.parse_seq() {
                    while let Ok(Some(sub)) = seq.next() {
                        if let Ok(mut s2) = sub.parse_seq() {
                            if let (Ok(Some(t)), Ok(Some(d))) = (
                                s2.context_child(0),
                                s2.context_child(1).map(|x| x.map(|c| c.unwrap_context())),
                            ) {
                                let t = t.unwrap_context().and_then(|i| i.parse_int_i64()).unwrap_or(-1);
                                if t == crate::ad_type::AD_WIN2K_PAC as i64 {
                                    let blob = d?.parse_bytes()?;
                                    return Pac::parse(blob);
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    Err(Krb5Error::BadPac("no se encontró AD-WIN2K-PAC en la authorization-data".into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Construye un KERB_VALIDATION_INFO sintético conforme a MS-PAC
    /// (cifras conocidas) y comprueba el parseo completo.
    #[test]
    fn logon_info_roundtrip_synthetic() {
        // Escritor NDR mínimo para el test.
        let mut body: Vec<u8> = Vec::new(); // parte fija
        let mut deferred: Vec<u8> = Vec::new();
        let push32 = |v: &mut Vec<u8>, x: u32| v.extend_from_slice(&x.to_le_bytes());

        for _ in 0..6 {
            push32(&mut body, 0x11223344);
            push32(&mut body, 0x55667788);
        }
        let strings = vec!["jsmith", "John Smith", "", "", "", ""];
        let mut push_string = |name: &str, body: &mut Vec<u8>, deferred: &mut Vec<u8>| {
            let chars: Vec<u8> = name.encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
            push32(body, chars.len() as u32 | 0); // len (u16) + maxlen (u16)
            // len y maxlen como u16 separados:
            body.truncate(body.len() - 4);
            body.extend_from_slice(&(chars.len() as u16).to_le_bytes());
            body.extend_from_slice(&(chars.len() as u16).to_le_bytes());
            push32(body, 0x00020000); // referent
            deferred.extend_from_slice(&chars);
            while deferred.len() % 4 != 0 {
                deferred.push(0);
            }
        };
        for s in &strings {
            push_string(s, &mut body, &mut deferred);
        }
        body.extend_from_slice(&3u16.to_le_bytes()); // LogonCount
        body.extend_from_slice(&0u16.to_le_bytes()); // BadPasswordCount
        push32(&mut body, 1104); // UserId (RID jdoe-like)
        push32(&mut body, 513); // PrimaryGroupId (Domain Users)
        push32(&mut body, 2); // GroupCount
        push32(&mut body, 0x00020004); // referent grupos
        push32(&mut body, 0); // UserFlags
        for i in 0..4u32 {
            push32(&mut body, i); // UserSessionKey
        }
        push_string("SRV01", &mut body, &mut deferred); // LogonServer
        push_string("LAB", &mut body, &mut deferred); // LogonDomainName
        push32(&mut body, 0x00020008); // referent SID
        push32(&mut body, 0); // Reserved1[0]
        push32(&mut body, 0); // Reserved1[1]
        push32(&mut body, 0x200); // UserAccountControl (NORMAL_ACCOUNT)
        push32(&mut body, 0); // SubAuthStatus
        for _ in 0..4 {
            push32(&mut body, 0); // 2 FILETIME restantes
        }

        // Diferido: cadenas (ya), grupos y SID.
        deferred.extend_from_slice(&2u32.to_le_bytes());
        deferred.extend_from_slice(&513u32.to_le_bytes());
        deferred.extend_from_slice(&7u32.to_le_bytes());
        deferred.extend_from_slice(&512u32.to_le_bytes());
        deferred.extend_from_slice(&32u32.to_le_bytes());
        let sid: Vec<u8> = {
            let mut v = vec![1u8, 2]; // revisión 1, 2 subauthorities
            v.extend_from_slice(&[0, 0, 0, 0, 0, 5]); // autoridad 5
            v.extend_from_slice(&21u32.to_le_bytes()); // S-1-5-21-...
            v.extend_from_slice(&1_000_000u32.to_le_bytes());
            v
        };
        deferred.extend_from_slice(&sid);

        let mut blob = body;
        blob.extend_from_slice(&deferred);

        // Envolver como PAC completo con LOGON_INFO + firma de servidor.
        let mut pac = Vec::new();
        pac.extend_from_slice(&2u32.to_le_bytes()); // 2 buffers
        pac.extend_from_slice(&0u32.to_le_bytes()); // versión 0
        let logon_off = 8u64 + 16 * 2;
        let logon_len = blob.len() as u32;
        let sig: Vec<u8> = {
            let mut s = 8u32.to_le_bytes().to_vec(); // HMAC-MD5 (tipo 8)
            s.extend_from_slice(&[0xAB; 16]);
            s
        };
        let sig_len = sig.len() as u32;
        // Buffers alineados a 8: el offset de la firma se calcula tras
        // rellenar el buffer LOGON_INFO.
        let mut blob_padded = blob.clone();
        while blob_padded.len() % 8 != 0 {
            blob_padded.push(0);
        }
        let sig_off = logon_off + blob_padded.len() as u64;
        pac.extend_from_slice(&1u32.to_le_bytes());
        pac.extend_from_slice(&logon_len.to_le_bytes());
        pac.extend_from_slice(&logon_off.to_le_bytes());
        pac.extend_from_slice(&3u32.to_le_bytes());
        pac.extend_from_slice(&sig_len.to_le_bytes());
        pac.extend_from_slice(&sig_off.to_le_bytes());
        pac.extend_from_slice(&blob_padded);
        pac.extend_from_slice(&sig);

        let parsed = Pac::parse(&pac).expect("PAC parseable");
        assert_eq!(parsed.version, 0);
        assert_eq!(parsed.buffers.len(), 2);
        let info = parsed.logon_info().expect("LOGON_INFO parseado");
        assert_eq!(info.account, "jsmith");
        assert_eq!(info.user_rid, 1104);
        assert_eq!(info.primary_group_rid, 513);
        assert_eq!(info.groups, vec![(513, 7), (512, 32)]);
        assert_eq!(info.logon_domain, "LAB");
        assert_eq!(info.domain_sid.as_deref(), Some("S1-5-21-1000000"));
        assert_eq!(info.user_account_control, 0x200);
        let sigs = parsed.signatures();
        assert_eq!(sigs.len(), 1);
        assert_eq!(sigs[0].0, 3);
        assert_eq!(sigs[0].1.sig_type, 8);
    }
}
