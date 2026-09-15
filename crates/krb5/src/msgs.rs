//! Mensajes de intercambio: AS-REQ/AS-REP, TGS-REQ/TGS-REP, KRB-ERROR,
//! AP-REQ, Authenticator y EncTicketPart (RFC 4120 §5.4, §5.5, §5.7, §5.8,
//! §5.9). Cada builder/parser cita la sección del RFC en el campo.

use crate::*;
use charon_asn1::{
    encode_context_wrapped, encode_integer, encode_octets, encode_sequence, encode_string, encode_tlv,
    DerReader, Element, Tag,
};

// helpers locales ---------------------------------------------------------

fn ctx_int(n: u32, v: i64) -> Vec<u8> {
    encode_context_wrapped(n, &encode_integer(v)).expect("tag universal")
}

fn ctx_str(n: u32, s: &str) -> Vec<u8> {
    encode_context_wrapped(n, &encode_string(s)).expect("tag universal")
}

fn ctx_octets(n: u32, b: &[u8]) -> Vec<u8> {
    encode_context_wrapped(n, &encode_octets(b)).expect("tag universal")
}

fn ctx_bitstring(n: u32, flags: u32) -> Vec<u8> {
    encode_context_wrapped(n, &charon_asn1::encode_flags(flags)).expect("tag universal")
}

// ---------- KDC-REQ-BODY (RFC 4120 §5.4.1) ----------

/// Cuerpo común de AS-REQ y TGS-REQ.
#[derive(Clone, Debug, PartialEq)]
pub struct KdcReqBody {
    pub kdc_options: u32,
    /// Solo en AS-REQ; en TGS-REQ se omite (el cname va en el TGT).
    pub cname: Option<PrincipalName>,
    pub realm: String,
    /// Destino: omitido en AS-REQ (es krbtgt/realm), SPN en TGS-REQ.
    pub sname: Option<PrincipalName>,
    pub from: Option<KrbTime>,
    pub till: KrbTime,
    pub rtime: Option<KrbTime>,
    pub nonce: u32,
    /// Orden de preferencia de etypes (la palanca OPSEC del proyecto).
    pub etypes: Vec<i32>,
    pub addresses: Option<Vec<HostAddress>>,
    pub enc_authorization_data: Option<EncryptedData>,
    /// S4U2Proxy: ticket del servicio intermediario.
    pub additional_tickets: Option<Vec<Ticket>>,
}

impl KdcReqBody {
    pub fn build(&self) -> Result<Vec<u8>> {
        let kdc_options = ctx_bitstring(0, self.kdc_options);
        let cname = match &self.cname {
            Some(c) => Some(encode_context_wrapped(1, &c.build()?)?),
            None => None,
        };
        let realm = ctx_str(2, &self.realm);
        let sname = match &self.sname {
            Some(s) => Some(encode_context_wrapped(3, &s.build()?)?),
            None => None,
        };
        let from = self.from.map(|t| crate::build_time_field(4, &t)).transpose()?;
        let till = crate::build_time_field(5, &self.till)?;
        let rtime = self.rtime.map(|t| crate::build_time_field(6, &t)).transpose()?;
        let nonce = ctx_int(7, self.nonce as i64);
        let etype_content: Vec<Vec<u8>> = self.etypes.iter().map(|e| encode_integer(*e as i64)).collect();
        let etypes = encode_context_wrapped(8, &encode_sequence(&etype_content)?)?;
        let addresses = match &self.addresses {
            Some(addrs) => {
                let items: Vec<Vec<u8>> = addrs.iter().map(|a| a.build()).collect::<std::result::Result<_, _>>()?;
                Some(encode_context_wrapped(9, &encode_sequence(&items)?)?)
            }
            None => None,
        };
        let enc_ad = match &self.enc_authorization_data {
            Some(e) => Some(encode_context_wrapped(10, &e.build()?)?),
            None => None,
        };
        let tickets = match &self.additional_tickets {
            Some(ts) => {
                let items: Vec<Vec<u8>> = ts.iter().map(|t| t.build()).collect::<std::result::Result<_, _>>()?;
                Some(encode_context_wrapped(11, &encode_sequence(&items)?)?)
            }
            None => None,
        };

        let children: Vec<Vec<u8>> = [
            Some(kdc_options), cname, Some(realm), sname, from, Some(till), rtime, Some(nonce),
            Some(etypes), addresses, enc_ad, tickets,
        ]
        .into_iter()
        .flatten()
        .collect();
        Ok(encode_sequence(&children)?)
    }

    pub fn parse(el: &Element<'_>) -> Result<KdcReqBody> {
        let mut seq = el.parse_seq()?;
        let kdc_options = seq.context_child_req(0)?.unwrap_context()?.parse_flags_u32()?;
        let cname = seq
            .context_child(1)?
            .map(|c| c.unwrap_context().and_then(|i| PrincipalName::parse(&i)))
            .transpose()?;
        let realm = seq.context_child_req(2)?.unwrap_context()?.parse_str()?.to_string();
        let sname = seq
            .context_child(3)?
            .map(|s| s.unwrap_context().and_then(|i| PrincipalName::parse(&i)))
            .transpose()?;
        let from = crate::parse_time_child(&mut seq, 4)?;
        let till = crate::parse_time_child(&mut seq, 5)?.ok_or(charon_asn1::Asn1Error::TrailingBytes(0))?;
        let rtime = crate::parse_time_child(&mut seq, 6)?;
        let nonce = seq.context_child_req(7)?.unwrap_context()?.parse_int_u32()?;
        let mut etypes = Vec::new();
        if let Some(e) = seq.context_child(8)? {
            let inner = e.unwrap_context()?;
            let mut r = inner.parse_seq()?;
            while let Some(t) = r.next()? {
                etypes.push(t.parse_int_i64()? as i32);
            }
        }
        let addresses = seq.context_child(9)?.map(|a| -> std::result::Result<Vec<HostAddress>, charon_asn1::Asn1Error> {
            let inner = a.unwrap_context()?;
            let mut r = inner.parse_seq()?;
            let mut out = Vec::new();
            while let Some(t) = r.next()? {
                let mut s = t.parse_seq()?;
                let addr_type = s.context_child_req(0)?.unwrap_context()?.parse_int_i64()? as i32;
                let address = s.context_child_req(1)?.unwrap_context()?.parse_bytes()?.to_vec();
                out.push(HostAddress { addr_type, address });
            }
            Ok(out)
        }).transpose()?;
        let enc_authorization_data = seq
            .context_child(10)?
            .map(|e| e.unwrap_context().and_then(|i| EncryptedData::parse(&i)))
            .transpose()?;
        let additional_tickets = seq
            .context_child(11)?
            .map(|t| -> std::result::Result<Vec<Ticket>, charon_asn1::Asn1Error> {
                let inner = t.unwrap_context()?;
                let mut r = inner.parse_seq()?;
                let mut out = Vec::new();
                while let Some(t) = r.next()? {
                    out.push(Ticket::from_body(&t)?);
                }
                Ok(out)
            })
            .transpose()?;
        seq.finish()?;
        Ok(KdcReqBody {
            kdc_options,
            cname,
            realm,
            sname,
            from,
            till,
            rtime,
            nonce,
            etypes,
            addresses,
            enc_authorization_data,
            additional_tickets,
        })
    }
}

// ---------- AS-REQ / TGS-REQ (RFC 4120 §5.4.1) ----------

/// KDC-REQ genérico: msg-type 10 (AS) o 12 (TGS).
#[derive(Clone, Debug, PartialEq)]
pub struct KdcReq {
    pub msg_type: u32,
    pub padata: Vec<PaData>,
    pub body: KdcReqBody,
}

pub const TAG_AS_REQ: Tag = Tag::application(10, true);
pub const TAG_TGS_REQ: Tag = Tag::application(12, true);

pub const MSG_AS_REQ: u32 = 10;
pub const MSG_TGS_REQ: u32 = 12;
pub const MSG_AS_REP: u32 = 11;
pub const MSG_TGS_REP: u32 = 13;
pub const MSG_AP_REQ: u32 = 14;
pub const MSG_KRB_ERROR: u32 = 30;

impl KdcReq {
    pub fn build(&self) -> Result<Vec<u8>> {
        let tag = if self.msg_type == MSG_AS_REQ { TAG_AS_REQ } else { TAG_TGS_REQ };
        // ⚠ RFC 4120 §5.4.1: a diferencia de KDC-REP y KRB-ERROR, KDC-REQ
        // empieza en [1] (el RFC lo advierte: "NOTE: first tag is [1], not
        // [0]"). MIT y Windows codifican así en el cable.
        let pvno = ctx_int(1, 5);
        let msg_type = ctx_int(2, self.msg_type as i64);
        let padata = if self.padata.is_empty() {
            None
        } else {
            Some(encode_context_wrapped(3, &PaData::build_seq(&self.padata)?)?)
        };
        let body = encode_context_wrapped(4, &self.body.build()?)?;
        let children: Vec<Vec<u8>> = [Some(pvno), Some(msg_type), padata, Some(body)]
            .into_iter()
            .flatten()
            .collect();
        let content = encode_sequence(&children)?;
        Ok(encode_tlv(tag, &content)?)
    }

    pub fn parse(bytes: &[u8]) -> Result<KdcReq> {
        let mut r = DerReader::new(bytes);
        let el = r.next()?;
        let el = el.ok_or(Krb5Error::BadMsgType(-1))?;
        let msg_type = match el.tag {
            t if t == TAG_AS_REQ => MSG_AS_REQ,
            t if t == TAG_TGS_REQ => MSG_TGS_REQ,
            _ => return Err(Krb5Error::BadMsgType(-1)),
        };
        let mut seq = el.content_reader();
        let body_el = seq.next_tag(Tag::SEQUENCE)?;
        seq.finish()?;
        let mut fields = body_el.parse_seq()?;
        let pvno = fields.context_child_req(1)?.unwrap_context()?.parse_int_u32()?;
        if pvno != 5 {
            return Err(Krb5Error::BadPvno(pvno as i64));
        }
        let mt = fields.context_child_req(2)?.unwrap_context()?.parse_int_u32()?;
        if mt != msg_type {
            return Err(Krb5Error::BadMsgType(mt as i64));
        }
        let mut padata = Vec::new();
        if let Some(p) = fields.context_child(3)? {
            padata = PaData::parse_seq(&p.unwrap_context()?)?;
        }
        let body = KdcReqBody::parse(&fields.context_child_req(4)?.unwrap_context()?)?;
        fields.finish()?;
        Ok(KdcReq { msg_type, padata, body })
    }
}

// ---------- AS-REP / TGS-REP (RFC 4120 §5.4.2) ----------

#[derive(Clone, Debug, PartialEq)]
pub struct KdcRep {
    pub msg_type: u32,
    pub padata: Vec<PaData>,
    pub crealm: String,
    pub cname: PrincipalName,
    pub ticket: Ticket,
    pub enc_part: EncryptedData,
}

pub const TAG_AS_REP: Tag = Tag::application(11, true);
pub const TAG_TGS_REP: Tag = Tag::application(13, true);

impl KdcRep {
    pub fn build(&self) -> Result<Vec<u8>> {
        let tag = if self.msg_type == MSG_AS_REP { TAG_AS_REP } else { TAG_TGS_REP };
        let pvno = ctx_int(0, 5);
        let msg_type = ctx_int(1, self.msg_type as i64);
        let padata = if self.padata.is_empty() {
            None
        } else {
            Some(encode_context_wrapped(2, &PaData::build_seq(&self.padata)?)?)
        };
        let crealm = ctx_str(3, &self.crealm);
        let cname = encode_context_wrapped(4, &self.cname.build()?)?;
        let ticket = encode_context_wrapped(5, &self.ticket.build()?)?;
        let enc_part = encode_context_wrapped(6, &self.enc_part.build()?)?;
        let children: Vec<Vec<u8>> = [
            Some(pvno), Some(msg_type), padata, Some(crealm), Some(cname), Some(ticket), Some(enc_part),
        ]
        .into_iter()
        .flatten()
        .collect();
        let content = encode_sequence(&children)?;
        Ok(encode_tlv(tag, &content)?)
    }

    /// Parsea AS-REP o TGS-REP (deduce el tipo por el tag).
    pub fn parse(bytes: &[u8]) -> Result<KdcRep> {
        let mut r = DerReader::new(bytes);
        let el = r.next()?.ok_or(Krb5Error::BadMsgType(-1))?;
        let msg_type = match el.tag {
            t if t == TAG_AS_REP => MSG_AS_REP,
            t if t == TAG_TGS_REP => MSG_TGS_REP,
            _ => return Err(Krb5Error::BadMsgType(-1)),
        };
        let mut seq = el.content_reader();
        let body = seq.next_tag(Tag::SEQUENCE)?;
        seq.finish()?;
        let mut f = body.parse_seq()?;
        let pvno = f.context_child_req(0)?.unwrap_context()?.parse_int_u32()?;
        if pvno != 5 {
            return Err(Krb5Error::BadPvno(pvno as i64));
        }
        let mt = f.context_child_req(1)?.unwrap_context()?.parse_int_u32()?;
        if mt != msg_type {
            return Err(Krb5Error::BadMsgType(mt as i64));
        }
        let mut padata = Vec::new();
        if let Some(p) = f.context_child(2)? {
            padata = PaData::parse_seq(&p.unwrap_context()?)?;
        }
        let crealm = f.context_child_req(3)?.unwrap_context()?.parse_str()?.to_string();
        let cname = PrincipalName::parse(&f.context_child_req(4)?.unwrap_context()?)?;
        let ticket = Ticket::from_body(&f.context_child_req(5)?.unwrap_context()?)?;
        let enc_part = EncryptedData::parse(&f.context_child_req(6)?.unwrap_context()?)?;
        f.finish()?;
        Ok(KdcRep { msg_type, padata, crealm, cname, ticket, enc_part })
    }
}

/// `EncKDCRepPart` (RFC 4120 §5.4.2): el contenido descifrado del enc-part
/// de AS-REP/TGS-REP. Aquí vive la clave de sesión.
#[derive(Clone, Debug, PartialEq)]
pub struct EncKdcRepPart {
    pub key: EncryptionKey,
    pub nonce: u32,
    pub flags: u32,
    pub authtime: KrbTime,
    pub starttime: Option<KrbTime>,
    pub endtime: KrbTime,
    pub renew_till: Option<KrbTime>,
    pub srealm: String,
    pub sname: PrincipalName,
    /// `encrypted-pa-data [12]` (RFC 4120 §5.4.2; MIT DEFFIELD enc_kdc_rep_12,
    /// asn1_k_encode.c 423-424). MIT 1.21 lo usa para devolver PA-PAC-OPTIONS
    /// cuando la petición lo lleva (kdc_add_pa_pac_options, kdc_util.c): el
    /// parser debe tolerarlo o todo TGS-REP con bit RBCD queda sin parsear.
    pub enc_padata: Vec<PaData>,
}

impl EncKdcRepPart {
    pub fn build(&self) -> Result<Vec<u8>> {
        let key = encode_context_wrapped(0, &self.key.build()?)?;
        // last-req [1]: SEQUENCE OF (vacío pero presente, como MIT).
        let last_req = encode_context_wrapped(1, &encode_sequence(&[])?)?;
        let nonce = ctx_int(2, self.nonce as i64);
        let flags = ctx_bitstring(4, self.flags);
        let authtime = crate::build_time_field(5, &self.authtime)?;
        let starttime = self.starttime.map(|t| crate::build_time_field(6, &t)).transpose()?;
        let endtime = crate::build_time_field(7, &self.endtime)?;
        let renew_till = self.renew_till.map(|t| crate::build_time_field(8, &t)).transpose()?;
        let srealm = ctx_str(9, &self.srealm);
        let sname = encode_context_wrapped(10, &self.sname.build()?)?;
        let enc_padata = if self.enc_padata.is_empty() {
            None
        } else {
            Some(encode_context_wrapped(12, &PaData::build_seq(&self.enc_padata)?)?)
        };
        let children: Vec<Vec<u8>> = [
            Some(key), Some(last_req), Some(nonce), None::<Vec<u8>>, Some(flags), Some(authtime),
            starttime, Some(endtime), renew_till, Some(srealm), Some(sname), None::<Vec<u8>>,
            enc_padata,
        ]
        .into_iter()
        .flatten()
        .collect();
        Ok(encode_sequence(&children)?)
    }

    /// Parse desde bytes crudos descifrados (el contenido del enc-part).
    ///
    /// RFC 4120 §5.4.2: el interior de un AS-REP llega envuelto como
    /// `EncASRepPart ::= [APPLICATION 25] EncKDCRepPart` y el de un
    /// TGS-REP como `EncTGSRepPart ::= [APPLICATION 26] EncKDCRepPart`.
    /// Algunas implementaciones envían la SEQUENCE desnuda: se aceptan
    /// las tres formas.
    pub fn parse_element(bytes: &[u8]) -> Result<EncKdcRepPart> {
        let mut r = charon_asn1::DerReader::new(bytes);
        let el = r.next()?.ok_or(charon_asn1::Asn1Error::TrailingBytes(0))?;
        r.finish()?;
        let wrapped = el.tag.class == charon_asn1::Class::Application;
        if wrapped {
            let mut outer = el.content_reader();
            let body = outer.next_tag(charon_asn1::Tag::SEQUENCE)?;
            outer.finish()?;
            EncKdcRepPart::parse(&body)
        } else {
            EncKdcRepPart::parse(&el)
        }
    }

    pub fn parse(el: &Element<'_>) -> Result<EncKdcRepPart> {
        let mut f = el.parse_seq()?;
        let key = EncryptionKey::parse(&f.context_child_req(0)?.unwrap_context()?)?;
        let mut nonce = 0u32;
        // last-req [1] presente pero no estructuralmente necesario.
        let _ = f.context_child(1)?;
        if let Some(n) = f.context_child(2)? {
            nonce = n.unwrap_context()?.parse_int_u32()?;
        }
        let flags = f.context_child(4)?.map(|x| x.unwrap_context().and_then(|i| i.parse_flags_u32())).transpose()?.unwrap_or(0);
        let authtime = crate::parse_time_child(&mut f, 5)?.ok_or(charon_asn1::Asn1Error::TrailingBytes(0))?;
        let starttime = crate::parse_time_child(&mut f, 6)?;
        let endtime = crate::parse_time_child(&mut f, 7)?.ok_or(charon_asn1::Asn1Error::TrailingBytes(0))?;
        let renew_till = crate::parse_time_child(&mut f, 8)?;
        let srealm = f.context_child(9)?.map(|x| x.unwrap_context().and_then(|i| i.parse_str().map(|s| s.to_string()))).transpose()?.unwrap_or_default();
        let sname_opt = f
            .context_child(10)?
            .map(|x| x.unwrap_context().and_then(|i| PrincipalName::parse(&i)))
            .transpose()?;
        let sname = sname_opt.unwrap_or_else(|| PrincipalName::user("<desconocido>"));
        // encrypted-pa-data [12]: opcional; con RBCD MIT devuelve aquí el
        // PA-PAC-OPTIONS eco de la petición.
        let enc_padata = f
            .context_child(12)?
            .map(|x| x.unwrap_context().and_then(|i| PaData::parse_seq(&i)))
            .transpose()?
            .unwrap_or_default();
        f.finish()?;
        Ok(EncKdcRepPart { key, nonce, flags, authtime, starttime, endtime, renew_till, srealm, sname, enc_padata })
    }
}

// ---------- KRB-ERROR (RFC 4120 §5.9.1) ----------

/// `[APPLICATION 30]` con numeración NO consecutiva (¡ojo!: crealm es [7]).
#[derive(Clone, Debug, PartialEq)]
pub struct KrbError {
    pub ctime: Option<KrbTime>,
    pub cusec: Option<u32>,
    pub stime: KrbTime,
    pub susec: u32,
    pub error_code: i32,
    pub crealm: Option<String>,
    pub cname: Option<PrincipalName>,
    pub realm: Option<String>,
    pub sname: Option<PrincipalName>,
    pub e_text: Option<String>,
    pub e_data: Option<Vec<u8>>,
}

pub const TAG_KRB_ERROR: Tag = Tag::application(30, true);

impl KrbError {
    pub fn build(&self) -> Result<Vec<u8>> {
        let pvno = ctx_int(0, 5);
        let msg_type = ctx_int(1, MSG_KRB_ERROR as i64);
        let ctime = self.ctime.map(|t| crate::build_time_field(2, &t)).transpose()?;
        let cusec = self.cusec.map(|u| ctx_int(3, u as i64));
        let stime = crate::build_time_field(4, &self.stime)?;
        let susec = ctx_int(5, self.susec as i64);
        let error_code = ctx_int(6, self.error_code as i64);
        let crealm = self.crealm.as_ref().map(|r| ctx_str(7, r));
        let cname = match &self.cname {
            Some(c) => Some(encode_context_wrapped(8, &c.build()?)?),
            None => None,
        };
        let realm = self.realm.as_ref().map(|r| ctx_str(9, r));
        let sname = match &self.sname {
            Some(s) => Some(encode_context_wrapped(10, &s.build()?)?),
            None => None,
        };
        let e_text = self.e_text.as_ref().map(|t| ctx_str(11, t));
        let e_data = self.e_data.as_ref().map(|d| ctx_octets(12, d));
        let children: Vec<Vec<u8>> = [
            Some(pvno), Some(msg_type), ctime, cusec, Some(stime), Some(susec), Some(error_code),
            crealm, cname, realm, sname, e_text, e_data,
        ]
        .into_iter()
        .flatten()
        .collect();
        let content = encode_sequence(&children)?;
        Ok(encode_tlv(TAG_KRB_ERROR, &content)?)
    }

    pub fn parse(bytes: &[u8]) -> Result<KrbError> {
        let mut r = DerReader::new(bytes);
        let el = r.next_tag(TAG_KRB_ERROR)?;
        r.finish()?;
        let mut seq = el.content_reader();
        let body = seq.next_tag(Tag::SEQUENCE)?;
        seq.finish()?;
        let mut f = body.parse_seq()?;
        let _pvno = f.context_child_req(0)?.unwrap_context()?.parse_int_u32()?;
        let mt = f.context_child_req(1)?.unwrap_context()?.parse_int_u32()?;
        if mt != MSG_KRB_ERROR {
            return Err(Krb5Error::BadMsgType(mt as i64));
        }
        let ctime = crate::parse_time_child(&mut f, 2)?;
        let cusec = f.context_child(3)?.map(|x| x.unwrap_context().and_then(|i| i.parse_int_u32())).transpose()?;
        let stime = crate::parse_time_child(&mut f, 4)?.ok_or(charon_asn1::Asn1Error::TrailingBytes(0))?;
        let susec = f.context_child_req(5)?.unwrap_context()?.parse_int_u32()?;
        let error_code = f.context_child_req(6)?.unwrap_context()?.parse_int_i64()? as i32;
        let crealm = f.context_child(7)?.map(|x| x.unwrap_context().and_then(|i| i.parse_str().map(|s| s.to_string()))).transpose()?;
        let cname = f.context_child(8)?.map(|x| x.unwrap_context().and_then(|i| PrincipalName::parse(&i))).transpose()?;
        let realm = f.context_child(9)?.map(|x| x.unwrap_context().and_then(|i| i.parse_str().map(|s| s.to_string()))).transpose()?;
        let sname = f.context_child(10)?.map(|x| x.unwrap_context().and_then(|i| PrincipalName::parse(&i))).transpose()?;
        let e_text = f.context_child(11)?.map(|x| x.unwrap_context().and_then(|i| i.parse_str().map(|s| s.to_string()))).transpose()?;
        let e_data = f.context_child(12)?.map(|x| x.unwrap_context().and_then(|i| i.parse_bytes().map(|b| b.to_vec()))).transpose()?;
        f.finish()?;
        Ok(KrbError { ctime, cusec, stime, susec, error_code, crealm, cname, realm, sname, e_text, e_data })
    }

    /// El e-data de un error 25 trae METHOD-DATA (SEQUENCE OF PA-DATA) con
    /// PA-ETYPE-INFO2, que regala el salt del usuario. Oráculo del proyecto.
    pub fn etype_info2(&self) -> Option<Vec<EtypeInfo2Entry>> {
        let data = self.e_data.as_ref()?;
        let mut r = DerReader::new(data);
        let method_data = r.next().ok()??;
        let mut entries = Vec::new();
        if let Ok(mut seq) = method_data.parse_seq() {
            while let Ok(Some(pa)) = seq.next() {
                // Cada hijo es un PA-DATA: {tipo [1], valor [2]}.
                let mut fields = match pa.parse_seq() {
                    Ok(f) => f,
                    Err(_) => continue,
                };
                let pa_type = match fields.context_child(1).map(|o| o.map(|t| t.unwrap_context().and_then(|i| i.parse_int_i64()))) {
                    Ok(Some(Ok(t))) => t as i32,
                    _ => continue,
                };
                if pa_type != crate::pa_type::PA_ETYPE_INFO2 {
                    continue;
                }
                // El padata-value es un OCTET STRING ([2]) cuyo contenido es
                // la DER de la entrada ETYPE-INFO2: desenvolver dos niveles.
                let value_bytes = match fields.context_child(2).map(|o| o.map(|v| v.unwrap_context().and_then(|i| i.parse_bytes().map(|b| b.to_vec())))) {
                    Ok(Some(Ok(b))) => b,
                    _ => continue,
                };
                // El valor es la DER de ETYPE-INFO2 ::= SEQUENCE OF
                // ETYPE-INFO2-ENTRY (RFC 4120 §5.2.7.5): iterar entradas.
                let mut vr = DerReader::new(&value_bytes);
                if let Ok(Some(info2)) = vr.next() {
                    if let Ok(mut entries_seq) = info2.parse_seq() {
                        while let Ok(Some(entry_el)) = entries_seq.next() {
                            if let Ok(e) = EtypeInfo2Entry::parse(&entry_el) {
                                entries.push(e);
                            }
                        }
                    }
                }
            }
        }
        Some(entries)
    }
}

/// Entrada de PA-ETYPE-INFO2 (RFC 4120 §5.2.7.5): etype + salt + s2kparams.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EtypeInfo2Entry {
    pub etype: i32,
    pub salt: Option<Vec<u8>>,
    pub s2kparams: Option<Vec<u8>>,
}

impl EtypeInfo2Entry {
    pub fn build(&self) -> Result<Vec<u8>> {
        let etype = ctx_int(0, self.etype as i64);
        let salt = self.salt.as_ref().map(|s| ctx_octets(1, s));
        let s2k = self.s2kparams.as_ref().map(|s| ctx_octets(2, s));
        let children: Vec<Vec<u8>> = [Some(etype), salt, s2k].into_iter().flatten().collect();
        Ok(encode_sequence(&children)?)
    }

    pub fn parse(el: &Element<'_>) -> Result<EtypeInfo2Entry> {
        let mut f = el.parse_seq()?;
        let etype = f.context_child_req(0)?.unwrap_context()?.parse_int_i64()? as i32;
        let salt = f.context_child(1)?.map(|x| x.unwrap_context().and_then(|i| i.parse_str_lenient().map(|s2| s2.as_bytes().to_vec()))).transpose()?;
        let s2kparams = f.context_child(2)?.map(|x| x.unwrap_context().and_then(|i| i.parse_bytes().map(|b| b.to_vec()))).transpose()?;
        f.finish()?;
        Ok(EtypeInfo2Entry { etype, salt, s2kparams })
    }
}

// ---------- AP-REQ / Authenticator (RFC 4120 §5.5.1) ----------

#[derive(Clone, Debug, PartialEq)]
pub struct ApReq {
    pub ap_options: u32,
    pub ticket: Ticket,
    pub authenticator: EncryptedData,
}

pub const TAG_AP_REQ: Tag = Tag::application(14, true);

impl ApReq {
    pub fn build(&self) -> Result<Vec<u8>> {
        let pvno = ctx_int(0, 5);
        let msg_type = ctx_int(1, MSG_AP_REQ as i64);
        let ap_options = ctx_bitstring(2, self.ap_options);
        let ticket = encode_context_wrapped(3, &self.ticket.build()?)?;
        let authenticator = encode_context_wrapped(4, &self.authenticator.build()?)?;
        let content = encode_sequence(&[pvno, msg_type, ap_options, ticket, authenticator])?;
        Ok(encode_tlv(TAG_AP_REQ, &content)?)
    }

    pub fn parse(bytes: &[u8]) -> Result<ApReq> {
        let mut r = DerReader::new(bytes);
        let el = r.next_tag(TAG_AP_REQ)?;
        r.finish()?;
        let mut seq = el.content_reader();
        let body = seq.next_tag(Tag::SEQUENCE)?;
        seq.finish()?;
        let mut f = body.parse_seq()?;
        let _pvno = f.context_child_req(0)?.unwrap_context()?.parse_int_u32()?;
        let mt = f.context_child_req(1)?.unwrap_context()?.parse_int_u32()?;
        if mt != MSG_AP_REQ {
            return Err(Krb5Error::BadMsgType(mt as i64));
        }
        let ap_options = f.context_child(2)?.map(|x| x.unwrap_context().and_then(|i| i.parse_flags_u32())).transpose()?.unwrap_or(0);
        let ticket = Ticket::from_body(&f.context_child_req(3)?.unwrap_context()?)?;
        let authenticator = EncryptedData::parse(&f.context_child_req(4)?.unwrap_context()?)?;
        f.finish()?;
        Ok(ApReq { ap_options, ticket, authenticator })
    }
}

/// `Authenticator` (RFC 4120 §5.5.1) — `[APPLICATION 2]`.
#[derive(Clone, Debug, PartialEq)]
pub struct Authenticator {
    pub crealm: String,
    pub cname: PrincipalName,
    pub cksum: Option<Checksum>,
    pub cusec: u32,
    pub ctime: KrbTime,
    pub subkey: Option<EncryptionKey>,
    pub seq_number: Option<u32>,
}

pub const TAG_AUTHENTICATOR: Tag = Tag::application(2, true);

impl Authenticator {
    pub fn build(&self) -> Result<Vec<u8>> {
        let vno = ctx_int(0, 5);
        let crealm = ctx_str(1, &self.crealm);
        let cname = encode_context_wrapped(2, &self.cname.build()?)?;
        let cksum = match &self.cksum {
            Some(c) => Some(encode_context_wrapped(3, &c.build()?)?),
            None => None,
        };
        let cusec = ctx_int(4, self.cusec as i64);
        let ctime = crate::build_time_field(5, &self.ctime)?;
        let subkey = match &self.subkey {
            Some(s) => Some(encode_context_wrapped(6, &s.build()?)?),
            None => None,
        };
        let seq_number = self.seq_number.map(|s| ctx_int(7, s as i64));
        let children: Vec<Vec<u8>> = [
            Some(vno), Some(crealm), Some(cname), cksum, Some(cusec), Some(ctime), subkey, seq_number,
        ]
        .into_iter()
        .flatten()
        .collect();
        let content = encode_sequence(&children)?;
        Ok(encode_tlv(TAG_AUTHENTICATOR, &content)?)
    }

    pub fn parse(bytes: &[u8]) -> Result<Authenticator> {
        let mut r = DerReader::new(bytes);
        let el = r.next_tag(TAG_AUTHENTICATOR)?;
        r.finish()?;
        let mut seq = el.content_reader();
        let body = seq.next_tag(Tag::SEQUENCE)?;
        seq.finish()?;
        let mut f = body.parse_seq()?;
        let vno = f.context_child_req(0)?.unwrap_context()?.parse_int_u32()?;
        if vno != 5 {
            return Err(Krb5Error::BadPvno(vno as i64));
        }
        let crealm = f.context_child_req(1)?.unwrap_context()?.parse_str()?.to_string();
        let cname = PrincipalName::parse(&f.context_child_req(2)?.unwrap_context()?)?;
        let cksum = f.context_child(3)?.map(|x| x.unwrap_context().and_then(|i| Checksum::parse(&i))).transpose()?;
        let cusec = f.context_child_req(4)?.unwrap_context()?.parse_int_u32()?;
        let ctime = crate::parse_time_child(&mut f, 5)?.ok_or(charon_asn1::Asn1Error::TrailingBytes(0))?;
        let subkey = f.context_child(6)?.map(|x| x.unwrap_context().and_then(|i| EncryptionKey::parse(&i))).transpose()?;
        let seq_number = f.context_child(7)?.map(|x| x.unwrap_context().and_then(|i| i.parse_int_u32())).transpose()?;
        f.finish()?;
        Ok(Authenticator { crealm, cname, cksum, cusec, ctime, subkey, seq_number })
    }
}

/// `EncTicketPart` (RFC 4120 §5.3): el interior descifrado de un ticket.
/// Aquí vive el PAC (authorization-data).
#[derive(Clone, Debug, PartialEq)]
pub struct EncTicketPart {
    pub flags: u32,
    pub key: EncryptionKey,
    pub crealm: String,
    pub cname: PrincipalName,
    pub authtime: KrbTime,
    pub endtime: KrbTime,
    pub authorization_data: Option<Vec<AuthorizationDataEntry>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthorizationDataEntry {
    pub ad_type: i32,
    pub ad_data: Vec<u8>,
}

pub mod ad_type {
    pub const AD_IF_RELEVANT: i32 = 1;
    pub const AD_WIN2K_PAC: i32 = 128;
}

impl EncTicketPart {
    pub fn parse(bytes: &[u8]) -> Result<EncTicketPart> {
        let mut r = DerReader::new(bytes);
        let el = r.next()?.ok_or(charon_asn1::Asn1Error::TrailingBytes(0))?;
        r.finish()?;
        // RFC 4120 §5.3: el enc-part del ticket codifica
        // EncTicketPart ::= [APPLICATION 3]; MIT lo envía envuelto.
        // Se acepta también la SEQUENCE desnuda.
        let mut outer = el.content_reader();
        let body = outer.next_tag(charon_asn1::Tag::SEQUENCE)?;
        outer.finish()?;
        let mut f = body.parse_seq()?;
        let flags = f.context_child_req(0)?.unwrap_context()?.parse_flags_u32()?;
        let key = EncryptionKey::parse(&f.context_child_req(1)?.unwrap_context()?)?;
        let crealm = f.context_child_req(2)?.unwrap_context()?.parse_str()?.to_string();
        let cname = PrincipalName::parse(&f.context_child_req(3)?.unwrap_context()?)?;
        let _transited = f.context_child(4)?;
        let authtime = crate::parse_time_child(&mut f, 5)?.ok_or(charon_asn1::Asn1Error::TrailingBytes(0))?;
        let _starttime = crate::parse_time_child(&mut f, 6)?;
        let endtime = crate::parse_time_child(&mut f, 7)?.ok_or(charon_asn1::Asn1Error::TrailingBytes(0))?;
        let _renew_till = crate::parse_time_child(&mut f, 8)?;
        let _caddr = f.context_child(9)?;
        let authorization_data = f.context_child(10)?.map(|x| -> std::result::Result<Vec<AuthorizationDataEntry>, charon_asn1::Asn1Error> {
            let inner = x.unwrap_context()?;
            let mut r = inner.parse_seq()?;
            let mut out = Vec::new();
            while let Some(e) = r.next()? {
                let mut s = e.parse_seq()?;
                let ad_type = s.context_child_req(0)?.unwrap_context()?.parse_int_i64()? as i32;
                let ad_data = s.context_child(1)?.map(|d| d.unwrap_context().and_then(|i| i.parse_bytes().map(|b| b.to_vec()))).transpose()?.unwrap_or_default();
                out.push(AuthorizationDataEntry { ad_type, ad_data });
            }
            Ok(out)
        }).transpose()?;
        f.finish()?;
        Ok(EncTicketPart { flags, key, crealm, cname, authtime, endtime, authorization_data })
    }
}
