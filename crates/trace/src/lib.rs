//! # charon-trace — el lente sobre el protocolo
//!
//! Decodifica cada mensaje campo por campo con: nombre ASN.1, valor,
//! explicación en español y referencia al RFC. Dos salidas:
//! árbol de texto (para el terminal) y JSON (para máquinas/dataset).
//!
//! El objetivo es didáctico y forense a la vez: después de leer traces
//! de Charon, una captura de Kerberos en Wireshark se lee con fluidez.

use charon_client::ClientError;
use charon_krb5::error_codes::describe;
use charon_krb5::*;

/// Un nodo del árbol de trace.
#[derive(Clone, Debug, serde::Serialize)]
pub struct TraceNode {
    pub name: String,
    pub value: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rfc: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub raw_hex: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub children: Vec<TraceNode>,
}

impl TraceNode {
    fn leaf(name: &str, value: impl Into<String>, rfc: &str) -> TraceNode {
        TraceNode {
            name: name.into(),
            value: value.into(),
            detail: None,
            rfc: Some(rfc.into()),
            raw_hex: None,
            children: vec![],
        }
    }

    fn with_detail(mut self, detail: impl Into<String>) -> TraceNode {
        self.detail = Some(detail.into());
        self
    }

    fn branch(name: &str, rfc: &str, children: Vec<TraceNode>) -> TraceNode {
        TraceNode {
            name: name.into(),
            value: String::new(),
            detail: None,
            rfc: Some(rfc.into()),
            raw_hex: None,
            children,
        }
    }
}

/// Render en texto con indentación.
pub fn render_text(root: &TraceNode) -> String {
    let mut out = String::new();
    walk(root, 0, &mut out);
    out
}

fn walk(n: &TraceNode, depth: usize, out: &mut String) {
    let pad = "  ".repeat(depth);
    let value = if n.value.is_empty() {
        String::new()
    } else {
        format!(" = {}", n.value)
    };
    out.push_str(&format!("{pad}{}{}\n", n.name, value));
    if let Some(d) = &n.detail {
        out.push_str(&format!("{pad}   · {d}\n"));
    }
    if let Some(r) = &n.rfc {
        out.push_str(&format!("{pad}   ⟶ {r}\n"));
    }
    for c in &n.children {
        walk(c, depth + 1, out);
    }
}

/// Trace de un mensaje genérico: deduce el tipo por el tag raíz.
pub fn trace_message(bytes: &[u8]) -> charon_client::Result<TraceNode> {
    use charon_asn1::DerReader;
    let mut r = DerReader::new(bytes);
    let el = r.next()?.ok_or(charon_asn1::Asn1Error::TrailingBytes(0))?;
    match el.tag.number {
        10 if el.tag.class == charon_asn1::Class::Application => trace_kdc_req(bytes, 10),
        12 if el.tag.class == charon_asn1::Class::Application => trace_kdc_req(bytes, 12),
        11 if el.tag.class == charon_asn1::Class::Application => trace_kdc_rep(bytes, None),
        13 if el.tag.class == charon_asn1::Class::Application => trace_kdc_rep(bytes, None),
        30 if el.tag.class == charon_asn1::Class::Application => trace_krb_error(bytes),
        14 if el.tag.class == charon_asn1::Class::Application => trace_ap_req(bytes),
        _ => Err(ClientError::UnknownReply),
    }
}

/// AS-REQ / TGS-REQ campo a campo.
pub fn trace_kdc_req(bytes: &[u8], msg_type: u32) -> charon_client::Result<TraceNode> {
    let req = KdcReq::parse(bytes)?;
    let kind = if msg_type == 10 { "AS-REQ" } else { "TGS-REQ" };
    let rfc = if msg_type == 10 { "RFC 4120 §5.4.1 (solicita un TGT)" } else { "RFC 4120 §5.4.1 (canjea un TGT por un service ticket)" };
    let mut root = TraceNode::branch(kind, rfc, vec![]);
    root.children.push(TraceNode::leaf("pvno", 5.to_string(), "RFC 4120 §5.4.1 — versión del protocolo").with_detail("siempre 5"));
    root.children.push(TraceNode::leaf("msg-type", req.msg_type.to_string(), "RFC 4120 §6 — 10=AS-REQ, 12=TGS-REQ"));
    if !req.padata.is_empty() {
        let mut pa_node = TraceNode::branch("padata", "RFC 4120 §5.2.7 — datos previos a la autenticación", vec![]);
        for pa in &req.padata {
            let name = match pa.pa_type {
                1 => "PA-TGS-REQ".into(),
                2 => "PA-ENC-TIMESTAMP".into(),
                19 => "PA-ETYPE-INFO2".into(),
                128 => "PA-PAC-REQUEST".into(),
                129 => "PA-FOR-USER".into(),
                t => format!("PA-DATA tipo {t}"),
            };
            let detail = match pa.pa_type {
                2 => Some("timestamp cifrado con la clave del usuario (usage 1): prueba de conocimiento de la contraseña sin enviarla".to_string()),
                1 => Some("AP-REQ con el TGT: el TGT viaja dentro y el KDC no puede leer el authenticator".to_string()),
                128 => Some("booleano de Microsoft: pide (o no) el PAC dentro del ticket".to_string()),
                129 => Some("MS-SFU §2.2.2: S4U2Self — pide un ticket «en nombre de» otro usuario".to_string()),
                _ => None,
            };
            let mut node = TraceNode::leaf(&name, format!("{} bytes", pa.pa_value.len()), "RFC 4120 §5.2.7.2");
            node.detail = detail;
            node.raw_hex = Some(short_hex(&pa.pa_value));
            pa_node.children.push(node);
        }
        root.children.push(pa_node);
    }
    let body = &req.body;
    let mut body_node = TraceNode::branch("req-body", "RFC 4120 §5.4.1", vec![]);
    body_node.children.push(TraceNode::leaf(
        "kdc-options",
        format!("0x{:08x}", body.kdc_options),
        "RFC 4120 §5.4.1 — bit 1=forwardable, 8=renewable, 22=canonicalize",
    ));
    if let Some(c) = &body.cname {
        body_node.children.push(TraceNode::leaf("cname", c.flat(), "RFC 4120 §5.2.2 — quien pide (ausente en TGS-REQ)"));
    }
    body_node.children.push(TraceNode::leaf("realm", body.realm.clone(), "RFC 4120 §5.2.7 — dominio del KDC destino"));
    if let Some(s) = &body.sname {
        let detail = if s.name_string.first().map(|x| x.as_str()) == Some("krbtgt") {
            "krbtgt: pide el TGT (ticket para hablar con el propio KDC)".to_string()
        } else {
            "SPN del servicio destino".to_string()
        };
        body_node.children.push(TraceNode::leaf("sname", s.flat(), "RFC 4120 §5.2.2").with_detail(detail));
    }
    body_node.children.push(TraceNode::leaf("till", body.till.to_wire(), "RFC 4120 §5.4.1 — validez solicitada"));
    body_node.children.push(TraceNode::leaf("nonce", body.nonce.to_string(), "RFC 4120 §5.4.1 — antirreplay: el KDC debe devolverlo"));
    body_node.children.push(TraceNode::leaf(
        "etype",
        format!("{:?}", body.etypes),
        "RFC 4120 §5.2.9 / RFC 3962 — 18=AES256, 17=AES128, 23=RC4. El ORDEN es la negociación: pedir 18 primero evita el downgrade (0x17 en el evento 4769)",
    ));
    root.children.push(body_node);
    Ok(root)
}

/// AS-REP / TGS-REP: se explica el sobre y, si se entrega la clave para
/// descifrar el enc-part, también su interior (clave de sesión, flags...).
pub fn trace_kdc_rep(bytes: &[u8], dec_key: Option<&charon_kcrypto::KerberosKey>) -> charon_client::Result<TraceNode> {
    let rep = KdcRep::parse(bytes)?;
    let kind = if rep.msg_type == 11 { "AS-REP" } else { "TGS-REP" };
    let mut root = TraceNode::branch(
        kind,
        "RFC 4120 §5.4.2 — respuesta del KDC con el ticket pedido",
        vec![],
    );
    root.children.push(TraceNode::leaf("crealm", rep.crealm.clone(), "RFC 4120 §5.4.2"));
    root.children.push(TraceNode::leaf("cname", rep.cname.flat(), "RFC 4120 §5.4.2"));
    let mut tkt = TraceNode::branch("ticket", "RFC 4120 §5.3 — el ticket (solo el KDC y el servicio lo pueden leer)", vec![]);
    tkt.children.push(TraceNode::leaf("realm", rep.ticket.realm.clone(), "dominio del servicio"));
    tkt.children.push(TraceNode::leaf("sname", rep.ticket.sname.flat(), "identidad del servicio"));
    let t = rep.ticket.enc_part.etype;
    let et_desc = match t {
        18 => "AES256-CTS-HMAC-SHA1-96",
        17 => "AES128-CTS-HMAC-SHA1-96",
        23 => "RC4-HMAC (downgrade si la cuenta tiene AES: evento 4769 con 0x17)",
        _ => "etype no estándar",
    };
    tkt.children.push(TraceNode::leaf("enc-part.etype", t.to_string(), "RFC 3962/4757 — etype de la clave del SERVICIO").with_detail(et_desc));
    tkt.children.push(TraceNode::leaf("enc-part.cipher", format!("{} bytes", rep.ticket.enc_part.cipher.len()), "dentro va la clave de sesión y el PAC (firmado por krbtgt)"));
    root.children.push(tkt);

    root.children.push(TraceNode::leaf(
        "enc-part.etype",
        rep.enc_part.etype.to_string(),
        "etype con el que se cifra ESTE enc-part",
    ));
    if let Some(key) = dec_key {
        let usage = if rep.msg_type == 11 {
            charon_kcrypto::usage::AS_REP_ENCPART
        } else {
            charon_kcrypto::usage::TGS_REP_ENCPART_SESSKEY
        };
        match charon_kcrypto::decrypt(key, usage, &rep.enc_part.cipher) {
            Ok(plain) => {
                let part = EncKdcRepPart::parse_element(&plain)?;
                let usage_note = if rep.msg_type == 11 { "usage 3 (clave del cliente)" } else { "usage 8 (clave de sesión del TGT)" };
                let mut inner = TraceNode::branch("enc-part (descifrado)", "RFC 4120 §5.4.2 — EncKDCRepPart", vec![]);
                inner.children.push(TraceNode::leaf(
                    "key (clave de sesión)",
                    format!("etype {} / {} bytes", part.key.keytype, part.key.keyvalue.len()),
                    usage_note,
                ));
                inner.children.push(TraceNode::leaf("nonce", part.nonce.to_string(), "eco del nonce del AS-REQ (antirreplay)"));
                inner.children.push(TraceNode::leaf(
                    "flags",
                    format!("0x{:08x}", part.flags),
                    "bit 9=initial (es un TGT nuevo), 10=pre-authent, 1=forwardable, 13=ok-as-delegate",
                ));
                inner.children.push(TraceNode::leaf("authtime", part.authtime.to_wire(), "cuándo se autenticó el usuario"));
                inner.children.push(TraceNode::leaf("endtime", part.endtime.to_wire(), "caducidad del ticket"));
                if let Some(rt) = part.renew_till {
                    inner.children.push(TraceNode::leaf("renew-till", rt.to_wire(), "hasta cuándo se puede renovar"));
                }
                inner.children.push(TraceNode::leaf("srealm", part.srealm.clone(), "dominio del servicio"));
                inner.children.push(TraceNode::leaf("sname", part.sname.flat(), "servicio"));
                root.children.push(inner);
            }
            Err(e) => {
                let mut failed = TraceNode::leaf("enc-part", "NO DESCIFRADO", "clave/usage incorrectos");
                failed.detail = Some(format!("{e}"));
                root.children.push(failed);
            }
        }
    } else {
        root.children.push(TraceNode::leaf(
            "enc-part",
            format!("{} bytes (sin clave para descifrar: pasa --key o --password)", rep.enc_part.cipher.len()),
            "sin descifrar",
        ));
    }
    Ok(root)
}

/// KRB-ERROR con la lectura ofensiva de cada código.
pub fn trace_krb_error(bytes: &[u8]) -> charon_client::Result<TraceNode> {
    let err = KrbError::parse(bytes)?;
    let d = describe(err.error_code);
    let mut root = TraceNode::branch(
        "KRB-ERROR",
        "RFC 4120 §5.9.1 — el KDC habla: cada código filtra información",
        vec![],
    );
    root.children.push(TraceNode::leaf("error-code", format!("{} ({})", err.error_code, d.name), "").with_detail(d.leak));
    root.children.push(TraceNode::leaf("stime", err.stime.to_wire(), "reloj del KDC (útil para sincronizar)"));
    if let Some(t) = &err.e_text {
        root.children.push(TraceNode::leaf("e-text", t.clone(), "explicación del KDC"));
    }
    if let Some(salt_entries) = err.etype_info2() {
        for s in salt_entries {
            if let Some(salt) = s.salt {
                root.children.push(TraceNode::leaf(
                    "PA-ETYPE-INFO2.salt",
                    String::from_utf8_lossy(&salt).into_owned(),
                    "RFC 4120 §5.2.7.5 — ¡el KDC regala el salt para derivar la clave AES del usuario!",
                )
                .with_detail("string-to-key: PBKDF2(UTF-16LE(password), este salt, 4096)"));
            }
        }
    }
    Ok(root)
}

/// AP-REQ (lo que un cliente presenta a un servicio).
pub fn trace_ap_req(bytes: &[u8]) -> charon_client::Result<TraceNode> {
    let ap = ApReq::parse(bytes)?;
    let mut root = TraceNode::branch("AP-REQ", "RFC 4120 §5.5.1 — presentación del ticket al servicio", vec![]);
    root.children.push(TraceNode::leaf("ticket.sname", ap.ticket.sname.flat(), "servicio destino"));
    root.children.push(TraceNode::leaf("authenticator.etype", ap.authenticator.etype.to_string(), "cifrado con la clave de sesión del ticket (usage 11 o 7 si es PA-TGS-REQ)"));
    root.children.push(TraceNode::leaf("authenticator.cipher", format!("{} bytes", ap.authenticator.cipher.len()), "dentro: cname, ctime, quizá subkey"));
    Ok(root)
}

fn short_hex(b: &[u8]) -> String {
    let take = b.len().min(24);
    let hex: String = b[..take].iter().map(|x| format!("{x:02x}")).collect();
    if b.len() > take {
        format!("{hex}… ({} bytes)", b.len())
    } else {
        hex
    }
}
