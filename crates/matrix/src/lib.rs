//! # charon-matrix — matriz de comportamiento entre implementaciones de KDC
//!
//! La contribución de investigación del proyecto (M4): la misma batería
//! de mensajes —válidos, casi válidos y deliberadamente torcidos— se
//! lanza contra cada KDC disponible (MIT krb5 en este entorno; Windows
//! y Samba cuando haya laboratorio) y se mide la respuesta.
//!
//! Deliverable: dataset JSON reproducible. Cualquier comportamiento
//! anómalo exploitable → disclosure responsable; este runner está
//! diseñado para que el experimento sea público y repetible.

use charon_asn1::KrbTime;
use charon_client::{ClientError, KdcConnection};
use charon_kcrypto::KerberosKey;
use charon_krb5::*;

/// Fila del dataset.
#[derive(Clone, Debug, serde::Serialize)]
pub struct MatrixRow {
    pub id: String,
    pub name: String,
    pub description: String,
    /// Qué dice el RFC o qué se esperaba razonablemente.
    pub expected: String,
    /// "OK" o el código de error observado.
    pub observed_code: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub observed_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub e_text: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
    pub transport: String,
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct MatrixDataset {
    pub generated_at: String,
    pub kdc_profile: String,
    pub host: String,
    pub port: u16,
    pub realm: String,
    pub rows: Vec<MatrixRow>,
}

/// Contexto de credenciales para las sondas que necesitan autenticarse.
pub struct ProbeCtx {
    pub conn: KdcConnection,
    pub realm: String,
    /// Usuario válido con contraseña conocida.
    pub user: String,
    pub user_key: KerberosKey,
    /// Cuenta AES-only (sin RC4).
    pub aes_only_user: String,
    /// Cuenta con DONT_REQUIRE_PREAUTH.
    pub no_preauth_user: String,
    /// SPN de servicio con clave AES.
    pub spn_with_aes: String,
    /// SPN de servicio RC4-only.
    pub spn_rc4_only: String,
    /// Usuario inexistente.
    pub ghost_user: String,
}

fn err_row(id: &str, name: &str, desc: &str, expected: &str, e: &ClientError, transport: &str) -> MatrixRow {
    MatrixRow {
        id: id.into(),
        name: name.into(),
        description: desc.into(),
        expected: expected.into(),
        observed_code: "EXCEPTION".into(),
        observed_name: None,
        e_text: Some(format!("{e}")),
        notes: None,
        transport: transport.into(),
    }
}

fn code_row(id: &str, name: &str, desc: &str, expected: &str, reply: &[u8], transport: String, notes: Option<String>) -> MatrixRow {
    match KrbError::parse(reply) {
        Ok(e) => {
            let d = error_codes::describe(e.error_code);
            MatrixRow {
                id: id.into(),
                name: name.into(),
                description: desc.into(),
                expected: expected.into(),
                observed_code: e.error_code.to_string(),
                observed_name: Some(d.name.to_string()),
                e_text: e.e_text.clone(),
                notes,
                transport,
            }
        }
        Err(_) => MatrixRow {
            id: id.into(),
            name: name.into(),
            description: desc.into(),
            expected: expected.into(),
            observed_code: if KdcRep::parse(reply).is_ok() { "AS-REP/TGS-REP".into() } else { "UNKNOWN-MESSAGE".into() },
            observed_name: None,
            e_text: None,
            notes,
            transport,
        },
    }
}

/// Ejecuta la batería completa. Nunca corta por fallos: cada sonda
/// produce una fila (los errores de red son datos, no abortos).
pub fn run_battery(ctx: &ProbeCtx, profile: &str) -> MatrixDataset {
    let mut rows = Vec::new();

    // ---------- AS ----------
    // 1. Usuario inexistente sin preauth.
    {
        let req = charon_client::build_as_req(&ctx.ghost_user, &ctx.realm, None, &[18, 17, 23], true, 0);
        let (reply, tr) = match req {
            Ok(r) => ctx.conn.exchange(&r.build().unwrap_or_default()).unwrap_or_else(|e| {
                (format!("{e}").into_bytes(), charon_client::Transport::Udp)
            }),
            Err(_) => (vec![], charon_client::Transport::Udp),
        };
        rows.push(code_row("AS-001", "AS-REQ sin preauth a usuario inexistente", 
            "cname=<inexistente>, sin PA-DATA", "KDC_ERR_PRINCIPAL_UNKNOWN (6)", &reply, tr_str(tr), None));
    }

    // 2. Usuario existente sin preauth → 25 + salt.
    {
        let req = charon_client::build_as_req(&ctx.user, &ctx.realm, None, &[18, 17], true, 0);
        let mut notes = None;
        if let Ok(r) = req {
            if let Ok((reply, tr)) = ctx.conn.exchange(&r.build().unwrap_or_default()) {
                if let Ok(err) = KrbError::parse(&reply) {
                    if let Some(entries) = err.etype_info2() {
                        let salts: Vec<String> = entries
                            .iter()
                            .filter_map(|e| e.salt.as_ref().map(|s| format!("etype {}: {}", e.etype, String::from_utf8_lossy(s))))
                            .collect();
                        notes = Some(format!("salts filtrados: [{}]", salts.join(", ")));
                    }
                }
                rows.push(code_row("AS-002", "AS-REQ sin preauth a usuario existente",
                    "cname=<existente>, sin PA-DATA", "KDC_ERR_PREAUTH_REQUIRED (25) + PA-ETYPE-INFO2 con salt", &reply, tr_str(tr), notes));
            }
        }
    }

    // 3. Preauth con contraseña incorrecta (clave AES del salt correcto).
    {
        let bad = KerberosKey::from_password("Contrasena-Equivocada-XYZ", &format!("{}{}", ctx.realm, ctx.user), 18).unwrap();
        let req = charon_client::build_as_req(&ctx.user, &ctx.realm, Some(&bad), &[18], true, 0);
        if let Ok(r) = req {
            if let Ok((reply, tr)) = ctx.conn.exchange(&r.build().unwrap_or_default()) {
                rows.push(code_row("AS-003", "AS-REQ con contraseña incorrecta",
                    "PA-ENC-TIMESTAMP válido en forma, contenido erróneo", "KDC_ERR_PREAUTH_FAILED (24)", &reply, tr_str(tr), None));
            }
        }
    }

    // 4. etype imposible.
    {
        let req = charon_client::build_as_req(&ctx.user, &ctx.realm, None, &[9999], true, 0);
        if let Ok(r) = req {
            if let Ok((reply, tr)) = ctx.conn.exchange(&r.build().unwrap_or_default()) {
                rows.push(code_row("AS-004", "AS-REQ pidiendo etype 9999",
                    "lista de etypes con un valor inexistente", "KDC_ERR_ETYPE_NOTSUPP (14) o 25", &reply, tr_str(tr), None));
            }
        }
    }

    // 5. Cuenta sin preauth → AS-REP directo.
    {
        let req = charon_client::build_as_req(&ctx.no_preauth_user, &ctx.realm, None, &[18, 17, 23], true, 0);
        if let Ok(r) = req {
            if let Ok((reply, tr)) = ctx.conn.exchange(&r.build().unwrap_or_default()) {
                rows.push(code_row("AS-005", "AS-REQ a cuenta DONT_REQUIRE_PREAUTH",
                    "sin preauth sobre cuenta con la opción desactivada", "AS-REP directo (enc-part cifrado con la clave del usuario: AS-REP roast)", &reply, tr_str(tr), None));
            }
        }
    }

    // 6. Skew de reloj +10 min (preauth en el futuro).
    {
        let key = ctx.user_key.clone();
        let future = KrbTime::now().plus_secs(600);
        let req = charon_client::build_pa_enc_timestamp_at(&key, future)
            .and_then(|pa| charon_client::build_as_req_raw(&ctx.user, &ctx.realm, vec![pa], &[18], 0));
        if let Ok(r) = req {
            if let Ok((reply, tr)) = ctx.conn.exchange(&r.build().unwrap_or_default()) {
                rows.push(code_row("AS-006", "AS-REQ con timestamp a +10 minutos",
                    "preauth con reloj adelantado más allá del skew típico (5 min)", "rechazo del preauth (24) o aceptación según política", &reply, tr_str(tr), None));
            }
        }
    }

    // 7. Cname con otra caja (case).
    {
        let upper = ctx.user.to_uppercase();
        let req = charon_client::build_as_req(&upper, &ctx.realm, None, &[18, 17, 23], true, 0);
        if let Ok(r) = req {
            if let Ok((reply, tr)) = ctx.conn.exchange(&r.build().unwrap_or_default()) {
                rows.push(code_row("AS-007", "AS-REQ con cname en mayúsculas",
                    &format!("cname={} vs {}", upper, ctx.user), "KerberosString es case-sensitive por RFC; ¿el KDC la pliega?", &reply, tr_str(tr), None));
            }
        }
    }

    // 8. Realm desconocido.
    {
        let req = charon_client::build_as_req(&ctx.user, "NOEXISTE.INVALID", None, &[18, 17, 23], true, 0);
        if let Ok(r) = req {
            if let Ok((reply, tr)) = ctx.conn.exchange(&r.build().unwrap_or_default()) {
                rows.push(code_row("AS-008", "AS-REQ a realm inexistente",
                    "realm=NOEXISTE.INVALID", "KDC_ERR_PRINCIPAL_UNKNOWN (6) o referral (13)", &reply, tr_str(tr), None));
            }
        }
    }

    // 9. PA-DATA de tipo desconocido.
    {
        let pa = PaData { pa_type: 4242, pa_value: vec![0xDE, 0xAD] };
        let req = charon_client::build_as_req_raw(&ctx.user, &ctx.realm, vec![pa], &[18, 17, 23], 0);
        if let Ok(r) = req {
            if let Ok((reply, tr)) = ctx.conn.exchange(&r.build().unwrap_or_default()) {
                rows.push(code_row("AS-009", "AS-REQ con PA-DATA tipo 4242",
                    "padata-type sin significado", "ignorado (25) o KDC_ERR_PADATA_TYPE_NOSUPP (16): huella de implementación", &reply, tr_str(tr), None));
            }
        }
    }

    // ---------- TGS (se necesita TGT válido) ----------
    let tgt = charon_client::request_tgt(&ctx.conn, &ctx.user, &ctx.realm, &ctx.user_key, &[18], kdc_options::FORWARDABLE);
    let tgt = match tgt {
        Ok(t) => t,
        Err(e) => {
            rows.push(err_row("TGS-000", "obtención de TGT previa", "requisito para las sondas TGS", "TGT", &e, "-"));
            return finish(ctx, profile, rows);
        }
    };

    // 10. SPN inexistente.
    {
        let r = charon_client::request_service_ticket(&ctx.conn, &tgt, "inexistente/noexiste", &[18, 17, 23], 0);
        rows.push(match r {
            Err(ClientError::Krb5(Krb5Error::BadReply(msg))) => row_from_reply_error("TGS-001", "TGS-REQ a SPN inexistente",
                "sname=<spn sin registrar>", "KDC_ERR_S_PRINCIPAL_UNKNOWN (7)", &msg),
            Ok(_) => ok_row("TGS-001", "TGS-REQ a SPN inexistente", "sname=<spn sin registro>", "7", "el KDC EMITIÓ un ticket para un SPN inexistente: anómalo"),
            Err(e) => err_row("TGS-001", "TGS-REQ a SPN inexistente", "sname=<spn sin registro>", "7", &e, "UDP"),
        });
    }

    // 11. SPN malformado (una sola componente).
    {
        let r = charon_client::request_service_ticket(&ctx.conn, &tgt, "nobarra", &[18, 17, 23], 0);
        let row = match r {
            Err(ClientError::Krb5(Krb5Error::BadReply(msg))) => row_from_reply_error("TGS-002", "TGS-REQ con SPN de una sola componente",
                "sname=<sin barra>, nt-srv-inst", "7 o 13 según implementación", &msg),
            Ok(_) => ok_row("TGS-002", "TGS-REQ con SPN de una sola componente", "nobarra", "7", "ticket emitido"),
            Err(e) => err_row("TGS-002", "TGS-REQ con SPN de una sola componente", "nobarra", "7/13", &e, "UDP"),
        };
        rows.push(row);
    }

    // 12. etype 9999 en TGS.
    {
        let r = charon_client::request_service_ticket(&ctx.conn, &tgt, &ctx.spn_with_aes, &[9999], 0);
        let row = match r {
            Err(ClientError::Krb5(Krb5Error::BadReply(msg))) => row_from_reply_error("TGS-003", "TGS-REQ pidiendo etype 9999",
                "lista de etypes imposible", "KDC_ERR_ETYPE_NOTSUPP (14)", &msg),
            Ok(st) => ok_row("TGS-003", "TGS-REQ pidiendo etype 9999", "imposible", "14", &format!("ticket emitido en etype {}", st.ticket.enc_part.etype)),
            Err(e) => err_row("TGS-003", "TGS-REQ pidiendo etype 9999", "imposible", "14", &e, "UDP"),
        };
        rows.push(row);
    }

    // 13. Kerberoast AES-first vs RC4-only: el downgrade medible.
    {
        let st_aes = charon_client::request_service_ticket(&ctx.conn, &tgt, &ctx.spn_with_aes, &[18, 17, 23], 0);
        let row = match st_aes {
            Ok(st) => ok_row("TGS-004", "TGS-REQ con etypes [18,17,23] a cuenta AES",
                "AES-first: la herramienta pide primero el etype fuerte", "ticket en etype 18 (sin evento 4769 con 0x17)",
                &format!("ticket en etype {}", st.ticket.enc_part.etype)),
            Err(e) => err_row("TGS-004", "TGS-REQ con etypes [18,17,23] a cuenta AES", "AES-first", "ticket etype 18", &e, "UDP"),
        };
        rows.push(row);
        let st_rc4 = charon_client::request_service_ticket(&ctx.conn, &tgt, &ctx.spn_rc4_only, &[18, 17, 23], 0);
        let row = match st_rc4 {
            Ok(st) => ok_row("TGS-005", "TGS-REQ con etypes [18,17,23] a cuenta RC4-only",
                "la cuenta no tiene AES", "ticket en etype 23 (única opción de la cuenta)",
                &format!("ticket en etype {}", st.ticket.enc_part.etype)),
            Err(e) => err_row("TGS-005", "TGS-REQ con etypes [18,17,23] a cuenta RC4-only", "cuenta legacy", "ticket etype 23", &e, "UDP"),
        };
        rows.push(row);
    }

    // 14. Replay del authenticator: mismo wire dos veces.
    {
        let req = build_tgs_request(&tgt, &ctx.spn_with_aes);
        match req {
            Ok(wire) => {
                let r1 = ctx.conn.exchange(&wire);
                let (r2_reply, tr2) = ctx.conn.exchange(&wire).unwrap_or_else(|e| (format!("{e}").into_bytes(), charon_client::Transport::Udp));
                let note = match &r1 {
                    Ok(_) => Some("primera petición idéntica tuvo éxito".to_string()),
                    Err(e) => Some(format!("primera petición ya falló: {e}")),
                };
                rows.push(code_row("TGS-006", "replay exacto del TGS-REQ",
                    "se reenvía byte a byte la misma petición (mismo authenticator)", "KRB_AP_ERR_REPEAT (34) si hay caché de replays", &r2_reply, tr_str(tr2), note));
            }
            Err(e) => rows.push(err_row("TGS-006", "replay exacto del TGS-REQ", "mismo wire dos veces", "34", &ClientError::Krb5(e), "UDP")),
        }
    }

    finish(ctx, profile, rows)
}

fn finish(ctx: &ProbeCtx, profile: &str, rows: Vec<MatrixRow>) -> MatrixDataset {
    MatrixDataset {
        generated_at: charon_asn1::KrbTime::now().to_wire(),
        kdc_profile: profile.to_string(),
        host: ctx.conn.host.clone(),
        port: ctx.conn.port,
        realm: ctx.realm.clone(),
        rows,
    }
}

fn tr_str(t: charon_client::Transport) -> String {
    match t {
        charon_client::Transport::Udp => "UDP".into(),
        charon_client::Transport::Tcp => "TCP".into(),
    }
}

fn ok_row(id: &str, name: &str, desc: &str, expected: &str, note: &str) -> MatrixRow {
    MatrixRow {
        id: id.into(),
        name: name.into(),
        description: desc.into(),
        expected: expected.into(),
        observed_code: "OK".into(),
        observed_name: None,
        e_text: None,
        notes: Some(note.to_string()),
        transport: "UDP".into(),
    }
}

fn row_from_reply_error(id: &str, name: &str, desc: &str, expected: &str, msg: &str) -> MatrixRow {
    // Extrae el código si el mensaje lo lleva entre paréntesis del describe().
    let observed = if msg.contains("S_PRINCIPAL_UNKNOWN") {
        "7".to_string()
    } else if msg.contains("PREAUTH_FAILED") {
        "24".to_string()
    } else if msg.contains("ETYPE_NOTSUPP") || msg.contains("SUMTYPE_NOSUPP") {
        "14/15".to_string()
    } else if msg.contains("BADOPTION") {
        "13".to_string()
    } else if msg.contains("REPEAT") {
        "34".to_string()
    } else {
        "?".to_string()
    };
    MatrixRow {
        id: id.into(),
        name: name.into(),
        description: desc.into(),
        expected: expected.into(),
        observed_code: observed,
        observed_name: Some(msg.chars().take(80).collect()),
        e_text: None,
        notes: None,
        transport: "UDP".into(),
    }
}

/// Construye un TGS-REQ "a pelo" reutilizando el authenticator del client,
/// para sondas que necesitan el wire exacto (replays).
fn build_tgs_request(tgt: &charon_client::Tgt, spn: &str) -> std::result::Result<Vec<u8>, Krb5Error> {
    let now = KrbTime::now();
    let authenticator = Authenticator {
        crealm: tgt.crealm.clone(),
        cname: PrincipalName::user(&tgt.cname),
        cksum: None,
        cusec: 0,
        ctime: now,
        subkey: None,
        seq_number: None,
    };
    let key = charon_kcrypto::KerberosKey::from_raw(tgt.session_key.keytype, &tgt.session_key.keyvalue)
        .map_err(|_| Krb5Error::BadPac("clave de sesión inválida".into()))?;
    let auth_edata = charon_kcrypto::encrypt(&key, charon_kcrypto::usage::TGS_REQ_AUTH, &authenticator.build()?)
        .map_err(|_| Krb5Error::BadPac("no se pudo cifrar el authenticator".into()))?;
    let req = KdcReq {
        msg_type: MSG_TGS_REQ,
        padata: vec![PaData {
            pa_type: pa_type::PA_TGS_REQ,
            pa_value: ApReq {
                ap_options: 0,
                ticket: tgt.ticket.clone(),
                authenticator: EncryptedData { etype: tgt.session_key.keytype, kvno: None, cipher: auth_edata },
            }
            .build()?,
        }],
        body: KdcReqBody {
            kdc_options: 0,
            cname: None,
            realm: tgt.crealm.clone(),
            sname: Some(PrincipalName::from_spn(spn)),
            from: None,
            till: now.plus_secs(3_600),
            rtime: None,
            nonce: 1,
            etypes: vec![18, 17, 23],
            addresses: None,
            enc_authorization_data: None,
            additional_tickets: None,
        },
    };
    req.build()
}
