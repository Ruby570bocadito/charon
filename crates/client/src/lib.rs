//! # charon-client — driver Kerberos
//!
//! Transporte UDP/TCP con el framing de RFC 4120 §7.2.2 (prefijo de
//! longitud big-endian de 4 bytes en TCP; UDP → TCP cuando el KDC
//! responde KRB_ERR_RESPONSE_TOO_BIG) y las operaciones de alto nivel
//! sobre el intercambio AS y TGS.
//!
//! Cada función devuelve el mensaje crudo además del parseado para que
//! la capa de trace pueda explicarlo campo a campo.

use std::net::{TcpStream, UdpSocket};
use std::time::Duration;

use charon_asn1::KrbTime;
use charon_kcrypto::random_u32;
use charon_kcrypto::KerberosKey;
use charon_krb5::*;

pub type Result<T> = std::result::Result<T, ClientError>;

#[derive(thiserror::Error, Debug)]
pub enum ClientError {
    #[error("E/S con el KDC: {0}")]
    Io(#[from] std::io::Error),

    #[error(transparent)]
    Asn1(#[from] charon_asn1::Asn1Error),

    #[error(transparent)]
    Krb5(#[from] Krb5Error),

    #[error("crypto: {0}")]
    Crypto(#[from] charon_kcrypto::CryptoError),

    #[error("el KDC respondió con un mensaje no reconocido (tag no es AS-REP/TGS-REP/KRB-ERROR)")]
    UnknownReply,
}

/// Resultado de un intercambio AS exitoso: el TGT y su material.
#[derive(Clone, Debug)]
pub struct Tgt {
    pub crealm: String,
    pub cname: String,
    pub ticket: Ticket,
    pub session_key: EncryptionKey,
    pub flags: u32,
    pub authtime: KrbTime,
    pub endtime: KrbTime,
    pub renew_till: Option<KrbTime>,
    /// AS-REP completo tal cual llegó (para trace).
    pub raw_reply: Vec<u8>,
    /// EncKDCRepPart descifrado (para trace).
    pub enc_rep_part_raw: Vec<u8>,
}

/// Resultado de un TGS-REQ: el service ticket pedido.
#[derive(Clone, Debug)]
pub struct ServiceTicket {
    pub crealm: String,
    pub cname: String,
    pub ticket: Ticket,
    pub session_key: EncryptionKey,
    pub flags: u32,
    /// TGS-REP completo tal cual llegó (para trace).
    pub raw_reply: Vec<u8>,
}

/// Sondea el KDC con un AS-REQ SIN preauth y clasifica la respuesta.
/// Es el primitivo de enumeración de usuarios y de AS-REP roasting.
#[derive(Clone, Debug)]
pub enum AsProbe {
    /// 25: el usuario existe y requiere preauth (regala el salt).
    PreauthRequired { salts: Vec<EtypeInfo2Entry>, raw: Vec<u8> },
    /// AS-REP directo: la cuenta no requiere preauth (AS-REP roasteable).
    /// `reply` va en Box: KdcRep es grande y AsProbe se devuelve por valor.
    NoPreauth { reply: Box<KdcRep>, raw: Vec<u8> },
    /// 6: el principal no existe.
    PrincipalUnknown { raw: Vec<u8> },
    /// 24: existe y el preauth (si se envió) era incorrecto.
    PreauthFailed { raw: Vec<u8> },
    /// Cualquier otro código del KDC.
    Error { code: i32, e_text: Option<String>, raw: Vec<u8> },
}

/// Conexión con un KDC.
pub struct KdcConnection {
    pub host: String,
    pub port: u16,
    pub timeout: Duration,
}

impl KdcConnection {
    pub fn new(host: &str, port: u16) -> KdcConnection {
        KdcConnection {
            host: host.to_string(),
            port,
            timeout: Duration::from_secs(3),
        }
    }

    fn udp_socket(&self) -> std::io::Result<UdpSocket> {
        let s = UdpSocket::bind("0.0.0.0:0")?;
        s.set_read_timeout(Some(self.timeout))?;
        s.set_write_timeout(Some(self.timeout))?;
        Ok(s)
    }

    /// Envía por UDP y espera una respuesta completa.
    pub fn send_udp(&self, req: &[u8]) -> Result<Vec<u8>> {
        let sock = self.udp_socket()?;
        let target = format!("{}:{}", self.host, self.port);
        sock.send_to(req, &target)?;
        let mut buf = vec![0u8; 65535];
        let n = sock.recv(&mut buf)?;
        buf.truncate(n);
        Ok(buf)
    }

    /// Envía por TCP con el framing de RFC 4120 §7.2.2.
    pub fn send_tcp(&self, req: &[u8]) -> Result<Vec<u8>> {
        let mut stream = TcpStream::connect((self.host.as_str(), self.port))?;
        stream.set_read_timeout(Some(self.timeout))?;
        stream.set_write_timeout(Some(self.timeout))?;
        let len = (req.len() as u32).to_be_bytes();
        use std::io::{Read, Write};
        stream.write_all(&len)?;
        stream.write_all(req)?;
        let mut len_buf = [0u8; 4];
        stream.read_exact(&mut len_buf)?;
        let rlen = u32::from_be_bytes(len_buf) as usize;
        if rlen > charon_asn1::MAX_DER_LEN {
            return Err(ClientError::UnknownReply);
        }
        let mut buf = vec![0u8; rlen];
        stream.read_exact(&mut buf)?;
        Ok(buf)
    }

    /// Envío con estrategia UDP→TCP: si la respuesta por UDP es un error
    /// 52 (RESPONSE_TOO_BIG) o el datagrama parece truncado, reintenta
    /// por TCP. Devuelve (respuesta, transporte_usado).
    pub fn exchange(&self, req: &[u8]) -> Result<(Vec<u8>, Transport)> {
        let udp_reply = match self.send_udp(req) {
            Ok(r) => r,
            Err(e) => {
                // UDP fallido (timeout/puerto): prueba TCP directamente.
                let _ = e;
                return Ok((self.send_tcp(req)?, Transport::Tcp));
            }
        };
        // ¿Truncamiento anunciado por el KDC?
        if let Ok(err) = KrbError::parse(&udp_reply) {
            if err.error_code == KRB_ERR_RESPONSE_TOO_BIG {
                return Ok((self.send_tcp(req)?, Transport::Tcp));
            }
        }
        Ok((udp_reply, Transport::Udp))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Transport {
    Udp,
    Tcp,
}

// ---------- construcción de mensajes ----------

/// PA-ENC-TIMESTAMP: el timestamp actual cifrado con la clave del cliente
/// (usage 1). El valor del PA-DATA es el edata crudo, sin envoltorio
/// EncryptedData (así lo hacen MIT, Windows, impacket y Rubeus).
pub fn build_pa_enc_timestamp(key: &KerberosKey) -> Result<PaData> {
    build_pa_enc_timestamp_at(key, KrbTime::now())
}

/// Variante con timestamp arbitrario (sondas de clock-skew de la matriz).
///
/// El valor del PA-DATA es la DER de `EncryptedData { etype, cipher }`:
/// así lo envían los clientes modernos (MIT 1.21 y Windows) y así lo
/// espera el decodificador del KDC. Enviar el edata crudo "funciona a
/// veces" contra MIT (hay un fallback) pero es no determinista: el
/// primer byte aleatorio del edata se interpreta como tag DER y el
/// resultado del parseo accidental cambia por petición.
pub fn build_pa_enc_timestamp_at(key: &KerberosKey, when: KrbTime) -> Result<PaData> {
    // pa-enc-ts-enc ::= SEQUENCE { patimestamp [0], pausec [1] opcional }
    let ts = charon_asn1::encode_sequence(&[charon_asn1::encode_context_wrapped(
        0,
        &charon_asn1::encode_time(when),
    )?])?;
    let edata = charon_kcrypto::encrypt(key, charon_kcrypto::usage::AS_REQ_PA_ENC_TS, &ts)?;
    let wrapped = EncryptedData {
        etype: key.etype(),
        kvno: None,
        cipher: edata,
    }
    .build()?;
    Ok(PaData { pa_type: pa_type::PA_ENC_TIMESTAMP, pa_value: wrapped })
}

/// AS-REQ con PA-DATA arbitrario (sondas de la matriz).
pub fn build_as_req_raw(
    user: &str,
    realm: &str,
    padata: Vec<PaData>,
    etypes: &[i32],
    kdc_options: u32,
) -> Result<KdcReq> {
    let nonce = random_u32().unwrap_or(1);
    Ok(KdcReq {
        msg_type: MSG_AS_REQ,
        padata,
        body: KdcReqBody {
            kdc_options,
            cname: Some(PrincipalName::user(user)),
            realm: realm.to_string(),
            sname: Some(PrincipalName::krbtgt(realm)),
            from: None,
            till: KrbTime::now().plus_secs(86_400),
            rtime: None,
            nonce,
            etypes: etypes.to_vec(),
            addresses: None,
            enc_authorization_data: None,
            additional_tickets: None,
        },
    })
}

/// PA-PAC-REQUEST (Microsoft): pide incluir el PAC en el TGT.
pub fn build_pa_pac_request(include_pac: bool) -> Result<PaData> {
    let body = charon_asn1::encode_sequence(&[charon_asn1::encode_context_wrapped(
        0,
        &charon_asn1::encode_bool(include_pac),
    )?])?;
    Ok(PaData { pa_type: pa_type::PA_PAC_REQUEST, pa_value: body })
}

/// AS-REQ completo con preauth y PAC.
pub fn build_as_req(
    user: &str,
    realm: &str,
    key: Option<&KerberosKey>,
    etypes: &[i32],
    include_pac: bool,
    kdc_options: u32,
) -> Result<KdcReq> {
    let mut padata = Vec::new();
    if let Some(k) = key {
        padata.push(build_pa_enc_timestamp(k)?);
    }
    if include_pac {
        padata.push(build_pa_pac_request(true)?);
    }
    build_as_req_raw(user, realm, padata, etypes, kdc_options)
}

// ---------- operaciones ----------

/// Sondeo AS sin preauth: clasifica 25/6/24/AS-REP/cualquier otro.
pub fn probe_as_no_preauth(conn: &KdcConnection, user: &str, realm: &str, etypes: &[i32]) -> Result<AsProbe> {
    let req = build_as_req(user, realm, None, etypes, true, kdc_options::CANONICALIZE)?;
    let (reply, _transport) = conn.exchange(&req.build()?)?;
    // ¿AS-REP directo? (cuenta sin preauth: roasteable)
    if KdcRep::parse(&reply).is_ok() {
        return Ok(AsProbe::NoPreauth { reply: Box::new(KdcRep::parse(&reply)?), raw: reply });
    }
    let err = KrbError::parse(&reply)?;
    match err.error_code {
        KDC_ERR_PREAUTH_REQUIRED => Ok(AsProbe::PreauthRequired {
            salts: err.etype_info2().unwrap_or_default(),
            raw: reply,
        }),
        KDC_ERR_PRINCIPAL_UNKNOWN => Ok(AsProbe::PrincipalUnknown { raw: reply }),
        KDC_ERR_PREAUTH_FAILED => Ok(AsProbe::PreauthFailed { raw: reply }),
        code => Ok(AsProbe::Error { code, e_text: err.e_text, raw: reply }),
    }
}

/// Obtiene un TGT con preauth (contraseña o clave cruda = pass-the-key).
pub fn request_tgt(
    conn: &KdcConnection,
    user: &str,
    realm: &str,
    key: &KerberosKey,
    etypes: &[i32],
    kdc_options: u32,
) -> Result<Tgt> {
    let req = build_as_req(user, realm, Some(key), etypes, true, kdc_options)?;
    let (reply, _transport) = conn.exchange(&req.build()?)?;
    parse_as_reply(&reply, user, key)
}

/// Parsea y descifra un AS-REP (o traduce el KRB-ERROR a error de cliente).
pub fn parse_as_reply(reply: &[u8], user: &str, key: &KerberosKey) -> Result<Tgt> {
    if let Ok(err) = KrbError::parse(reply) {
        let d = error_codes::describe(err.error_code);
        return Err(ClientError::Krb5(Krb5Error::BadReply(format!(
            "KDC rechazó el AS-REQ de {}: {} ({}){}",
            user,
            d.name,
            d.leak,
            err.e_text.as_deref().map(|t| format!(" — \"{}\"", t)).unwrap_or_default()
        ))));
    }
    let rep = KdcRep::parse(reply)?;
    if rep.cname.name_string.first().map(|s| s.as_str()) != Some(user) {
        return Err(ClientError::Krb5(Krb5Error::BadReply(format!(
            "el AS-REP es para {:?}, no para {}",
            rep.cname.name_string, user
        ))));
    }
    // El enc-part del AS-REP va cifrado con la clave del cliente (usage 3;
    // para RC4 el mapa interno ya lo traduce a 8 como exige la errata).
    let plain = charon_kcrypto::decrypt(key, charon_kcrypto::usage::AS_REP_ENCPART, &rep.enc_part.cipher)?;
    let part = EncKdcRepPart::parse_element(&plain)?;
    Ok(Tgt {
        crealm: rep.crealm.clone(),
        cname: rep.cname.flat(),
        ticket: rep.ticket.clone(),
        session_key: part.key.clone(),
        flags: part.flags,
        authtime: part.authtime,
        endtime: part.endtime,
        renew_till: part.renew_till,
        raw_reply: reply.to_vec(),
        enc_rep_part_raw: plain,
    })
}

/// TGS-REQ para un SPN usando un TGT (kerberoasting y acceso a servicios).
pub fn request_service_ticket(
    conn: &KdcConnection,
    tgt: &Tgt,
    spn: &str,
    etypes: &[i32],
    kdc_options: u32,
) -> Result<ServiceTicket> {
    // 1) El cuerpo se construye primero: MIT 1.21 (como Windows) exige un
    // checksum del authenticator sobre el req-body codificado.
    let body = KdcReqBody {
        kdc_options,
        cname: None,
        realm: tgt.crealm.clone(),
        sname: Some(PrincipalName::from_spn(spn)),
        from: None,
        till: KrbTime::now().plus_secs(3_600),
        rtime: None,
        nonce: random_u32().unwrap_or(1),
        etypes: etypes.to_vec(),
        addresses: None,
        enc_authorization_data: None,
        additional_tickets: None,
    };
    let body_tlv = body.build()?;

    // 2) Checksum del authenticator: con clave de sesión del TGT, usage 6
    // (RFC 4120 §7.5.1), cubre el TLV del req-body. Tipos collision-proof
    // exigidos por el KDC: HMAC-SHA1-96 AES (15/16) o HMAC-MD5-ARCFOUR (-138),
    // exactamente lo que produce kcrypto::checksum según el etype.
    let session_key = charon_kcrypto::KerberosKey::from_raw(tgt.session_key.keytype, &tgt.session_key.keyvalue)?;
    let cksum_data = charon_kcrypto::checksum(&session_key, charon_kcrypto::usage::TGS_REQ_AUTH_CKSUM, &body_tlv)?;
    let cksum_type = match tgt.session_key.keytype {
        charon_kcrypto::etype::RC4_HMAC => -138, // HMAC-MD5-ARCFOUR
        _ => 16,                                 // HMAC-SHA1-96-AES256 (o 15 con AES128: mismo formato)
    };

    // 3) Authenticator cifrado con la clave de sesión del TGT (usage 7).
    let now = KrbTime::now();
    let authenticator = Authenticator {
        crealm: tgt.crealm.clone(),
        cname: PrincipalName::user(&tgt.cname),
        cksum: Some(Checksum { cksumtype: cksum_type, checksum: cksum_data }),
        cusec: 0,
        ctime: now,
        subkey: None,
        seq_number: None,
    };
    let auth_plain = authenticator.build()?;
    let auth_edata = charon_kcrypto::encrypt(&session_key, charon_kcrypto::usage::TGS_REQ_AUTH, &auth_plain)?;
    let ap_req = ApReq {
        ap_options: 0,
        ticket: tgt.ticket.clone(),
        authenticator: EncryptedData {
            etype: tgt.session_key.keytype,
            kvno: None,
            cipher: auth_edata,
        },
    };
    let req = KdcReq {
        msg_type: MSG_TGS_REQ,
        padata: vec![PaData {
            pa_type: pa_type::PA_TGS_REQ,
            pa_value: ap_req.build()?,
        }],
        body,
    };
    let (reply, _transport) = conn.exchange(&req.build()?)?;
    parse_tgs_reply(&reply, &tgt.session_key)
}

pub fn parse_tgs_reply(reply: &[u8], tgt_session_key: &EncryptionKey) -> Result<ServiceTicket> {
    if let Ok(err) = KrbError::parse(reply) {
        let d = error_codes::describe(err.error_code);
        return Err(ClientError::Krb5(Krb5Error::BadReply(format!(
            "KDC rechazó el TGS-REQ: {} ({}){}",
            d.name,
            d.leak,
            err.e_text.as_deref().map(|t| format!(" — \"{}\"", t)).unwrap_or_default()
        ))));
    }
    let rep = KdcRep::parse(reply)?;
    let key = charon_kcrypto::KerberosKey::from_raw(tgt_session_key.keytype, &tgt_session_key.keyvalue)?;
    // El enc-part del TGS-REP va con la clave de sesión del TGT (usage 8).
    let plain = charon_kcrypto::decrypt(&key, charon_kcrypto::usage::TGS_REP_ENCPART_SESSKEY, &rep.enc_part.cipher)?;
    let part = EncKdcRepPart::parse_element(&plain)?;
    Ok(ServiceTicket {
        crealm: rep.crealm.clone(),
        cname: rep.cname.flat(),
        ticket: rep.ticket.clone(),
        session_key: part.key.clone(),
        flags: part.flags,
        raw_reply: reply.to_vec(),
    })
}

// ---------- S4U2Self (MS-SFU §2.2) ----------

/// Construye el PA-FOR-USER de MS-SFU §2.2.2.
///
/// El checksum usa la construcción HMAC-MD5-ARCFOUR ("signaturekey")
/// con usage 17 **independientemente del etype de la clave de sesión**
/// ("Per spec, use hmac-md5 checksum regardless of key type", MIT
/// s4u_creds.c), sobre `LE32(name-type) || componentes || realm ||
/// "Kerberos"`.
pub fn build_pa_for_user(
    session_key: &charon_kcrypto::KerberosKey,
    target_user: &str,
    realm: &str,
) -> Result<PaData> {
    let user = PrincipalName::user(target_user);
    let mut data: Vec<u8> = Vec::new();
    data.extend_from_slice(&user.name_type.to_le_bytes());
    for comp in &user.name_string {
        data.extend_from_slice(comp.as_bytes());
    }
    data.extend_from_slice(realm.as_bytes());
    data.extend_from_slice(b"Kerberos");
    let cksum = charon_kcrypto::rc4hmac::checksum(session_key.as_bytes(), charon_kcrypto::usage::APP_DATA_CKSUM, &data)?;

    let pa_for_user = charon_asn1::encode_sequence(&[
        charon_asn1::encode_context_wrapped(0, &user.build()?)?,
        charon_asn1::encode_context_wrapped(1, &charon_asn1::encode_string(realm))?,
        charon_asn1::encode_context_wrapped(
            2,
            &Checksum { cksumtype: -138, checksum: cksum }.build()?,
        )?,
        charon_asn1::encode_context_wrapped(3, &charon_asn1::encode_string("Kerberos"))?,
    ])?;
    Ok(PaData { pa_type: pa_type::PA_FOR_USER, pa_value: pa_for_user })
}

/// S4U2Self: obtiene un ticket "para" `target_user` presentando el TGT de
/// `service`. El ticket devuelto va cifrado con la clave larga del
/// servicio: con ella, `pac::extract_pac` muestra el PAC del usuario
/// suplantado (la prueba de que el KDC lo emitió en su nombre).
pub fn s4u2self(
    conn: &KdcConnection,
    tgt: &Tgt,
    service_as: &str,
    target_user: &str,
    realm: &str,
) -> Result<ServiceTicket> {
    let session_key = charon_kcrypto::KerberosKey::from_raw(tgt.session_key.keytype, &tgt.session_key.keyvalue)?;
    let body = KdcReqBody {
        kdc_options: kdc_options::FORWARDABLE | kdc_options::CANONICALIZE,
        cname: None,
        realm: realm.to_string(),
        // S4U2Self: el sname es el PROPIO servicio que pide; el usuario
        // suplantado viaja en el PA-FOR-USER (MS-SFU §2.2.2).
        sname: Some(PrincipalName::user(service_as)),
        from: None,
        till: KrbTime::now().plus_secs(600),
        rtime: None,
        nonce: random_u32().unwrap_or(1),
        etypes: vec![charon_kcrypto::etype::AES256_CTS_HMAC_SHA1_96, charon_kcrypto::etype::RC4_HMAC],
        addresses: None,
        enc_authorization_data: None,
        additional_tickets: None,
    };
    let body_tlv = body.build()?;
    let cksum_data = charon_kcrypto::checksum(&session_key, charon_kcrypto::usage::TGS_REQ_AUTH_CKSUM, &body_tlv)?;
    let cksum_type = match tgt.session_key.keytype {
        charon_kcrypto::etype::RC4_HMAC => -138,
        _ => 16,
    };
    let now = KrbTime::now();
    let authenticator = Authenticator {
        crealm: tgt.crealm.clone(),
        cname: PrincipalName::user(&tgt.cname),
        cksum: Some(Checksum { cksumtype: cksum_type, checksum: cksum_data }),
        cusec: 0,
        ctime: now,
        subkey: None,
        seq_number: None,
    };
    let auth_plain = authenticator.build()?;
    let auth_edata = charon_kcrypto::encrypt(&session_key, charon_kcrypto::usage::TGS_REQ_AUTH, &auth_plain)?;
    let pa_for_user = build_pa_for_user(&session_key, target_user, realm)?;
    let req = KdcReq {
        msg_type: MSG_TGS_REQ,
        padata: vec![
            PaData {
                pa_type: pa_type::PA_TGS_REQ,
                pa_value: ApReq {
                    ap_options: 0,
                    ticket: tgt.ticket.clone(),
                    authenticator: EncryptedData {
                        etype: tgt.session_key.keytype,
                        kvno: None,
                        cipher: auth_edata,
                    },
                }
                .build()?,
            },
            pa_for_user,
        ],
        body,
    };
    let (reply, _transport) = conn.exchange(&req.build()?)?;
    parse_tgs_reply(&reply, &tgt.session_key)
}
