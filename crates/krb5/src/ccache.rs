//! # ccache — formato FILE de MIT krb5 (estructura versión 4)
//!
//! Implementación del formato documentado en
//! <https://web.mit.edu/kerberos/krb5-1.21/doc/formats/ccache_file_format.html>,
//! verificada byte a byte contra un ccache real producido por `kinit` 1.21.3
//! (oráculo: `klist -c` y `kinit -R -c` del propio MIT leen los ficheros que
//! escribe Charon).
//!
//! Estructura del fichero (todo big-endian; las versiones 3 y 4 usan siempre
//! big-endian):
//!
//! ```text
//! 05 04               formato 5, estructura 4
//! cabecera (solo v4):  longitud u16 + campos { tag u16, len u16, valor }
//! principal por defecto: sin framing externo
//! credenciales:        sin framing externo ni contador; el final es el EOF
//! ```
//!
//! `principal ::= nametype(u32) + count(u32) + reino(data) + componentes(data)`
//! — `count` es el número de componentes SIN contar el reino.
//!
//! `credencial ::= cliente(principal) + servidor(principal)
//!               + keyblock(enctype u16 + data) + authtime(u32) + starttime(u32)
//!               + endtime(u32) + renew_till(u32) + is_skey(u8) + flags(u32)
//!               + addresses(count + { adrtype u16 + data }) + authdata(count + ...)
//!               + ticket(data) + second_ticket(data)`
//!
//! Nota de alcance: los tiempos del formato son u32 (segundos UNIX), límite
//! propio del formato de MIT (2038 en el peor caso de lectura con signo; el
//! formato no da más). Charon lo hereda sin rebuscar: se documenta y punto.
//!
//! Las **entradas de configuración** (`krb5_ccache_conf_data/<clave>` en el
//! reino especial `X-CACHECONF:`) se leen y se exponen como credenciales
//! normales; `is_config_entry()` permite saltarlas y `first_tgt()` lo hace
//! por ti. Al ESCRIBIR Charon no genera entradas de configuración: no son
//! necesarias para que `klist`/`kinit` acepten el fichero (verificado).

use crate::{EncryptionKey, Krb5Error, PrincipalName, Result, Ticket, name_type};

/// Reino especial de las entradas de configuración del ccache de MIT.
pub const X_CACHECONF_REALM: &str = "X-CACHECONF:";

/// Tope de componentes/entradas al leer: un fichero corrupto no debe poder
/// provocar reservas enormes (cada componente paga su longitud en bytes, así
/// que el tope solo cierra el círculo contra ficheros hostiles).
const MAX_COMPONENTS: usize = 256;

/// Principal de ccache: nametype + reino + componentes (el reino es propio
/// del principal en este formato, a diferencia de `PrincipalName`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CcachePrincipal {
    pub name_type: i32,
    pub realm: String,
    pub components: Vec<String>,
}

impl CcachePrincipal {
    /// Nombre plano tipo `jdoe` o `krbtgt/LAB.LOCAL`.
    pub fn flat(&self) -> String {
        self.components.join("/")
    }

    /// Conversión al `PrincipalName` de los mensajes (sin el reino).
    pub fn to_principal(&self) -> PrincipalName {
        PrincipalName {
            name_type: self.name_type,
            name_string: self.components.clone(),
        }
    }

    /// De un `PrincipalName` de los mensajes y su reino.
    pub fn from_principal(p: &PrincipalName, realm: &str) -> CcachePrincipal {
        CcachePrincipal {
            name_type: p.name_type,
            realm: realm.to_string(),
            components: p.name_string.clone(),
        }
    }

    /// Principal de usuario simple (`nt-principal`, un componente).
    pub fn user(name: &str, realm: &str) -> CcachePrincipal {
        CcachePrincipal {
            name_type: name_type::NT_PRINCIPAL,
            realm: realm.to_string(),
            components: vec![name.to_string()],
        }
    }

    fn build_into(&self, out: &mut Vec<u8>) -> Result<()> {
        push_u32(out, self.name_type as u32);
        push_u32(out, self.components.len() as u32);
        push_data(out, self.realm.as_bytes())?;
        for c in &self.components {
            push_data(out, c.as_bytes())?;
        }
        Ok(())
    }
}

/// Una credencial de ccache: todo el material de un ticket y su clave.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CcacheCredential {
    pub client: CcachePrincipal,
    pub server: CcachePrincipal,
    pub key: EncryptionKey,
    /// Segundos UNIX (u32 del formato; 0 = sin dato).
    pub authtime: u32,
    pub starttime: Option<u32>,
    pub endtime: u32,
    pub renew_till: Option<u32>,
    pub is_skey: bool,
    /// Bitmask tal cual (misma numeración que `ticket_flags`).
    pub flags: u32,
    /// DER del ticket completo ([APPLICATION 1]).
    pub ticket_der: Vec<u8>,
}

impl CcacheCredential {
    /// ¿Es una entrada de configuración de MIT (`X-CACHECONF:`)? Estas
    /// entradas guardan metadatos (fast_avail, pa_type, ...) y su campo
    /// ticket NO es un ticket Kerberos.
    pub fn is_config_entry(&self) -> bool {
        self.server.realm == X_CACHECONF_REALM
    }
}

/// Un fichero ccache parseado (o listo para serializar).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CcacheFile {
    /// Versión de estructura (solo se soporta 4, la que escribe MIT 1.21).
    pub version: u8,
    pub default_principal: CcachePrincipal,
    pub credentials: Vec<CcacheCredential>,
}

impl CcacheFile {
    /// Crea un ccache v4 mínimo: el principal por defecto es el cliente de
    /// la credencial dada (así lo hace `kinit` con un solo ticket).
    pub fn single(credential: CcacheCredential) -> CcacheFile {
        CcacheFile {
            version: 4,
            default_principal: credential.client.clone(),
            credentials: vec![credential],
        }
    }

    /// Primera credencial real (no `X-CACHECONF:`): en un ccache recién
    /// escrito por Charon es el TGT.
    pub fn first_tgt(&self) -> Option<&CcacheCredential> {
        self.credentials.iter().find(|c| !c.is_config_entry())
    }

    /// Serializa el fichero completo (cabecera v4 como la que escribe MIT:
    /// campo 1 = offset de reloj KDC, aquí 0).
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        if self.version != 4 {
            return Err(Krb5Error::BadCcache(format!(
                "solo se escribe la estructura versión 4 (pedida: {})",
                self.version
            )));
        }
        let mut out = Vec::new();
        out.push(0x05);
        out.push(0x04);
        // Cabecera v4: longitud total (u16) + campos { tag u16, len u16, valor }.
        // Un solo campo (tag 1): segundos y microsegundos del offset del KDC,
        // 0 en el lab (mismo reloj). Un lector debe ignorar tags desconocidos;
        // escribir el campo es lo que hace kinit 1.21 y lo reflejamos.
        push_u16(&mut out, 12);
        push_u16(&mut out, 1);
        push_u16(&mut out, 8);
        out.extend_from_slice(&[0u8; 8]);

        self.default_principal.build_into(&mut out)?;
        for cred in &self.credentials {
            cred.build_into(&mut out)?;
        }
        Ok(out)
    }

    /// Parsea un fichero ccache v4 (lecturas acotadas: un fichero corrupto
    /// o hostil produce `Krb5Error::BadCcache`, nunca un panic ni una
    /// reserva desmedida).
    pub fn parse(bytes: &[u8]) -> Result<CcacheFile> {
        if bytes.len() < 2 || bytes[0] != 0x05 {
            return Err(Krb5Error::BadCcache(
                "no empieza con la firma 0x05 del formato FILE".into(),
            ));
        }
        if bytes[1] != 4 {
            return Err(Krb5Error::BadCcache(format!(
                "estructura versión {} no soportada (solo 4)",
                bytes[1]
            )));
        }
        let mut r = Reader { buf: bytes, pos: 2 };
        // Cabecera: se salta entera (los tags se ignoran por especificación).
        let header_len = r.u16()? as usize;
        r.take(header_len)?;

        let default_principal = read_principal(&mut r)?;
        let mut credentials = Vec::new();
        while r.pos < r.buf.len() {
            credentials.push(read_credential(&mut r)?);
        }
        Ok(CcacheFile { version: 4, default_principal, credentials })
    }
}

impl CcacheCredential {
    fn build_into(&self, out: &mut Vec<u8>) -> Result<()> {
        self.client.build_into(out)?;
        self.server.build_into(out)?;
        // keyblock: enctype (u16) + data (u32 longitud + bytes).
        push_u16(out, self.key.keytype as u16);
        push_data(out, &self.key.keyvalue)?;
        push_u32(out, self.authtime);
        push_u32(out, self.starttime.unwrap_or(0));
        push_u32(out, self.endtime);
        push_u32(out, self.renew_till.unwrap_or(0));
        out.push(u8::from(self.is_skey));
        push_u32(out, self.flags);
        // addresses / authdata: Charon no guarda ni_addresses ni authdata en
        // el ccache (el TGT funciona sin ellos y klist no los exige).
        push_u32(out, 0);
        push_u32(out, 0);
        push_data(out, &self.ticket_der)?;
        push_u32(out, 0); // second_ticket vacío
        Ok(())
    }
}

// ---------- escritura auxiliar ----------

fn push_u16(out: &mut Vec<u8>, v: u16) {
    out.extend_from_slice(&v.to_be_bytes());
}

fn push_u32(out: &mut Vec<u8>, v: u32) {
    out.extend_from_slice(&v.to_be_bytes());
}

fn push_data(out: &mut Vec<u8>, data: &[u8]) -> Result<()> {
    if data.len() > u32::MAX as usize {
        return Err(Krb5Error::BadCcache("campo demasiado largo para el formato".into()));
    }
    push_u32(out, data.len() as u32);
    out.extend_from_slice(data);
    Ok(())
}

// ---------- lectura (acotada, sin panics) ----------

struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self.pos.checked_add(n).ok_or_else(|| {
            Krb5Error::BadCcache(format!("longitud absurda en el offset {}", self.pos))
        })?;
        let slice = self
            .buf
            .get(self.pos..end)
            .ok_or_else(|| Krb5Error::BadCcache(format!("fichero truncado en el offset {}", self.pos)))?;
        self.pos = end;
        Ok(slice)
    }

    fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16> {
        let b = self.take(2)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }

    fn u32(&mut self) -> Result<u32> {
        let b = self.take(4)?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }

    fn data(&mut self) -> Result<&'a [u8]> {
        let len = self.u32()? as usize;
        // Tope de sanidad: un campo de más de 16 MB en un ccache es basura
        // (un TGT real no llega ni de lejos); se rechaza antes de reservar.
        if len > 16 * 1024 * 1024 {
            return Err(Krb5Error::BadCcache(format!(
                "campo de {len} bytes en el offset {}: fuera de todo rango plausible",
                self.pos
            )));
        }
        self.take(len)
    }
}

fn read_principal(r: &mut Reader<'_>) -> Result<CcachePrincipal> {
    let name_type = r.u32()? as i32;
    let count = r.u32()? as usize;
    if count > MAX_COMPONENTS {
        return Err(Krb5Error::BadCcache(format!(
            "principal con {count} componentes: corrupto o hostil"
        )));
    }
    let realm = String::from_utf8_lossy(r.data()?).into_owned();
    let mut components = Vec::with_capacity(count.min(8));
    for _ in 0..count {
        components.push(String::from_utf8_lossy(r.data()?).into_owned());
    }
    Ok(CcachePrincipal { name_type, realm, components })
}

fn read_credential(r: &mut Reader<'_>) -> Result<CcacheCredential> {
    let client = read_principal(r)?;
    let server = read_principal(r)?;
    let keytype = r.u16()? as i32;
    let keyvalue = r.data()?.to_vec();
    let authtime = r.u32()?;
    let starttime = r.u32()?;
    let endtime = r.u32()?;
    let renew_till = r.u32()?;
    let is_skey = r.u8()? != 0;
    let flags = r.u32()?;
    // addresses: count + count × { addrtype u16 + data }
    let n_addrs = r.u32()? as usize;
    if n_addrs > MAX_COMPONENTS {
        return Err(Krb5Error::BadCcache(format!("direcciones absurdas: {n_addrs}")));
    }
    for _ in 0..n_addrs {
        let _addr_type = r.u16()?;
        let _addr = r.data()?;
    }
    // authdata: count + count × { ad_type u16 + data }
    let n_ad = r.u32()? as usize;
    if n_ad > MAX_COMPONENTS {
        return Err(Krb5Error::BadCcache(format!("authdata absurdo: {n_ad}")));
    }
    for _ in 0..n_ad {
        let _ad_type = r.u16()?;
        let _ad = r.data()?;
    }
    let ticket_der = r.data()?.to_vec();
    let _second_ticket = r.data()?;
    Ok(CcacheCredential {
        client,
        server,
        key: EncryptionKey { keytype, keyvalue },
        authtime,
        starttime: (starttime != 0).then_some(starttime),
        endtime,
        renew_till: (renew_till != 0).then_some(renew_till),
        is_skey,
        flags,
        ticket_der,
    })
}

/// Extrae el `Ticket` de una credencial (parse DER con los errores de
/// siempre; el ticket de una entrada de configuración NO es un ticket —
/// por eso `first_tgt()` salta las entradas de configuración).
pub fn ticket_of(cred: &CcacheCredential) -> Result<Ticket> {
    Ticket::parse(&cred.ticket_der).map_err(|e| {
        Krb5Error::BadCcache(format!(
            "el campo ticket de {} no es un ticket DER válido: {e}",
            cred.server.flat()
        ))
    })
}

// ---------- tests ----------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{EncryptedData, kdc_options};

    /// Ticket sintético realista: se construye con el propio codec (mismo
    /// camino que un ticket del cable) y se usa como material del ccache.
    fn ticket_ejemplo() -> Ticket {
        Ticket {
            tkt_vno: 5,
            realm: "LAB.LOCAL".into(),
            sname: PrincipalName::krbtgt("LAB.LOCAL"),
            enc_part: EncryptedData {
                etype: 18,
                kvno: Some(2),
                cipher: vec![0xde, 0xad, 0xbe, 0xef, 0x42],
            },
        }
    }

    fn credencial_ejemplo() -> CcacheCredential {
        CcacheCredential {
            client: CcachePrincipal::user("jdoe", "LAB.LOCAL"),
            server: CcachePrincipal::from_principal(&PrincipalName::krbtgt("LAB.LOCAL"), "LAB.LOCAL"),
            key: EncryptionKey { keytype: 18, keyvalue: (0..32).collect() },
            authtime: 1_789_462_092,
            starttime: Some(1_789_462_092),
            endtime: 1_789_548_492,
            renew_till: Some(1_790_066_892),
            is_skey: false,
            flags: kdc_options::FORWARDABLE | kdc_options::RENEWABLE, // mismo nº de bits
            ticket_der: ticket_ejemplo().build().expect("ticket DER"),
        }
    }

    #[test]
    fn round_trip_write_parse_conserva_todo() {
        let cred = credencial_ejemplo();
        let file = CcacheFile::single(cred.clone());
        let bytes = file.to_bytes().expect("serializa");
        let back = CcacheFile::parse(&bytes).expect("parsea");
        assert_eq!(back.version, 4);
        assert_eq!(back.default_principal, cred.client);
        assert_eq!(back.credentials.len(), 1);
        assert_eq!(back.credentials[0], cred);
    }

    #[test]
    fn el_ticket_vuelve_a_parsear_y_es_idéntico() {
        let file = CcacheFile::single(credencial_ejemplo());
        let bytes = file.to_bytes().expect("serializa");
        let back = CcacheFile::parse(&bytes).expect("parsea");
        let cred = back.first_tgt().expect("una credencial real");
        let ticket = ticket_of(cred).expect("ticket DER válido");
        assert_eq!(ticket, ticket_ejemplo());
        assert!(!cred.is_config_entry());
    }

    #[test]
    fn rechaza_fichero_cortos_y_versiones_desconocidas_sin_panics() {
        assert!(CcacheFile::parse(&[]).is_err());
        assert!(CcacheFile::parse(&[0x05]).is_err());
        assert!(CcacheFile::parse(&[0x06, 0x04]).is_err());
        assert!(CcacheFile::parse(&[0x05, 0x02]).is_err());
        // firma correcta pero truncado en la cabecera
        assert!(CcacheFile::parse(&[0x05, 0x04, 0x00]).is_err());
        // cabecera que anuncia más bytes de los que hay
        assert!(CcacheFile::parse(&[0x05, 0x04, 0xff, 0xff]).is_err());
    }

    #[test]
    fn fichero_truncado_en_medio_de_una_credencial_es_error_no_panic() {
        let bytes = CcacheFile::single(credencial_ejemplo()).to_bytes().expect("serializa");
        // corta por la mitad: el parser debe fallar con error, no colgar
        for cut in [2, 20, 60, bytes.len() / 2, bytes.len() - 3] {
            assert!(
                CcacheFile::parse(&bytes[..cut]).is_err(),
                "un truncado a {cut} bytes debe fallar"
            );
        }
    }

    #[test]
    fn las_entradas_x_cacheconf_se_detectan_y_se_saltan() {
        let mut cred = credencial_ejemplo();
        cred.server = CcachePrincipal {
            name_type: name_type::NT_PRINCIPAL,
            realm: X_CACHECONF_REALM.into(),
            components: vec!["krb5_ccache_conf_data".into(), "pa_type".into()],
        };
        cred.ticket_der = vec![1, 2, 3]; // no es un ticket: por eso hay que saltarla
        let file = CcacheFile::single(cred);
        let bytes = file.to_bytes().expect("serializa");
        let back = CcacheFile::parse(&bytes).expect("parsea");
        assert!(back.credentials[0].is_config_entry());
        assert!(back.first_tgt().is_none(), "solo hay una entrada de configuración");
    }
}
