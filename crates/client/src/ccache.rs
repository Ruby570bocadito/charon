//! # Persistencia de material: ccache FILE de MIT ↔ [`Tgt`]
//!
//! Charon escribe el TGT (ticket DER + clave de sesión + tiempos) en un
//! ccache FILE v4 legible por `klist`/`kinit` de MIT, y lo vuelve a cargar
//! para renovar SIN volver a credencializar — el ciclo que hace real la
//! renovación de sesión (`charon as --ccache` → `charon renew --ccache`).
//!
//! Seguridad: el fichero lleva la clave de sesión en claro (igual que un
//! ccache de MIT: es SU formato). Se escribe con permisos 0600 y el README
//! lo documenta; el usuario decide dónde vive.

use std::io::Write;
use std::path::Path;

use charon_asn1::KrbTime;
use charon_krb5::ccache::{CcacheCredential, CcacheFile, CcachePrincipal, X_CACHECONF_REALM};

use crate::{ClientError, Result, Tgt};

/// Convierte un `Tgt` en credencial de ccache (el ticket se serializa a DER
/// con el propio codec; el reino va en cada principal, como pide el formato).
pub fn tgt_to_credential(tgt: &Tgt) -> Result<CcacheCredential> {
    // El cname llega plano ("jdoe"); si fuera multi-componente
    // ("host/mquina"), el split('/') lo preserva para el round-trip.
    let comps: Vec<String> = tgt.cname.split('/').map(str::to_string).collect();
    let name_type = if comps.len() == 1 {
        charon_krb5::name_type::NT_PRINCIPAL
    } else {
        charon_krb5::name_type::NT_SRV_INST
    };
    let u32_time = |t: &KrbTime| -> u32 {
        // El formato guarda u32: los tiempos Kerberos viven en [0, 2^32);
        // un valor negativo no puede existir aquí (KrbTime::now es ≥ 0) y
        // se acota a 0 por honestidad aritmética.
        t.unix_secs.clamp(0, u32::MAX as i64) as u32
    };
    Ok(CcacheCredential {
        client: CcachePrincipal {
            name_type,
            realm: tgt.crealm.clone(),
            components: comps,
        },
        server: CcachePrincipal::from_principal(&tgt.ticket.sname, &tgt.ticket.realm),
        key: tgt.session_key.clone(),
        authtime: u32_time(&tgt.authtime),
        starttime: None,
        endtime: u32_time(&tgt.endtime),
        renew_till: tgt.renew_till.as_ref().map(u32_time),
        is_skey: false,
        flags: tgt.flags,
        ticket_der: tgt.ticket.build().map_err(ClientError::from)?,
    })
}

/// Reconstruye el `Tgt` desde una credencial (parse del DER del ticket con
/// el codec propio). `raw_reply`/`enc_rep_part_raw` quedan vacíos: no hay
/// respuesta del KDC que preservar — el material persistido es el ticket y
/// su clave, y la renovación no necesita más (el trace de la renovación
/// muestra el TGS-REP nuevo, que sí llega por el cable).
pub fn tgt_from_credential(cred: &CcacheCredential) -> Result<Tgt> {
    if cred.is_config_entry() {
        return Err(ClientError::Krb5(charon_krb5::Krb5Error::BadCcache(format!(
            "la credencial pedida es una entrada de configuración ({X_CACHECONF_REALM}): no es un TGT"
        ))));
    }
    let ticket = charon_krb5::ccache::ticket_of(cred).map_err(ClientError::from)?;
    if ticket.realm != cred.server.realm {
        return Err(ClientError::Krb5(charon_krb5::Krb5Error::BadCcache(format!(
            "el ticket dice realm {:?} pero la credencial {:?}",
            ticket.realm, cred.server.realm
        ))));
    }
    let from_u32 = |v: u32| KrbTime::from_unix(i64::from(v));
    Ok(Tgt {
        crealm: cred.client.realm.clone(),
        cname: cred.client.flat(),
        ticket,
        session_key: cred.key.clone(),
        flags: cred.flags,
        authtime: from_u32(cred.authtime),
        endtime: from_u32(cred.endtime),
        renew_till: cred.renew_till.map(from_u32),
        raw_reply: Vec::new(),
        enc_rep_part_raw: Vec::new(),
    })
}

/// Escribe el `Tgt` en `path` como ccache FILE v4 con permisos 0600
/// (el equivalente exacto de lo que hace `kinit`: el fichero lleva la
/// clave de sesión y NO debe ser legible por otros).
pub fn save_tgt(path: &str, tgt: &Tgt) -> Result<()> {
    let cred = tgt_to_credential(tgt)?;
    let bytes = CcacheFile::single(cred).to_bytes().map_err(ClientError::from)?;
    write_private(path, &bytes)
}

/// Escribe bytes con 0600 en unix (ignorado donde no aplique; el proyecto
/// opera en unix — es el entorno del lab y del KDC real).
fn write_private(path: &str, bytes: &[u8]) -> Result<()> {
    let p = Path::new(path);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(p)?;
        f.write_all(bytes)?;
    }
    #[cfg(not(unix))]
    {
        let mut f = std::fs::File::create(p)?;
        f.write_all(bytes)?;
    }
    Ok(())
}

/// Carga el primer TGT real de un ccache (salta las entradas de
/// configuración `X-CACHECONF:` que kinit escribe).
pub fn load_tgt(path: &str) -> Result<Tgt> {
    let bytes = std::fs::read(path).map_err(|e| {
        ClientError::Krb5(charon_krb5::Krb5Error::BadCcache(format!(
            "no pude leer {path}: {e}"
        )))
    })?;
    let file = CcacheFile::parse(&bytes).map_err(ClientError::from)?;
    let cred = file.first_tgt().ok_or_else(|| {
        ClientError::Krb5(charon_krb5::Krb5Error::BadCcache(format!(
            "{path} no contiene ninguna credencial real (solo entradas de configuración)"
        )))
    })?;
    tgt_from_credential(cred)
}
