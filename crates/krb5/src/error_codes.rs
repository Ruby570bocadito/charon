//! Códigos de error KDC (RFC 4120 §5.9.1 / §7.5.8) y lo que cada uno
//! filtra: la tabla que convierte a Charon en un oráculo de enumeración.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KdcErrorCode {
    pub code: i32,
    pub name: &'static str,
    /// Qué filtra el error para un atacante/defensor.
    pub leak: &'static str,
}

pub const KDC_ERR_NONE: i32 = 0;
pub const KDC_ERR_NAME_EXP: i32 = 1;
pub const KDC_ERR_SERVICE_EXP: i32 = 2;
pub const KDC_ERR_BAD_PVNO: i32 = 3;
pub const KDC_ERR_C_OLD_MAST_KVNO: i32 = 4;
pub const KDC_ERR_S_OLD_MAST_KVNO: i32 = 5;
pub const KDC_ERR_PRINCIPAL_UNKNOWN: i32 = 6;
pub const KDC_ERR_S_PRINCIPAL_UNKNOWN: i32 = 7;
pub const KDC_ERR_PRINCIPAL_NOT_UNIQUE: i32 = 8;
pub const KDC_ERR_NULL_KEY: i32 = 9;
pub const KDC_ERR_CANNOT_POSTDATE: i32 = 10;
pub const KDC_ERR_NEVER_VALID: i32 = 11;
pub const KDC_ERR_POLICY: i32 = 12;
pub const KDC_ERR_BADOPTION: i32 = 13;
pub const KDC_ERR_ETYPE_NOTSUPP: i32 = 14;
pub const KDC_ERR_SUMTYPE_NOSUPP: i32 = 15;
pub const KDC_ERR_PADATA_TYPE_NOSUPP: i32 = 16;
pub const KDC_ERR_TRTYPE_NOSUPP: i32 = 17;
pub const KDC_ERR_CLIENT_REVOKED: i32 = 18;
pub const KDC_ERR_SERVICE_REVOKED: i32 = 19;
pub const KDC_ERR_TGT_REVOKED: i32 = 20;
pub const KDC_ERR_CLIENT_NOTYET: i32 = 21;
pub const KDC_ERR_SERVICE_NOTYET: i32 = 22;
pub const KDC_ERR_KEY_EXPIRED: i32 = 23;
pub const KDC_ERR_PREAUTH_FAILED: i32 = 24;
pub const KDC_ERR_PREAUTH_REQUIRED: i32 = 25;
pub const KDC_ERR_SERVER_NAME_NOMATCH: i32 = 26;
pub const KDC_ERR_MUST_USE_USER2USER: i32 = 27;
pub const KDC_ERR_PATH_NOT_ACCEPTED: i32 = 28;
pub const KDC_ERR_SVC_UNAVAILABLE: i32 = 29;
pub const KRB_AP_ERR_SKEW: i32 = 37;
pub const KRB_AP_ERR_REPEAT: i32 = 34;
pub const KRB_AP_ERR_NOT_US: i32 = 31;
pub const KRB_AP_ERR_TKT_EXPIRED: i32 = 32;
pub const KRB_AP_ERR_TKT_NYV: i32 = 33;
pub const KRB_AP_ERR_BADMATCH: i32 = 35;
pub const KRB_AP_ERR_BADVERSION: i32 = 39;
pub const KRB_AP_ERR_MSG_TYPE: i32 = 40;
pub const KRB_AP_ERR_MODIFIED: i32 = 41;
pub const KRB_AP_ERR_BADKEYVER: i32 = 44;
pub const KRB_AP_ERR_NOKEY: i32 = 45;
pub const KRB_ERR_RESPONSE_TOO_BIG: i32 = 52;

/// Tabla de códigos con su lectura ofensiva/defensiva.
pub fn describe(code: i32) -> KdcErrorCode {
    use {KDC_ERR_PRINCIPAL_UNKNOWN as UNKNOWN, KDC_ERR_PREAUTH_FAILED as PREAUTH_FAILED, KDC_ERR_PREAUTH_REQUIRED as PREAUTH_REQUIRED};
    match code {
        0 => KdcErrorCode { code, name: "KDC_ERR_NONE", leak: "éxito" },
        UNKNOWN => KdcErrorCode { code, name: "KDC_ERR_PRINCIPAL_UNKNOWN", leak: "el principal NO existe (enumeración)" },
        PREAUTH_FAILED => KdcErrorCode { code, name: "KDC_ERR_PREAUTH_FAILED", leak: "el principal EXISTE y la contraseña/clave es incorrecta" },
        PREAUTH_REQUIRED => KdcErrorCode { code, name: "KDC_ERR_PREAUTH_REQUIRED", leak: "el principal EXISTE y requiere preauth; regala el salt en PA-ETYPE-INFO2" },
        7 => KdcErrorCode { code, name: "KDC_ERR_S_PRINCIPAL_UNKNOWN", leak: "el SPN NO existe (kerberoast: SPN erróneo)" },
        13 => KdcErrorCode { code, name: "KDC_ERR_BADOPTION", leak: "opción rechazada: típico de S4U2Proxy sin delegación permitida" },
        14 => KdcErrorCode { code, name: "KDC_ERR_ETYPE_NOTSUPP", leak: "etype no soportado: huella de configuración de enctypes" },
        15 => KdcErrorCode { code, name: "KDC_ERR_SUMTYPE_NOSUPP", leak: "tipo de checksum no soportado" },
        16 => KdcErrorCode { code, name: "KDC_ERR_PADATA_TYPE_NOSUPP", leak: "tipo de PA-DATA no soportado: huella de implementación" },
        18 => KdcErrorCode { code, name: "KDC_ERR_CLIENT_REVOKED", leak: "cuenta deshabilitada/bloqueada (existe)" },
        23 => KdcErrorCode { code, name: "KDC_ERR_KEY_EXPIRED", leak: "contraseña caducada (la cuenta existe)" },
        24 => KdcErrorCode { code, name: "KDC_ERR_PREAUTH_FAILED", leak: "preauth incorrecto" },
        34 => KdcErrorCode { code, name: "KRB_AP_ERR_REPEAT", leak: "replay: authenticator ya visto (caché de replays)" },
        37 => KdcErrorCode { code, name: "KRB_AP_ERR_SKEW", leak: "reloj desincronizado: revela tolerancia de skew" },
        52 => KdcErrorCode { code, name: "KRB_ERR_RESPONSE_TOO_BIG", leak: "respuesta grande: fuerza TCP (UDP truncado)" },
        _ => KdcErrorCode { code, name: "DESCONOCIDO", leak: "código sin catálogo en Charon (apúntalo en la matriz)" },
    }
}
