# ROADMAP — CHARON

> *El barquero ya cruza el río con soltura. Este documento traza los
> siguientes viajes: dónde ensanchar el cauce, qué orillas nuevas tocar y
> cómo pulir el casco sin perder el rumbo que hace de Charon **arma y
> microscopio** a la vez.*

Este roadmap es **largo a propósito**. Está pensado para sobrevivir a varias
rondas de trabajo y para que cualquiera —tú dentro de seis meses, un
colaborador nuevo, un agente— pueda abrirlo y saber qué sigue, por qué, y qué
NO se va a hacer. No es un contrato: las prioridades se reordenan según lo que
aprendas del protocolo y del campo.

## Índice

1. [Principios rectores](#1-principios-rectores)
2. [Estado actual (baseline)](#2-estado-actual-baseline)
3. [Muros de scope: qué sigue fuera](#3-muros-de-scope-qué-sigue-fuera)
4. [Horizontes y milestones](#4-horizontes-y-milestones)
5. [H1 — Profundizar el stack de protocolo](#h1--profundizar-el-stack-de-protocolo)
6. [H2 — Nuevos primitivos ofensivos](#h2--nuevos-primitivos-ofensivos)
7. [H3 — El ángulo defensivo (blue team)](#h3--el-ángulo-defensivo-blue-team)
8. [H4 — La matriz KDC como investigación publicable](#h4--la-matriz-kdc-como-investigación-publicable)
9. [H5 — Calidad, pruebas e ingeniería](#h5--calidad-pruebas-e-ingeniería)
10. [H6 — Experiencia de usuario y CLI](#h6--experiencia-de-usuario-y-cli)
11. [H7 — Documentación y README](#h7--documentación-y-readme)
12. [H8 — Distribución y empaquetado](#h8--distribución-y-empaquetado)
13. [H9 — Laboratorio y reproducibilidad](#h9--laboratorio-y-reproducibilidad)
14. [V2 — Saltos grandes (PKINIT, cross-realm, Windows)](#v2--saltos-grandes)
15. [Tabla maestra de priorización](#tabla-maestra-de-priorización)
16. [Métricas de éxito](#métricas-de-éxito)

---

## 1. Principios rectores

Toda ampliación debe pasar estos cinco filtros. Si una funcionalidad no los
respeta, no entra —por muy llamativa que sea.

1. **Protocolo, no botón.** Cada feature debe exponer el cable: qué campos
   viajan, por qué, y qué pasa al tocarlos. Si una feature solo "hace el
   ataque" sin enseñar el protocolo, pertenece a Rubeus, no a Charon.
2. **Verificado contra realidad.** Nada se declara "hecho" sin validación
   contra un KDC real (MIT, el módulo test KDB, o AD) y, donde aplique,
   contra un oráculo independiente (impacket, `klist`/`kinit`, openssl,
   test vectors del RFC).
3. **Sin reimplementar primitivos criptográficos** (ADR-003). Se usan las
   crates de RustCrypto; Charon orquesta, no inventa AES.
4. **OPSEC explícito.** Cada primitivo documenta su huella: qué deja en los
   logs del KDC, qué eventos de Windows dispara, qué rota o no rota.
5. **Salida consumible.** Todo comando nuevo emite JSON estable (snake_case,
   campos dedicados) además del texto humano. La UI de máquina no se acopla
   a los tipos internos.

---

## 2. Estado actual (baseline)

Para fijar el punto de partida (sep. 2026):

- **Stack propio**: codec DER (ADR-001), crypto RFC (RC4-HMAC, AES-CTS),
  builders/parsers AS/TGS/AP/KRB-ERROR/PAC.
- **Primitivos**: enum, kerberoast (AES-first), AS-REP roast, pass-the-key,
  spray, S4U2Self, S4U2Proxy, RBCD puro, renovación de TGT.
- **Persistencia**: ccache FILE v4 (lee/escribe, interoperable con
  klist/kinit), keytab FILE v1/v2 (lee, autentica).
- **Observabilidad**: trace campo a campo (texto/JSON), matriz KDC (15
  sondas, dataset reproducible).
- **Infra**: 8 crates, CI con clippy `-D warnings`, lab MIT sin root (dos
  realms), capturas reales del README generadas por script.

Es una base sólida. El roadmap construye **encima**, no reescribe.

---

## 3. Muros de scope: qué sigue fuera

Estos límites del README se mantienen salvo que un milestone los mueva
explícitamente:

- ❌ **C2 / post-explotación / persistencia de host** — Charon es workbench
  de protocolo, no implante. Fuera para siempre.
- ❌ **Cracking** — la salida es formato hashcat; el cómputo es de hashcat.
  Fuera para siempre.
- ❌ **GUI de escritorio** — CLI + JSON. (Un TUI de inspección es zona gris;
  ver H6.)
- 🟡 **ADCS / PKINIT** — planificado para **V2**, no antes. Es un salto de
  scope grande (certificados, criptografía asimétrica) que merece su propia
  fase.
- 🟡 **Cross-realm / trusts** — V2. Requiere referrals y topología multi-KDC.

---

## 4. Horizontes y milestones

El roadmap se organiza en **horizontes** (H1–H9) que corren en paralelo, más
una fase **V2** de saltos grandes. Dentro de cada horizonte, los ítems llevan
etiqueta de tamaño: **[S]** días, **[M]** semana o dos, **[L]** varias
semanas, **[XL]** mes o más.

Sugerencia de secuencia inicial (las tres primeras rondas):

- **Ronda A** — cerrar deuda de robustez: fuzzing del codec (H5), `whoami`/
  `describe-ticket` (H6), golden-file tests del trace (H5), CHANGELOG (H7).
- **Ronda B** — primer primitivo nuevo de alto valor: **AP-REQ / uso de
  tickets de servicio** y **U2U** (H2), más el modo `--opsec-report` (H3).
- **Ronda C** — profundizar PAC (firmas, validación) (H1) y arrancar la
  matriz contra AD con GOAD (H4).

---

## H1 — Profundizar el stack de protocolo

El cimiento. Cuanto más completo el stack, más primitivos se vuelven triviales
encima.

- **[M] Firmas del PAC (server/KDC checksum).** Hoy el PAC se descifra y se
  lee; falta **validar y generar** los `SERVER_CHECKSUM` (tipo 6) y
  `KDC_CHECKSUM` (tipo 7), y el `TICKET_CHECKSUM` de S4U. Es la base para
  detectar/forjar PACs y para entender por qué un golden ticket "normal"
  revienta con PAC validation activada. Enlaza con MS-PAC §2.8.
- **[M] PAC completo: `LOGON_INFO` parseado.** Decodificar los buffers
  NDR del `KERB_VALIDATION_INFO` (SIDs, grupos, flags de cuenta) en vez de
  tratarlos como opacos. Habilita el trace de "qué grupos afirma este
  ticket" y es prerrequisito de cualquier trabajo sobre privilegios.
- **[S] Más etypes y checksums.** Completar AES128 donde falte, DES-CBC-MD5
  (solo para interoperar con KDCs antiguos y para la matriz; marcado como
  inseguro), y los checksums HMAC-SHA1-96 / HMAC-MD5 que falten.
- **[M] GSS-API wrapper (SPNEGO/Kerberos token).** Envolver el AP-REQ en el
  token GSS que esperan los servicios reales (LDAP, HTTP Negotiate, SMB).
  Abre la puerta a usar los tickets contra servicios de verdad en el lab.
- **[S] Cobertura ASN.1 restante.** `KRB-CRED` (para exportar/importar
  credenciales entre formatos), `AP-REP`, `KRB-PRIV`/`KRB-SAFE`. El codec
  ya está; son builders/parsers nuevos.
- **[M] Lectura de más formatos de credencial.** ccache **DIR:** y **KEYRING:**
  (al menos lectura), y keytab v1 en big/little endian. Export a `KRB-CRED`
  para interoperar con Rubeus/impacket.
- **[L] Soporte FAST (RFC 6113).** Armor de preauth. Es complejo pero es el
  futuro del preauth y cada vez más KDCs lo exigen; sin él, Charon quedará
  ciego ante entornos endurecidos. Candidato tardío de H1 o temprano de V2.

---

## H2 — Nuevos primitivos ofensivos

Siempre bajo el principio "protocolo, no botón": cada uno expone el cable.

- **[M] Uso real de tickets de servicio (AP-REQ end-to-end).** Hoy se
  obtienen tickets; falta **presentarlos** a un servicio y completar el
  intercambio AP. Con el wrapper GSS (H1), autenticarse contra LDAP/SMB del
  lab. Es el cierre natural del ciclo "pido ticket → lo uso".
- **[M] User-to-User (U2U).** `ENC-TKT-IN-SKEY`: pedir un TGS cifrado con la
  clave de sesión del TGT del destino en vez de con su clave de servicio.
  Relevante para kerberoasting de cuentas sin SPN y para entender MSSQL.
- **[M] Overpass-the-hash / pass-the-key extendido.** Ya existe pass-the-key;
  extender a flujo completo "clave → TGT → TGS → uso" y documentar la
  diferencia de huella frente a pass-the-ticket.
- **[M] Pass-the-ticket.** Inyectar un TGT/TGS externo (desde ccache o
  KRB-CRED) y operar con él sin recredencializar. El ccache ya se lee; es
  conectar la tubería.
- **[L] Forja de tickets (golden / silver) — SOLO lab.** Con las firmas del
  PAC de H1, forjar TGTs (golden, clave krbtgt) y TGS (silver, clave de
  servicio). **Gated tras muro ético explícito**: requiere la clave, es
  puramente educativo sobre *por qué* funcionan y *cómo se detectan* (PAC
  validation, tiempos imposibles, RC4 forzado). El trace debe señalar cada
  anomalía forjable. Este es el ítem más sensible del roadmap: entra solo
  con el ángulo defensivo (H3) delante, no detrás.
- **[M] Diamond/Sapphire ticket (educativo).** Variante de forja que modifica
  un PAC legítimo en vez de crearlo de cero — precisamente para enseñar por
  qué evade detecciones de "PAC demasiado limpio". Depende de H1 completo.
- **[S] Timeroasting / enumeración por reloj.** Ya se observa el skew en la
  matriz; convertirlo en primitivo de fingerprinting de versión/config.
- **[M] AS-REP roasting masivo + kerberoasting por LDAP.** Hoy se dan los
  usuarios/SPN a mano; añadir descubrimiento (requiere un cliente LDAP
  mínimo, que llega gratis con el wrapper GSS de H1).

---

## H3 — El ángulo defensivo (blue team)

Aquí es donde Charon se diferencia de verdad: no solo ataca, **explica la
huella**. Este horizonte convierte el "microscopio" en producto.

- **[M] `--opsec-report` global.** Cada comando puede emitir un informe de
  huella: qué eventos de Windows dispara (4768/4769/4770/4771), con qué
  encryption type, qué deja en el log del KDC MIT, qué se puede correlacionar.
  Ya existe el conocimiento disperso en `threat-model.md` y en los traces;
  esto lo centraliza y lo hace accionable para un defensor.
- **[M] Reglas de detección generadas.** A partir de cada primitivo, emitir
  esqueletos de reglas **Sigma** (y opcionalmente SPL/KQL) que detectarían
  esa técnica. "Aquí está el ataque, aquí está la regla que lo caza." Enorme
  valor didáctico y defensivo.
- **[S] Mapeo MITRE ATT&CK.** Etiquetar cada primitivo con su técnica
  (T1558.003 kerberoasting, T1558.004 AS-REP roasting, etc.) en la ayuda del
  comando y en el JSON.
- **[M] Modo "detección contrastada".** Ejecutar el ataque AES-first vs. el
  clásico RC4 y mostrar lado a lado qué evento genera cada uno — la tesis
  central del README ("sin downgrade → sin 4769 con 0x17") convertida en
  demo reproducible y medible.
- **[S] Documentar la cadena de detección del PAC.** Cómo PAC validation
  (KB5008380 / las mitigaciones de 2021-2022) rompe la forja — directamente
  conectado con H2 forja.

---

## H4 — La matriz KDC como investigación publicable

La matriz es research latente. Este horizonte la convierte en algo citable.

- **[M] Matriz contra Windows AD (GOAD).** El runner ya es agnóstico; falta
  ejecutarlo contra un DC real y publicar el dataset `windows-ad-20xx.json`.
  Documentar cada divergencia MIT↔AD (case folding, RC4, PAC, skew) con
  evidencia por cable.
- **[M] Matriz contra Heimdal.** Tercer punto de triangulación. Las
  divergencias de tres implementaciones son mucho más valiosas que de dos.
- **[M] Ampliar la batería a 40+ sondas.** Añadir: FAST sí/no, etypes
  exóticos, nombres con caracteres Unicode/NUL, PA-DATA en orden alterado,
  tickets expirados reenviados, renovación más allá del renew-till, SPN con
  mayúsculas. Cada sonda, un hallazgo potencial.
- **[M] Diff automático entre datasets.** `charon matrix diff a.json b.json`
  → tabla de divergencias legible. Convierte N datasets en conocimiento.
- **[L] Paper / blogpost "Cómo responden los KDCs".** El entregable final:
  un documento (en `docs/research/`) que presente los hallazgos con el
  dataset como anexo reproducible. Este es el tipo de artefacto que da
  credibilidad al proyecto entero.

---

## H5 — Calidad, pruebas e ingeniería

Deuda y blindaje. Nada glamuroso, todo necesario antes de crecer.

- **[M] Fuzzing del codec ASN.1 y los parsers.** `cargo-fuzz` sobre
  `asn1::DerReader` y los `parse_*` de `krb5`. Un parser de red que no se ha
  fuzzeado es una CVE esperando. Prioridad alta: es la superficie que toca
  datos hostiles.
- **[M] Golden-file tests del trace.** Fijar la salida de `trace` campo a
  campo contra ficheros de referencia, para que un cambio de formato no pase
  desapercibido. Snapshot testing (`insta`).
- **[S] Cobertura medida.** `cargo-llvm-cov` en CI, badge en el README,
  objetivo explícito por crate (p.ej. ≥85% en asn1/krb5/kcrypto).
- **[S] `cargo-deny` + auditoría de dependencias.** Licencias, advisories,
  duplicados. Para una herramienta de seguridad, la cadena de suministro
  propia importa.
- **[S] MSRV declarado y testeado.** El README dice Rust 1.85+; fijarlo en CI
  con una matriz (stable + MSRV) para que no se rompa silenciosamente.
- **[M] Property-based testing de la crypto.** `proptest`: encrypt∘decrypt =
  id, n-fold de longitudes arbitrarias, DK determinista. Complementa los
  test vectors.
- **[S] Separar tests que requieren KDC.** Feature flag o `#[ignore]` + un
  `cargo test --features lab` para que `cargo test` en limpio pase sin
  infraestructura. Clarifica qué es unit y qué es integración.
- **[M] Benchmarks del codec y la crypto.** `criterion`, para no regresar en
  rendimiento al refactorizar (importa en spray/roast masivos).

---

## H6 — Experiencia de usuario y CLI

Pulido que multiplica la utilidad sin cambiar el núcleo.

- **[S] `charon whoami --ccache` / `describe-ticket`.** Resumen humano de un
  ticket: para quién, de quién, flags, vigencia, enctype, qué afirma el PAC.
  La función que más se usa en un engagement real.
- **[S] Autocompletado de shell.** `clap_complete` → bash/zsh/fish/pwsh.
  Un comando `charon completions <shell>`.
- **[S] Páginas de manual.** `clap_mangen` → `man charon`. Y `--help` con
  ejemplos por subcomando (ya hay after_help; extenderlo a todos).
- **[M] TUI de inspección (zona gris de scope).** NO una GUI de ataque: un
  visor interactivo del trace y del ccache (`ratatui`) para navegar un
  mensaje campo a campo. Explícitamente read-only. Decidir con cuidado si
  cruza el muro "sin GUI" — probablemente sí porque sigue siendo inspección,
  no botón de ataque. **Requiere decisión de scope antes de empezar.**
- **[S] Colores y verbosidad consistentes.** `--quiet`, `--verbose`, respeto a
  `NO_COLOR`, `--no-color`. Auditar que todos los comandos los honren.
- **[S] Códigos de salida estables y documentados.** 0 éxito, y un catálogo
  (p.ej. 2 = error de red, 3 = error de protocolo KDC, 4 = credencial
  inválida) para scripting. Documentar en el README.
- **[S] `--debug-wire` / volcado hex.** Opción global que vuelca el DER crudo
  enviado/recibido a fichero, para alimentar `decode` y Wireshark.

---

## H7 — Documentación y README

El README ya es excelente. Esto lo lleva a nivel de proyecto de referencia.

- **[S] CHANGELOG.md.** Keep-a-Changelog + SemVer. Las "rondas" del historial
  git piden a gritos un changelog narrado.
- **[M] `docs/protocol/` — guías por mensaje.** Una página por intercambio
  (AS, TGS, AP, S4U) con el diagrama, los campos y el enlace al trace real.
  Charon enseña protocolo; que la doc lo haga también.
- **[S] `CONTRIBUTING.md` + `CODE_OF_CONDUCT.md`.** Cómo montar el lab, cómo
  correr los tests, el estilo (clippy -D warnings), el flujo de ADRs.
- **[S] `SECURITY.md`.** Política de reporte responsable — irónico y
  necesario para una herramienta de seguridad.
- **[M] Mini-sitio con mdBook.** Publicar `docs/` en GitHub Pages:
  ADRs, threat model, guías de protocolo, matriz. Un índice navegable.
- **[S] README en inglés (`README.en.md`).** El proyecto es excelente y el
  público de infosec es anglófono; un README en inglés multiplica el
  alcance. Mantener el español como primario (es la voz del autor).
- **[S] GIFs/capturas por primitivo.** Los scripts ya generan PNG/GIF;
  ampliar a una galería corta (uno por técnica) en `docs/assets/`.
- **[S] Tabla de "huella por técnica".** Resumen tabular de H3 en el README:
  técnica → evento Windows → regla Sigma → mitigación. Un golpe de vista.

---

## H8 — Distribución y empaquetado

Para que instalar Charon sea un `cargo install` o un binario.

- **[S] Publicar en crates.io.** Al menos el binario `charon` y las crates de
  biblioteca reutilizables (`charon-asn1`, `charon-kcrypto` son útiles por sí
  solas). Requiere pulir docs de API (`cargo doc`) y versionado.
- **[M] Releases con binarios precompilados.** GitHub Actions que compile
  para linux-gnu, linux-musl (estático), macOS (x86_64+arm64) y Windows, y
  cuelgue los binarios en cada tag. `cargo-dist` lo automatiza.
- **[S] Dockerfile + imagen.** Imagen mínima con el binario y, opcionalmente,
  el lab MIT preconfigurado para demos y CI.
- **[S] Verificación de releases.** Firmar los binarios (sigstore/cosign) y
  publicar checksums. Coherente con ser herramienta de seguridad.
- **[S] `cargo install --git` documentado** como ruta rápida mientras no esté
  en crates.io.

---

## H9 — Laboratorio y reproducibilidad

El lab es un activo; hacerlo más barato de levantar amplía la base de usuarios.

- **[M] Lab en contenedor.** `docker compose up` que levante los dos realms
  MIT (LAB.LOCAL + DELEG.LAB) sin compilar MIT a mano. El script actual es
  excelente pero pide paciencia; un contenedor baja la barrera a cero.
- **[M] Lab de AD reproducible.** Scripts/doc para un GOAD mínimo o un
  Samba-AD en contenedor, para que la matriz contra AD (H4) sea reproducible
  por cualquiera, no solo en el entorno del autor.
- **[S] Lab en CI.** Correr la batería de integración contra el KDC MIT dentro
  de GitHub Actions (el contenedor del punto anterior lo hace viable). Hoy
  esos tests son locales; en CI serían red de seguridad real.
- **[S] Fixtures versionadas.** Más keytabs/ccaches de referencia (de kinit
  real, de distintas versiones) como fixtures, para tests de interoperabilidad
  sin levantar KDC.
- **[S] `make lab` / `just`.** Un `justfile` que envuelva setup, status, stop,
  test — reduce el README de laboratorio a tres comandos memorizables.

---

## V2 — Saltos grandes

Fases que cambian el scope y merecen planificación propia. No empezar hasta
que H1 esté sólido.

- **[XL] PKINIT (RFC 4556) + ADCS.** Preauth con certificados. Requiere
  criptografía asimétrica (RSA/ECDH), parseo de certificados X.509, y abre
  toda la familia de ataques ADCS (ESC1–ESC8), UnPAC-the-hash, Shadow
  Credentials (msDS-KeyCredentialLink). Es, realistamente, medio proyecto
  nuevo. Empezar por PKINIT puro (autenticar con cert) antes que por los
  abusos de ADCS.
- **[XL] Cross-realm y trusts.** Referrals (TGS a krbtgt del realm destino),
  tickets inter-realm, y los ataques asociados (golden/diamond cross-realm,
  SID history). Requiere topología multi-KDC en el lab.
- **[L] Soporte parcial de SMB/LDAP como clientes de verdad.** No reimplementar
  los protocolos, sino lo mínimo para *usar* los tickets contra esos
  servicios en el lab (relink con H1 GSS + H2 AP-REQ). Marca la frontera: un
  cliente mínimo para demostrar el uso del ticket, nunca una navaja suiza de
  SMB.
- **[L] Biblioteca embebible estable (`libcharon`).** API pública versionada
  para que otras herramientas construyan encima. Requiere que H5 (calidad) y
  H8 (publicación) estén maduros.

---

## Tabla maestra de priorización

Orden sugerido por **valor / esfuerzo**, no por horizonte. "Valor" pondera
utilidad real + diferenciación + didáctica.

| # | Ítem | Horizonte | Tamaño | Valor | Notas |
|---|------|-----------|--------|-------|-------|
| 1 | Fuzzing del codec/parsers | H5 | M | Alto | Seguridad propia; superficie hostil |
| 2 | `whoami`/`describe-ticket` | H6 | S | Alto | Lo más usado en campo |
| 3 | `--opsec-report` + Sigma | H3 | M | Muy alto | La diferenciación central |
| 4 | AP-REQ end-to-end + GSS | H1/H2 | M | Muy alto | Cierra el ciclo pedir→usar |
| 5 | Firmas del PAC | H1 | M | Alto | Desbloquea forja y validación |
| 6 | Matriz contra AD (GOAD) | H4 | M | Alto | Research publicable |
| 7 | Pass-the-ticket | H2 | M | Alto | Tubería casi hecha (ccache) |
| 8 | Golden-file tests del trace | H5 | M | Medio | Blinda el formato |
| 9 | CHANGELOG + CONTRIBUTING | H7 | S | Medio | Higiene de proyecto |
| 10 | Lab en contenedor | H9 | M | Alto | Baja la barrera de entrada |
| 11 | U2U | H2 | M | Medio | Kerberoast sin SPN |
| 12 | Releases con binarios | H8 | M | Medio | Adopción |
| 13 | Forja golden/silver (lab) | H2 | L | Alto | Solo tras H3; muro ético |
| 14 | mdBook + README.en | H7 | M | Medio | Alcance |
| 15 | FAST | H1 | L | Alto | Futuro del preauth; complejo |
| … | PKINIT/ADCS | V2 | XL | Muy alto | Medio proyecto; planificar aparte |

---

## Métricas de éxito

Cómo saber que el roadmap avanza, más allá de "features cerradas":

- **Cobertura de protocolo**: nº de mensajes Kerberos que Charon construye *y*
  parsea *y* traza (hoy ~5; objetivo: el core RFC 4120 completo).
- **Triangulación**: nº de implementaciones de KDC en la matriz (hoy 1;
  objetivo 3: MIT, Heimdal, AD).
- **Verificación**: % de primitivos con test end-to-end contra KDC real en CI
  (hoy local; objetivo: en CI).
- **Didáctica**: nº de técnicas con huella documentada + regla de detección
  (hoy ~0 formalizadas; objetivo: todas).
- **Seguridad propia**: horas-CPU de fuzzing sin crash; dependencias sin
  advisories abiertos.
- **Adopción**: instalable por `cargo install` / binario / contenedor sin
  compilar MIT a mano.

---

*Este documento es vivo. Cada ronda que cierre ítems debería actualizarlo:
marcar lo hecho, reordenar lo pendiente, y anotar lo aprendido que cambie las
prioridades. El río sigue corriendo.*
