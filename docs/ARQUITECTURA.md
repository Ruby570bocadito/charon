# Arquitectura de CHARON

CHARON no usa ninguna librería de Kerberos: todo el protocolo, desde el codec
ASN.1 hasta los mensajes AS/TGS, está construido desde el *wire format*. El
código se organiza como un **workspace Rust de 8 crates**, cada uno una capa
del protocolo. La regla es estricta: cada capa solo depende de las de debajo.

## La pila, de abajo arriba

```text
┌────────────────────────────────────────────────┐
│  charon · binario CLI (13 subcomandos)           │  ← la única cara visible
└────────────────────────────────────────────────┘
        │  attacks · trace · matrix                    ← capa de uso
        ▼
┌────────────────────────────────────────────────┐
│  client   · driver KDC (UDP/TCP 88)              │ ┐
│  krb5     · mensajes AS/TGS · PAC · ccache       │ │ pila de protocolo
│  kcrypto  · cripto Kerberos (AES, RC4-HMAC, RFC) │ │ propia, desde el cable
│  asn1     · codec DER propio                     │ ┘
└────────────────────────────────────────────────┘
```

Si lees el proyecto de abajo arriba, deja de parecer un montón de carpetas
sueltas: es una tubería donde cada crate resuelve un problema y se lo entrega
al de arriba.

## Capa 1 — fundamentos del cable

### `asn1` — el alfabeto

Codec DER propio (ADR-001). Kerberos viaja codificado en ASN.1/DER; este crate
es el que convierte bytes crudos en estructuras y viceversa. Validado por
cross-check contra `openssl asn1parse` para garantizar que lo que emite es DER
canónico de verdad, no una aproximación.

- **Entra**: `&[u8]` crudos del socket, o estructuras a serializar.
- **Sale**: tipos tipados (tags, longitudes, enteros, strings, secuencias).
- **Clave del diseño**: es DER *canónico* (longitudes mínimas, orden estricto),
  porque un KDC real rechaza cualquier desviación.

### `kcrypto` — cómo se cifra

Las construcciones criptográficas de Kerberos sobre primitivos auditados de
RustCrypto (ADR-003 prohíbe reimplementar los primitivos). Aquí viven:
`n-fold`, derivación de clave (DK), modo CTS, checksums, `string-to-key`,
RC4-HMAC (RFC 4757) y AES-CTS-HMAC-SHA1 (RFC 3961/3962). Validado con los test
vectors de los propios RFC y contra un KDC real.

- **Entra**: contraseñas, salts, claves, bloques a cifrar/descifrar.
- **Sale**: claves de Kerberos, textos cifrados, checksums verificables.

## Capa 2 — el idioma del protocolo

### `krb5` — las frases

Construye y parsea los mensajes del protocolo: AS-REQ/REP, TGS-REQ/REP,
AP-REQ, KRB-ERROR, y el PAC (MS-PAC). También implementa dos formatos de
persistencia de MIT: **ccache FILE v4** (verificado contra `klist`/`kinit`
reales) y **keytab FILE v1/v2** (verificado contra `ktutil`/`ktadd`).

- **Entra**: tipos de `asn1` + claves de `kcrypto`.
- **Sale**: mensajes Kerberos listos para enviar, o ya descifrados y
  comprensibles.

### `client` — la boca que habla

El driver que realmente habla con el KDC: transporte UDP/TCP en el puerto 88,
gestión de la sesión, el flujo AS→TGS, S4U2Self, S4U2Proxy, renovación de TGT
y escritura/lectura del ccache. Es la frontera entre "sé construir un mensaje"
y "sé mantener una conversación con un KDC real".

- **Entra**: mensajes de `krb5`, parámetros de conexión.
- **Sale**: respuestas del KDC, tickets, sesiones persistidas.

## Capa 3 — para qué sirve todo esto

### `attacks` — los primitivos ofensivos

Orquesta las capas de abajo en ataques concretos: enumeración de usuarios,
kerberoasting (AES-first), AS-REP roasting, pass-the-key y password spraying.
Produce salida en formato hashcat lista para crackear offline.

### `trace` — el microscopio

Toma cualquier mensaje decodificado y lo explica **campo a campo**, con la cita
exacta del RFC y comentarios en español. Es el diferencial de CHARON: no solo
ejecutas el ataque, ves el protocolo mientras cruza el río. Emite texto
coloreado o JSON.

### `matrix` — el comparador (research)

Lanza una batería de sondas (válidas, casi válidas y deliberadamente torcidas)
contra un KDC y vuelca un dataset JSON reproducible de cómo se comporta esa
implementación. Es lo que convierte a CHARON también en una herramienta de
investigación del protocolo.

## Capa 4 — la cara visible

### `charon` — el binario CLI

Lo único que el usuario ejecuta. Une todas las capas en ~13 subcomandos
(`enum`, `kerberoast`, `asreproast`, `passthekey`, `spray`, `as`, `renew`,
`s4u2self`, `s4u2proxy`, `ccache`, `keytab`, `decode`, `matrix`) con salida
uniforme en texto o JSON.

## Decisiones de diseño (ADRs)

Las decisiones estructurales están documentadas en [`adr/`](adr/):

- **ADR-001** — codec DER propio en lugar de una librería ASN.1 existente.
- **ADR-002** — Rust como lenguaje.
- **ADR-003** — frontera criptográfica: se usan primitivos auditados de
  RustCrypto, pero las *construcciones* del protocolo son propias.

## Por qué esta separación importa

El valor de la tubería no es estético. Cada crate se puede testear de forma
aislada contra un oráculo independiente: `asn1` contra `openssl`, `kcrypto`
contra los test vectors de los RFC, `krb5`/`client` contra un KDC MIT real e
`impacket` como segundo oráculo. Por eso cada capa es tan fina y tan estricta:
un bug en `asn1` se caza en `asn1`, no tres capas más arriba en un ataque que
"a veces falla".
