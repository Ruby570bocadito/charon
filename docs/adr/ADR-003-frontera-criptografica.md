# ADR-003 — Frontera criptográfica: primitivos externos, construcciones propias

- Estado: aceptado
- Fecha: 2026-09-15

## Contexto

Charon implementa la crypto de Kerberos: string-to-key, key derivation,
cifrado y checksums de los etypes 23 (RC4-HMAC, RFC 4757) y 17/18
(AES-CTS-HMAC-SHA1-96, RFC 3961/3962). Hay una línea que separa lo
correcto de lo incorrecto en este proyecto.

## Decisión

**NO se reimplementan primitivos.** AES, SHA1, HMAC, MD4, MD5, RC4 y
PBKDF2 vienen de crates auditados de RustCrypto (`aes`, `sha1`, `hmac`,
`md-4`, `md-5`, `rc4`, `pbkdf2`). "Roll your own crypto" de primitivos
es una red flag.

**SÍ se implementan las construcciones del protocolo** (eso ES el
proyecto, según los RFC):

- `string-to-key`: RC4 = MD4(UTF-16LE(password)); AES = PBKDF2-HMAC-SHA1
  (UTF-16LE(password), salt, iteraciones, keylen) — RFC 3962 §3.
- n-fold y DK()/DR(): derivación de claves por key usage — RFC 3961 §5.
- CBC-CTS: el modo de cifrado de AES-Kerberos — RFC 3962 §4.
- Perfiles de cifrado/checksum: confounder, padding, truncado HMAC a 96
  bits, separación de key usages — RFC 3961 §5.3 y RFC 4757 §5.
- La distinción de key usage por tipo de mensaje (3, 2, 8, 9, 7, 11...).

Estas construcciones no son "crypto propio": son pegamento de
especificación, y cada una se valida contra dos oráculos:

1. **Test vectors de los RFC** (3962 App. A para string-to-key) y de
   implementaciones de referencia.
2. **Un KDC real**: si el KDC MIT krb5 del laboratorio acepta el
   pre-auth que produce Charon y Charon descifra el AS-REP que devuelve,
   toda la cadena (string-to-key → DK → CTS → HMAC) es correcta
   end-to-end.

## Consecuencias

- `Cargo.toml` documenta cada primitivo y por qué está ahí.
- Cualquier duda de implementación se resuelve contra el RFC citado en
  el doc-comment de la función, nunca "a ojo".
- Los fallos de validación se consideran bugs de Charon, nunca del
  primitivo externo.
