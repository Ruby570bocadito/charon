# ADR-001 — Codec ASN.1/DER propio para Kerberos

- Estado: aceptado
- Fecha: 2026-09-15
- Contexto: construcción de Charon, workbench de protocolo Kerberos

## Contexto

Todo mensaje Kerberos (RFC 4120) es DER: AS-REQ, TGS-REQ, tickets,
KRB-ERROR, PAC. Charon necesita controlar cada campo de esos mensajes —
etypes arbitrarios, PA-DATA custom, flags "imposibles", mensajes
deliberadamente torcidos para la matriz KDC (M4).

## Decisión

Implementar un codec DER mínimo (`charon-asn1`) en vez de usar una
librería ASN.1 genérica (rasn, kerberos-rs, asn1-rs).

Motivos:

1. **El control es el producto.** Las librerías imponen su modelo de
   tipos; pedir un etype 9999 o un PA-DATA no estándar con ellas es
   luchar contra la librería. Con codec propio, un mensaje es una lista
   de TLVs que Charon compone byte a byte.
2. **El learning es el entregable.** Escribir el codec es lo que hace
   que después se lean capturas de Kerberos con fluidez nativa.
3. **Superficie mínima.** Kerberos usa: INTEGER, BOOLEAN, OCTET STRING,
   BIT STRING, SEQUENCE, GeneralizedTime y tags context/application ≤ 30.
   El codec completo son ~500 líneas testables, no un framework.

## Frontera y decisiones internas

- Tags de forma larga (> 30): rechazados en encode (Kerberos no los usa;
  el máximo es `[APPLICATION 30]` KRB-ERROR).
- **Decode leniente, encode estricto.** En decode se aceptan enteros no
  mínimos, `[n]` primitivos donde toca construidos y otros vicios que
  cometen KDCs reales: Charon debe poder analizar implementaciones
  imperfectas (eso es exactamente la matriz KDC). En encode, canónico.
- Longitud indefinida (BER): rechazada, DER la prohíbe.
- Cota de 16 MiB por elemento como defensa ante entradas hostiles.

## Validación (cómo sabemos que es correcto)

1. Round-trips byte a byte + vectores X.690 en tests unitarios.
2. `openssl asn1parse` (implementación independiente) parsea la salida
   de Charon: test de integración `openssl_crosscheck.rs`.
3. Los bytes que produce el cliente deben ser aceptados por un KDC real
   (MIT krb5 en el lab) — validación end-to-end por fase.
4. Al llegar a crypto: los test vectors de los RFC 3962/4757.

## Consecuencias

- Esfuerzo inicial mayor que usar una librería; costo amortizado en la
  fase 1 porque todo lo demás (mensajes, crypto, ataques, traces) se
  apoya directamente en él.
- Riesgo de bugs sutiles mitigado por los cuatro oráculos anteriores.
