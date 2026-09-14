# Modelo de amenaza de Charon

## Qué es Charon (y qué no)

Charon es un **workbench de protocolo**: construye, envía, decodifica y
modifica mensajes Kerberos. Está pensado para:

1. **Pentesting autorizado** de dominios Active Directory y entornos MIT
   krb5 propios o contratados.
2. **Análisis defensivo**: reproducir las sondas de la matriz contra el KDC
   productivo para verificar detecciones y configuración.
3. **Investigación**: comparar implementaciones de KDC (M4) y buscar
   comportamientos anómalos con *disclosure responsable*.

No es: C2, post-explotación, persistencia, cracking de contraseñas (la
salida es formato hashcat; el cracking es de hashcat) ni sustituto de un
pentest completo.

## Qué se ve en el cable y en los logs (OPSEC por primitivo)

| Primitivo | Tráfico generado | Huella en el KDC / logs |
|---|---|---|
| Enum de usuarios | 1 AS-REQ por usuario, sin preauth | Ningún evento de fallo de autenticación en AD por diseño (error 25/6 no son eventos 4625); en MIT aparece en `krb5kdc.log` a nivel info |
| Kerberoasting | 1 AS-REQ (TGT) + 1 TGS-REQ por SPN | Evento 4769 por SPN; con AES-first el etype del 4769 es 0x12 (sin indicador de downgrade); en MIT, entrada TGS_REQ ISSUE |
| AS-REP roast | 1 AS-REQ por cuenta sondeada | Las cuentas con `DONT_REQUIRE_PREAUTH` devuelven material crackeable: 4768 normal; el primitivo no fuerza fallos |
| Pass-the-key | 1 AS-REQ con preauth válido | Indistinguible de un login legítimo con contraseña (misma huella); el uso de la clave no se distingue en el cable |
| S4U2Self | 1 TGS-REQ con PA-FOR-USER | Evento 4769 con S4U en AD; en MIT, entrada TGS_REQ ISSUE con nombre del servicio |
| Matriz | batería de sondas deliberadamente inválidas | Entradas de error en el log del KDC: **no ejecutar contra producción sin ventaja de cambio** |

## Datos sensibles manejados

- **Contraseñas**: se aceptan por flag `--password` (visible en `ps` para el
  mismo usuario) o por la variable de entorno `CHARON_PASSWORD`
  (recomendado). No se escriben en disco, logs ni traces.
- **Claves (NT hash / AES)**: entrada por `--nt-hash`/`--aes-key` o
  derivadas en memoria. Nunca se persisten.
- **Tickets y claves de sesión**: permanecen en memoria del proceso; los
  `traces/` publicados contienen tráfico ya capturado de laboratorio
  desechable.
- El dataset de la matriz contiene **solo metadatos de comportamiento**
  (códigos de error, textos del KDC), nunca credenciales.

## Superficie de riesgo del propio código

- Parser DER **leniente** en decode (ADR-001): procesa bytes no confiados
  con cotas de tamaño (16 MiB) y sin allocations sin límite.
- Sin `unsafe` en los crates del workspace.
- Comparaciones de checksum en tiempo constante (`kcrypto::ct_eq`).
- El laboratorio (`lab/`) genera contraseñas fijas documentadas: es
  **desechable por diseño** y no debe exponerse a redes ajenas.

## Divulgación responsable

Si la matriz encuentra un comportamiento anómalo explotable en una
implementación concreta (Samba, MIT, Heimdal), el procedimiento es:
documentar la sonda mínima reproducible, notificar a los mantenedores del
producto afectado y publicar el dataset **sin** el detalle explotable hasta
que exista parche o plazo vencido.
