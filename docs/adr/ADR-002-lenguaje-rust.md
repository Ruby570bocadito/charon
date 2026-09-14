# ADR-002 — Lenguaje: Rust

- Estado: aceptado
- Fecha: 2026-09-15

## Contexto

Charon es un binario único con siete módulos: stack de protocolo,
primitivos ofensivos, trace y matriz KDC. Se barajaron Go y Rust.

## Decisión

Rust (edición 2021, toolchain estable).

Nota de honestidad: la primera propuesta del proyecto decía Go. Con la
extensión condicional del Hito C (agente LLM en Rust) sobre la mesa,
Rust es la mejor llamada: un solo lenguaje para todo y skill existente
que se reutiliza. Cambiar una decisión técnica con información nueva —y
documentarlo— es parte del proceso; el coste (iteración algo más lenta)
se asume a sabiendas.

## Motivos técnicos

1. **Precisión de bytes sin coste de abstracción.** El proyecto entero
   es manipular buffers con offsets; `&[u8]`, slicing y tipos de
   tamaño fijo hacen el wire format natural.
2. **Seguridad de memoria sin GC** en una herramienta que parsea
   entradas hostiles (respuestas de KDCs controlados por terceros).
3. **Workspace de crates** que mapea 1:1 a los módulos M1–M4 con
   fronteras de compilación reales.
4. **RustCrypto** da primitivos auditados (AES, SHA1, HMAC, MD4, RC4,
   PBKDF2) que ADR-003 exige no reimplementar.

## Consecuencias

- Iteración algo más lenta que Go para prototipar; se paga consciente.
- Distribución: binario estático por plataforma, sin runtime.
