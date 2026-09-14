//! n-fold (RFC 3961 §5.1): expande/reduce `m` bits de entrada a `n` bits
//! de salida con contribución aproximadamente igual de cada bit de entrada.
//!
//! Algoritmo: replicar la entrada hasta la longitud LCM(n, m) rotando 13
//! bits a la derecha antes de cada repetición, y sumar los trozos de n
//! bits con suma en complemento a uno (acarreo envolvente).
//!
//! Porte del algoritmo de referencia de MIT krb5 (lib/crypto/krb/nfold.c),
//! validado con los vectores del Apéndice A de RFC 3961.

/// n-fold: `input` (bytes) → `out_bits` bits (múltiplo de 8).
pub fn nfold(input: &[u8], out_bits: usize) -> Vec<u8> {
    let in_bytes = input.len();
    let out_bytes = out_bits / 8;
    assert!(in_bytes > 0 && out_bytes > 0, "n-fold: longitudes nulas");

    // mcm(n, k) en bytes.
    let (mut a, mut b) = (out_bytes, in_bytes);
    while b != 0 {
        let c = b;
        b = a % b;
        a = c;
    }
    let lcm = out_bytes * in_bytes / a;

    let bits = in_bytes * 8; // bits de entrada
    let mut out = vec![0u8; out_bytes];
    let mut carry: u32 = 0;

    // Se recorre en orden inverso para que el acarreo envolvente caiga
    // en el byte más significativo (ver RFC 3961 §5.1 / MIT nfold.c).
    for i in (0..lcm).rev() {
        // Posición del bit más significativo del byte que se suma ahora,
        // contando la rotación de 13 bits por repetición.
        let msbit = ((bits - 1)
            + (bits + 13) * (i / in_bytes)
            + (in_bytes - (i % in_bytes)) * 8)
            % bits;
        // Extraer el byte rotado correspondiente (con envoltura circular).
        let idx1 = ((in_bytes - 1) - (msbit >> 3)) % in_bytes;
        let idx2 = (in_bytes - (msbit >> 3)) % in_bytes;
        let rotated = (((input[idx1] as u32) << 8) | input[idx2] as u32) >> ((msbit & 7) + 1) & 0xFF;

        // Suma con acarreo diferido.
        carry += rotated + out[i % out_bytes] as u32;
        out[i % out_bytes] = (carry & 0xFF) as u8;
        carry >>= 8;
    }

    // Acarreo final: suma en complemento a uno (el exceso se devuelve por
    // el extremo más significativo).
    if carry != 0 {
        for i in (0..out_bytes).rev() {
            carry += out[i] as u32;
            out[i] = (carry & 0xFF) as u8;
            carry >>= 8;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::nfold;
    use hex;

    fn f(input: &str, bits: usize, expected: &str) {
        let got = nfold(input.as_bytes(), bits);
        assert_eq!(hex::encode(got), expected, "{bits}-fold(\"{input}\")");
    }

    /// Vectores del Apéndice A de RFC 3961 (Horowitz / Josefsson).
    #[test]
    fn rfc3961_appendix_a_vectors() {
        f("012345", 64, "be072631276b1955");
        f("password", 56, "78a07b6caf85fa");
        f("Rough Consensus, and Running Code", 64, "bb6ed30870b7f0e0");
        f("password", 168, "59e4a8ca7c0385c3c37b3f6d2000247cb6e6bd5b3e");
        f(
            "MASSACHVSETTS INSTITVTE OF TECHNOLOGY",
            192,
            "db3b0d8f0b061e603282b308a50841229ad798fab9540c1b",
        );
        f("Q", 168, "518a54a215a8452a518a54a215a8452a518a54a215");
        f("ba", 168, "fb25d531ae8974499f52fd92ea9857c4ba24cf297e");

        // Casos "kerberos": cuando la salida es múltiplo de la entrada,
        // los primeros octets son la propia entrada.
        f("kerberos", 64, "6b65726265726f73");
        f("kerberos", 128, "6b65726265726f737b9b5b2b93132b93");
        f("kerberos", 168, "8372c236344e5f1550cd0747e15d62ca7a5a3bcea4");
        f(
            "kerberos",
            256,
            "6b65726265726f737b9b5b2b93132b935c9bdcdad95c9899c4cae4dee6d6cae4",
        );
    }
}
