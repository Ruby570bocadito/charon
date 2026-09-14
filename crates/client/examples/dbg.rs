use charon_client::*;
fn main() {
    let conn = KdcConnection::new("127.0.0.1", 1088);
    let probe = probe_as_no_preauth(&conn, "jdoe", "LAB.LOCAL", &[18, 17]).unwrap();
    if let AsProbe::PreauthRequired { salts, raw } = probe {
        println!("25 con {} entradas de salt", salts.len());
        for s in &salts {
            println!("  etype {} salt {:02x?}", s.etype, s.salt.as_deref().unwrap_or(b"<ninguno>"));
        }
        let err = charon_krb5::KrbError::parse(&raw).unwrap();
        println!("e-data hex: {}", hex::encode(err.e_data.as_ref().unwrap()));
    } else {
        println!("probe inesperado");
    }
}
