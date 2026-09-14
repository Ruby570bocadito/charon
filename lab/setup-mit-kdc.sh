#!/usr/bin/env bash
#
# CHARON — Laboratorio: MIT krb5 KDC local sin privilegios de root
#
# Monta un KDC MIT krb5 REAL (binarios oficiales de Debian extraídos en un
# prefijo local) para validar el stack de Charon contra una implementación
# de referencia. Sin Docker, sin root, sin puertos privilegiados.
#
#   Realm:      LAB.LOCAL
#   Puerto:     1088 (el 88 requiere CAP_NET_BIND_SERVICE; Charon acepta --port)
#   Estado:     $CHARON_LAB_DIR (fuera del repo; datos desechables de laboratorio)
#
# Usuarios diseñados (§11 del diseño):
#   jdoe                usuario estándar con RC4+AES        Jdoe!Pass42
#   aesuser             cuenta AES-only (etype 18)          Aes!User01
#   mssql/srv01.lab.local  cuenta de servicio (kerberoast)  Mssql!Svc01
#   legacy              cuenta RC4-only (kerberoast RC4)    Legacy!RC4
#   nopreauth           DONT_REQUIRE_PREAUTH (AS-REP roast) NoPre!Auth1
#
# Uso:  bash lab/setup-mit-kdc.sh          # instala, configura y arranca
#       bash lab/setup-mit-kdc.sh status   # comprueba si el KDC responde
#
set -euo pipefail

LAB_DIR="${CHARON_LAB_DIR:-$HOME/charon-lab}"
PKG_DIR="${CHARON_LAB_PKG_DIR:-/tmp/charon-pkgs}"
REALM="LAB.LOCAL"
KDC_PORT="${CHARON_KDC_PORT:-1088}"
ADMIN_PORT="${CHARON_ADMIN_PORT:-11088}"
ROOTFS="$LAB_DIR/rootfs"
ETC="$LAB_DIR/etc"
VAR="$LAB_DIR/var/krb5kdc"
LOG="$LAB_DIR/var/log"
LIBS="$ROOTFS/usr/lib/x86_64-linux-gnu"

export LD_LIBRARY_PATH="$LIBS${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
export KRB5_CONFIG="$ETC/krb5.conf"
export KRB5_KDC_PROFILE="$ETC/kdc.conf"

# Debian instala algunos clientes con sufijo alternativo (.mit); resolvemos el
# primero que exista.
find_bin() {
    for name in "$@"; do
        [ -x "$ROOTFS/usr/bin/$name" ] && { echo "$ROOTFS/usr/bin/$name"; return 0; }
        [ -x "$ROOTFS/usr/sbin/$name" ] && { echo "$ROOTFS/usr/sbin/$name"; return 0; }
    done
    return 1
}

download_pkgs() {
    mkdir -p "$PKG_DIR" && cd "$PKG_DIR"
    local pkgs=(krb5-kdc krb5-admin-server krb5-user libverto1t64 libss2
                libk5crypto3 libkrb5-3 libkrb5support0 libgssapi-krb5-2)
    local p
    # apt-get download no necesita root; ignoramos los paquetes que ya vengan
    # en el sistema base o con otro nombre en la distro.
    for p in "${pkgs[@]}"; do
        apt-get download "$p" >/dev/null 2>&1 || true
    done
    ls ./*.deb >/dev/null 2>&1 || { echo "ERROR: no se descargó ningún .deb (¿apt sin listas de paquetes?)"; exit 1; }
}

write_configs() {
    mkdir -p "$ETC" "$VAR" "$LOG"

    cat > "$ETC/krb5.conf" <<EOF
[libdefaults]
    default_realm = $REALM
    dns_lookup_realm = false
    dns_lookup_kdc = false
    rdns = false
    ticket_lifetime = 24h
    forwardable = true
    udp_preference_limit = 0
    allow_weak_crypto = true

[realms]
    $REALM = {
        kdc = 127.0.0.1:$KDC_PORT
        admin_server = 127.0.0.1:$ADMIN_PORT
    }

[domain_realm]
    .lab.local = $REALM
    lab.local = $REALM

[logging]
    default = FILE:$LOG/krb5lib.log
EOF

    cat > "$ETC/kdc.conf" <<EOF
[kdcdefaults]
    kdc_ports = $KDC_PORT
    kdc_tcp_ports = $KDC_PORT

[realms]
    $REALM = {
        database_module = CHARON_DB
        key_stash_file = $VAR/stash
        acl_file = $ETC/kadm5.acl
        max_life = 24h 0m 0s
        max_renewable_life = 7d 0h 0m 0s
        default_principal_flags = +preauth
    }

[dbmodules]
    CHARON_DB = {
        db_module_dir = $LIBS/krb5/plugins/kdb
        database_name = $VAR/principal
    }

[logging]
    kdc = FILE:$LOG/krb5kdc.log
    default = FILE:$LOG/krb5lib.log
EOF

    touch "$ETC/kadm5.acl"
    echo "*/admin@$REALM *" > "$ETC/kadm5.acl"
}

create_db_and_principals() {
    local KDB5_UTIL KADMIN_LOCAL
    KDB5_UTIL="$(find_bin kdb5_util)"
    KADMIN_LOCAL="$(find_bin kadmin.local)"

    if [ ! -f "$VAR/principal" ]; then
        "$KDB5_UTIL" create -r "$REALM" -s -P 'charon-lab-master-key'
        echo "[lab] base de datos creada en $VAR"
    fi

    # kadmin.local opera directamente sobre la BD (no necesita kadmind).
    local KADMIN=("$KADMIN_LOCAL" -r "$REALM")
    # Nota: kadmin -q no interpreta comillas; las contraseñas van sin ellas.
    "${KADMIN[@]}" -q "addprinc -pw Jdoe!Pass42 jdoe" >/dev/null
    "${KADMIN[@]}" -q "addprinc -pw Aes!User01 -e aes256-cts-hmac-sha1-96:normal,aes128-cts-hmac-sha1-96:normal aesuser" >/dev/null
    "${KADMIN[@]}" -q "addprinc -pw Mssql!Svc01 mssql/srv01.lab.local" >/dev/null
    "${KADMIN[@]}" -q "addprinc -pw Legacy!RC4 -e arcfour-hmac-md5:normal legacy" >/dev/null
    "${KADMIN[@]}" -q "addprinc -no_preauth -pw NoPre!Auth1 nopreauth" >/dev/null
    echo "[lab] principales creados: jdoe aesuser mssql/srv01.lab.local legacy nopreauth"
}

start_kdc() {
    local KRB5KDC
    KRB5KDC="$(find_bin krb5kdc)"
    if pgrep -f "$KRB5KDC" >/dev/null 2>&1; then
        echo "[lab] el KDC ya está en marcha"
        return 0
    fi
    "$KRB5KDC"
    sleep 1
    pgrep -f "$KRB5KDC" >/dev/null 2>&1 || { echo "ERROR: krb5kdc no arrancó; mira $LOG/krb5kdc.log"; exit 1; }
    echo "[lab] krb5kdc escuchando en 127.0.0.1:$KDC_PORT (UDP+TCP)"
}

smoke_test() {
    local KINIT KLIST
    KINIT="$(find_bin kinit kinit.mit)"
    KLIST="$(find_bin klist klist.mit)"
    local TGT="$LAB_DIR/jdoe.cc"
    rm -f "$TGT"
    printf '%s\n' 'Jdoe!Pass42' | "$KINIT" -c "$TGT" jdoe
    "$KLIST" -c "$TGT" | sed 's/^/[lab] /'
    rm -f "$TGT"
}

status() {
    if pgrep -f "$(find_bin krb5kdc)" >/dev/null 2>&1; then
        echo "[lab] KDC activo en 127.0.0.1:$KDC_PORT"
    else
        echo "[lab] KDC parado"
        exit 1
    fi
}

case "${1:-install}" in
    install)
        echo "[lab] descargando binarios MIT krb5 de Debian (sin root)..."
        download_pkgs
        mkdir -p "$ROOTFS"
        for f in "$PKG_DIR"/*.deb; do dpkg-deb -x "$f" "$ROOTFS"; done
        write_configs
        create_db_and_principals
        start_kdc
        smoke_test
        echo "[lab] Listo. Credenciales de laboratorio en lab/setup-mit-kdc.sh (solo para este entorno desechable)."
        ;;
    status) status ;;
    *) echo "uso: $0 [install|status]"; exit 2 ;;
esac
