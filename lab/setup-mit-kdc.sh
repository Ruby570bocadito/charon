#!/usr/bin/env bash
#
# CHARON — Laboratorio: MIT krb5 KDC local sin privilegios de root
#
# Compila e instala MIT krb5 1.21.3 en un prefijo local ($CHARON_LAB_DIR),
# crea el realm de laboratorio con usuarios diseñados (§11 del diseño) y
# arranca krb5kdc. Sin Docker, sin root, sin puertos privilegiados.
#
#   Realm:      LAB.LOCAL
#   Puerto:     1088 (el 88 requiere CAP_NET_BIND_SERVICE; Charon acepta --port)
#   Prefijo:    $CHARON_LAB_DIR/krb5 (estado desechable, fuera del repo)
#
# Requisitos: gcc, make, bison/yacc, m4, curl (herramientas de build).
#
# Usuarios diseñados:
#   jdoe                   usuario estándar con RC4+AES      Jdoe!Pass42
#   aesuser                cuenta AES-only (etype 18)        Aes!User01
#   mssql/srv01.lab.local  cuenta de servicio (kerberoast)   Mssql!Svc01
#   legacy                 cuenta RC4-only (kerberoast RC4)  Legacy!RC4
#   nopreauth              DONT_REQUIRE_PREAUTH (AS-REP roast) NoPre!Auth1
#
# Uso:  bash lab/setup-mit-kdc.sh          # compila, configura y arranca
#       bash lab/setup-mit-kdc.sh status   # comprueba si el KDC responde
#
set -euo pipefail

LAB_DIR="${CHARON_LAB_DIR:-$HOME/charon-lab}"
PREFIX="$LAB_DIR/krb5"
SRC="$LAB_DIR/src/krb5-1.21.3/src"
REALM="LAB.LOCAL"
KDC_PORT="${CHARON_KDC_PORT:-1088}"
ADMIN_PORT="${CHARON_ADMIN_PORT:-11088}"
VERSION="1.21.3"

ETC="$PREFIX/etc"
KDCSTATE="$PREFIX/var/krb5kdc"
LOG="$KDCSTATE"

find_bin() {
    for name in "$@"; do
        [ -x "$PREFIX/bin/$name" ] && { echo "$PREFIX/bin/$name"; return 0; }
        [ -x "$PREFIX/sbin/$name" ] && { echo "$PREFIX/sbin/$name"; return 0; }
    done
    return 1
}

build_krb5() {
    if [ -x "$PREFIX/sbin/krb5kdc" ]; then
        echo "[lab] MIT krb5 ya instalado en $PREFIX"
        return 0
    fi
    mkdir -p "$LAB_DIR/src"
    if [ ! -d "$SRC" ]; then
        echo "[lab] descargando krb5-$VERSION (tarball origen de Debian)..."
        curl -sSf -o "$LAB_DIR/src/krb5.tar.gz" \
            "http://deb.debian.org/debian/pool/main/k/krb5/krb5_${VERSION}.orig.tar.gz"
        tar xzf "$LAB_DIR/src/krb5.tar.gz" -C "$LAB_DIR/src"
    fi
    echo "[lab] configurando (prefix=$PREFIX)..."
    (cd "$SRC" && ./configure --prefix="$PREFIX" --without-system-verto \
        LDFLAGS="-Wl,-rpath,$PREFIX/lib") > "$LAB_DIR/configure.log" 2>&1
    echo "[lab] compilando (make -j2, tarda unos minutos)..."
    (cd "$SRC" && make -j2) > "$LAB_DIR/make.log" 2>&1
    (cd "$SRC" && make install) > "$LAB_DIR/install.log" 2>&1
    echo "[lab] instalado."
}

write_configs() {
    mkdir -p "$ETC" "$KDCSTATE"

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

    cat > "$KDCSTATE/kdc.conf" <<EOF
[kdcdefaults]
    kdc_ports = $KDC_PORT
    kdc_tcp_ports = $KDC_PORT

[realms]
    $REALM = {
        key_stash_file = $KDCSTATE/stash
        acl_file = $KDCSTATE/kadm5.acl
        max_life = 24h 0m 0s
        max_renewable_life = 7d 0h 0m 0s
        default_principal_flags = +preauth
    }

[logging]
    kdc = FILE:$LOG/krb5kdc.log
    default = FILE:$LOG/krb5lib.log
EOF

    echo "*/admin@$REALM *" > "$KDCSTATE/kadm5.acl"
}

create_db_and_principals() {
    local KDB5_UTIL KADMIN_LOCAL
    KDB5_UTIL="$(find_bin kdb5_util)"
    KADMIN_LOCAL="$(find_bin kadmin.local)"

    export KRB5_KDC_PROFILE="$KDCSTATE/kdc.conf"
    export KRB5_CONFIG="$ETC/krb5.conf"

    if [ ! -f "$KDCSTATE/principal" ]; then
        "$KDB5_UTIL" create -r "$REALM" -s -P 'charon-lab-master-key'
        echo "[lab] base de datos creada en $KDCSTATE"
    fi

    # krbtgt también necesita clave RC4: la clave de sesión del TGT se
    # elige entre los etypes pedidos ∩ claves del krbtgt; sin ella, las
    # peticiones RC4-only fallan con ETYPE_NOSUPP (igual que en AD real
    # cuando el servicio no tiene la clave).
    "$KADMIN_LOCAL" -r "$REALM" -q "cpw -keepold -randkey -e arcfour-hmac-md5:normal krbtgt/$REALM" >/dev/null

    # kadmin.local opera directamente sobre la BD (no necesita kadmind).
    # Nota: kadmin -q no interpreta comillas; las contraseñas van sin ellas.
    #
    # Enctypes EXPLÍCITOS en cada addprinc: MIT 1.21 crea por defecto
    # SOLO AES256+AES128 (verificado: str_conv/kadmin), y el diseño del
    # lab necesita RC4 en jdoe/mssql/nopreauth para los primitivos.
    # addprinc falla con usage error pero SALE 0 (silencioso), así que
    # add_principal_checked VERIFICA la existencia tras crear.
    #
    # nopreauth: "-no_preauth" NO es un flagspec válido de kadmin (la
    # tabla de atributos solo tiene preauth/requires_preauth —
    # lib/kadm5/str_conv.c): el prefijo '-' de -requires_preauth LIMPIA
    # el flag. Con el default_principal_flags=+preauth del kdc.conf, el
    # principal sale SIN preauth requerido, que es lo que el AS-REP
    # roasting necesita.
    add_principal_checked() {
        local desc="$1"; shift
        "$KADMIN_LOCAL" -r "$REALM" -q "$*" >/dev/null
        local principal
        principal="$(echo "$*" | awk '{print $NF}')"
        # kadmin.local sale 0 incluso cuando getprinc falla (bug de
        # usabilidad de kadmin): la única señal fiable es el listado.
        # addprinc añade el reino por defecto al nombre desnudo.
        if ! "$KADMIN_LOCAL" -r "$REALM" -q "listprincs" 2>/dev/null | grep -q "^${principal}@${REALM}\$"; then
            echo "ERROR [lab]: no se pudo crear $principal ($desc) — kadmin no se queja pero la BD no lo tiene" >&2
            exit 1
        fi
        echo "[lab] creado y verificado: $principal"
    }

    add_principal_checked "usuario estándar AES+RC4" \
        "addprinc -pw Jdoe!Pass42 -e aes256-cts-hmac-sha1-96:normal,aes128-cts-hmac-sha1-96:normal,arcfour-hmac-md5:normal jdoe"
    add_principal_checked "cuenta AES-only" \
        "addprinc -pw Aes!User01 -e aes256-cts-hmac-sha1-96:normal,aes128-cts-hmac-sha1-96:normal aesuser"
    add_principal_checked "servicio kerberoast AES+RC4" \
        "addprinc -pw Mssql!Svc01 -e aes256-cts-hmac-sha1-96:normal,arcfour-hmac-md5:normal mssql/srv01.lab.local"
    add_principal_checked "servicio RC4-only" \
        "addprinc -pw Legacy!RC4 -e arcfour-hmac-md5:normal legacy"
    add_principal_checked "sin preauth (AS-REP roast) AES+RC4" \
        "addprinc -pw NoPre!Auth1 -requires_preauth -e aes256-cts-hmac-sha1-96:normal,arcfour-hmac-md5:normal nopreauth"

    # El atributo de nopreauth es la pieza crítica del AS-REP roasting:
    # se comprueba que REQUIRES_PRE_AUTH está LIMPIO (kadmin saldría 0
    # incluso si el modprinc fallara).
    if "$KADMIN_LOCAL" -r "$REALM" -q "getprinc nopreauth" 2>/dev/null | grep -q "REQUIRES_PRE_AUTH"; then
        echo "ERROR [lab]: nopreauth sigue exigiendo preauth — el AS-REP roasting no tendrá dato" >&2
        exit 1
    fi
    echo "[lab] principales creados y verificados: jdoe aesuser mssql/srv01.lab.local legacy nopreauth"
}

start_kdc() {
    local KRB5KDC
    KRB5KDC="$(find_bin krb5kdc)"
    if pgrep -f "$PREFIX/sbin/krb5kdc" >/dev/null 2>&1; then
        echo "[lab] el KDC ya está en marcha"
        return 0
    fi
    export KRB5_KDC_PROFILE="$KDCSTATE/kdc.conf"
    export KRB5_CONFIG="$ETC/krb5.conf"
    "$KRB5KDC"
    sleep 1
    pgrep -f "$PREFIX/sbin/krb5kdc" >/dev/null 2>&1 || { echo "ERROR: krb5kdc no arrancó; mira $LOG/krb5kdc.log"; exit 1; }
    echo "[lab] krb5kdc escuchando en 127.0.0.1:$KDC_PORT (UDP+TCP)"
}

smoke_test() {
    local KINIT KLIST
    KINIT="$(find_bin kinit)"
    KLIST="$(find_bin klist)"
    local TGT="$LAB_DIR/jdoe.cc"
    export KRB5_CONFIG="$ETC/krb5.conf"
    rm -f "$TGT"
    printf '%s\n' 'Jdoe!Pass42' | "$KINIT" -c "$TGT" jdoe
    "$KLIST" -c "$TGT" | sed 's/^/[lab] /'
    "$KLIST" -c "$TGT" -e | sed 's/^/[lab] /'
    rm -f "$TGT"
}

status() {
    if pgrep -f "$PREFIX/sbin/krb5kdc" >/dev/null 2>&1; then
        echo "[lab] KDC activo en 127.0.0.1:$KDC_PORT"
    else
        echo "[lab] KDC parado"
        exit 1
    fi
}

case "${1:-install}" in
    install)
        build_krb5
        write_configs
        create_db_and_principals
        start_kdc
        smoke_test
        echo "[lab] Listo. Las contraseñas de este bloque son SOLO de laboratorio desechable."
        ;;
    status) status ;;
    *) echo "uso: $0 [install|status]"; exit 2 ;;
esac
