#!/usr/bin/env bash
#
# CHARON — Laboratorio: segundo KDC con el módulo test KDB de MIT
#
# El backend db2 del primer KDC (LAB.LOCAL) NO puede autorizar delegación:
# la política allowed_to_delegate vive en el KDB, y db2 solo la implementa
# con LDAP o el módulo test de MIT (docs/threat-model.md). Este script monta
# un SEGUNDO realm servido por el módulo test KDB (plugins/kdb/test, leído
# de la fuente: kdb_test.c), que sí trae la tabla `delegation` y sirve para
# completar el ciclo end-to-end de `charon s4u2proxy`:
#
#   TGT(service/1) → evidence S4U2Self(user) → S4U2Proxy(service/2)
#   → ticket final cifrado con la clave de service/2 con el PAC de user.
#
# El módulo test es READ-ONLY y no usa base de datos: los principals viven
# en TEXTO PLANO del kdc.conf y sus claves son DETERMINISTAS (hash SHA-1 de
# "kvno enctype salttype principal reino", make_keyblock, kdb_test.c 191-218).
# No son claves derivadas de contraseñas: kinit con contraseña NO funciona
# contra este realm y el material correcto se obtiene exportando con
# `kadmin.local ktadd -norandkey` (el módulo incluye mod-princ data justo
# para que la extracción funcione, kdb_test.c 484-486). Esas keytabs son
# las que Charon consume con `--keytab` (as/s4u2self/s4u2proxy).
#
#   Realm:      DELEG.LAB
#   Puerto:     1190 (el 1088 es del primer KDC)
#   Estado:     $CHARON_LAB_DIR/deleg (desechable, fuera del repo)
#   Keytabs:    $CHARON_LAB_DIR/deleg/keytabs (0600; *.keytab ya está en
#               el .gitignore del repo — material de clave, no versiona)
#
# Principals del realm (los nombres replican t_authdata.py de MIT):
#   krbtgt/DELEG.LAB   TGS del realm
#   user               usuario que será suplantado
#   service/1          servicio que DELEGA (+ok_to_auth_as_delegate)
#   service/2          servicio DESTINO del ticket delegado
#
# Uso:  bash lab/setup-test-kdb.sh          # configura y arranca
#       bash lab/setup-test-kdb.sh status   # comprueba si el KDC responde
#       bash lab/setup-test-kdb.sh stop     # para SOLO este KDC (pidfile)
#
set -euo pipefail

LAB_DIR="${CHARON_LAB_DIR:-$HOME/charon-lab}"
PREFIX="$LAB_DIR/krb5"
SRC="$LAB_DIR/src/krb5-1.21.3/src"
REALM="DELEG.LAB"
KDC_PORT="${CHARON_DELEG_PORT:-1190}"
DELEG="$LAB_DIR/deleg"
ETC="$DELEG/etc"
KEYTABS="$DELEG/keytabs"

find_bin() {
    for name in "$@"; do
        [ -x "$PREFIX/bin/$name" ] && { echo "$PREFIX/bin/$name"; return 0; }
        [ -x "$PREFIX/sbin/$name" ] && { echo "$PREFIX/sbin/$name"; return 0; }
    done
    return 1
}

# El módulo test se compila con el árbol fuente pero `make install` no lo
# instala (solo db2 va al prefijo): se copia el .so compilado a la carpeta
# de plugins del prefijo, PLANO — el loader de MIT (lib/kdb/kdb5.c 400-410:
# filebase "test" + FILEEXTS ""/".so" sobre db_module_dir) busca
# <db_module_dir>/test.so, no <db_module_dir>/test/test.so. Es el MISMO
# artefacto que produce el build del krb5 instalado (misma fuente, mismo
# compiler run, RUNPATH ya apuntando al prefijo), no un binario externo.
install_test_plugin() {
    local PLUGIN_SRC="$SRC/plugins/kdb/test/test.so"
    local PLUGIN_DIR="$PREFIX/lib/krb5/plugins/kdb"
    if [ ! -f "$PLUGIN_SRC" ]; then
        echo "ERROR [lab-testkdb]: $PLUGIN_SRC no existe — compila el lab base primero (lab/setup-mit-kdc.sh)" >&2
        exit 1
    fi
    mkdir -p "$PLUGIN_DIR"
    if ! cmp -s "$PLUGIN_SRC" "$PLUGIN_DIR/test.so"; then
        cp "$PLUGIN_SRC" "$PLUGIN_DIR/test.so"
        chmod 0755 "$PLUGIN_DIR/test.so"
        echo "[lab-testkdb] plugin test KDB instalado en $PLUGIN_DIR/test.so"
    fi
}

write_configs() {
    mkdir -p "$ETC" "$KEYTABS"

    # Conf de CLIENTE (la usan kinit/kadmin/klist contra este realm).
    # Charon NO lee krb5.conf: conecta directo con --dc/--port.
    cat > "$ETC/krb5.conf" <<EOF
[libdefaults]
    default_realm = $REALM
    dns_lookup_realm = false
    dns_lookup_kdc = false
    rdns = false
    ticket_lifetime = 24h
    forwardable = true
    udp_preference_limit = 0

[realms]
    $REALM = {
        kdc = 127.0.0.1:$KDC_PORT
    }

[logging]
    default = FILE:$DELEG/krb5lib.log
EOF

    # Conf del KDC: database_module = test conecta el realm con la sección
    # dbmodules. db_module_dir apunta a los plugins del PREFIJO (el loader
    # resuelve db_library = test como <dir>/test/test.so). La tabla
    # `delegation` es la política allowed_to_delegate que db2 no tiene:
    # service/1 (el evidence ticket) puede delegar hacia service/2
    # (kdb_test.c test_check_allowed_to_delegate: match_in_table con los
    # nombres SIN reino).
    cat > "$DELEG/kdc.conf" <<EOF
[kdcdefaults]
    kdc_ports = $KDC_PORT
    kdc_tcp_ports = $KDC_PORT

[realms]
    $REALM = {
        database_module = test
        max_life = 24h 0m 0s
        max_renewable_life = 7d 0h 0m 0s
    }

[dbmodules]
    test = {
        db_library = test
        db_module_dir = $PREFIX/lib/krb5/plugins/kdb
        princs = {
            krbtgt/$REALM = {
                keys = 1 aes256-cts-hmac-sha1-96
            }
            # flags en HEXADECIMAL, no con flagspecs: krb5_flagspec_to_mask
            # solo acepta UN flag por cadena (str_conv.c 131-198) y el
            # módulo test hace abort() si el parseo falla (check(),
            # kdb_test.c 122-127) — el ejemplo del README con dos flags
            # "+a +b" tumba el KDC/kadmin. Valores: REQUIRES_PRE_AUTH
            # 0x00000080 y OK_TO_AUTH_AS_DELEGATE 0x00200000 (kdb.h 92/100).
            user = {
                keys = 1 aes256-cts-hmac-sha1-96
                flags = 0x00000080
            }
            service/1 = {
                keys = 1 aes256-cts-hmac-sha1-96
                flags = 0x00200080
            }
            service/2 = {
                keys = 1 aes256-cts-hmac-sha1-96
                flags = 0x00000080
            }
        }
        delegation = {
            service/1 = service/2
        }
    }

[logging]
    kdc = FILE:$DELEG/kdc.log
    default = FILE:$DELEG/kdc.log
EOF
    echo "[lab-testkdb] configs escritas en $DELEG (principals en texto plano: el módulo test no usa BD)"
}

# kadmin.local contra el realm test: lee database_module del kdc.conf y
# abre el módulo test (read-only). ktadd -norandkey EXTRAE las claves hash
# sin rotar nada (no hay nada que rotar: son deterministas).
export_keytabs() {
    local KADMIN_LOCAL
    KADMIN_LOCAL="$(find_bin kadmin.local)"
    export KRB5_CONFIG="$ETC/krb5.conf"
    export KRB5_KDC_PROFILE="$DELEG/kdc.conf"

    export_one() {
        local princ="$1" file="$2"
        rm -f "$file"
        # kadmin.local sale 0 incluso si el comando falla (bug conocido
        # del lab): se verifica el KEYTAB resultante con klist -kt.
        "$KADMIN_LOCAL" -r "$REALM" -q "ktadd -norandkey -k $file $princ" >/dev/null
        if ! "$(find_bin klist)" -kt "$file" 2>/dev/null | grep -q "^KVNO\|AES256"; then
            echo "ERROR [lab-testkdb]: la extracción de $princ no produjo un keytab válido" >&2
            exit 1
        fi
        chmod 0600 "$file"
        echo "[lab-testkdb] keytab exportado: $file ($princ)"
    }

    export_one "service/1" "$KEYTABS/service1.keytab"
    export_one "service/2" "$KEYTABS/service2.keytab"
    export_one "user" "$KEYTABS/user.keytab"
}

start_kdc() {
    local KRB5KDC
    KRB5KDC="$(find_bin krb5kdc)"
    export KRB5_KDC_PROFILE="$DELEG/kdc.conf"
    export KRB5_CONFIG="$ETC/krb5.conf"

    if [ -f "$DELEG/krb5kdc.pid" ] && kill -0 "$(cat "$DELEG/krb5kdc.pid")" 2>/dev/null; then
        echo "[lab-testkdb] el KDC test ya está en marcha (pid $(cat "$DELEG/krb5kdc.pid"))"
        return 0
    fi
    rm -f "$DELEG/krb5kdc.pid"
    # -P pidfile: distingue ESTE KDC del de LAB.LOCAL (mismo binario; sin
    # pidfile, pkill krb5kdc mataría a los dos).
    "$KRB5KDC" -P "$DELEG/krb5kdc.pid"
    sleep 1
    if ! kill -0 "$(cat "$DELEG/krb5kdc.pid")" 2>/dev/null; then
        echo "ERROR [lab-testkdb]: krb5kdc no arrancó; mira $DELEG/kdc.log" >&2
        tail -5 "$DELEG/kdc.log" >&2 || true
        exit 1
    fi
    echo "[lab-testkdb] krb5kdc (test KDB) escuchando en 127.0.0.1:$KDC_PORT (UDP+TCP)"
}

smoke_test() {
    local KINIT KLIST
    KINIT="$(find_bin kinit)"
    KLIST="$(find_bin klist)"
    export KRB5_CONFIG="$ETC/krb5.conf"
    local CC="$DELEG/smoke.cc"
    rm -f "$CC"
    # La prueba de fuego: kinit -k con el keytab extraído. Solo funciona
    # si (1) el módulo test cargó, (2) las claves hash del keytab
    # coinciden con las que el KDC deriva, (3) el puerto responde.
    "$KINIT" -k -t "$KEYTABS/service1.keytab" -c "$CC" "service/1"
    "$KLIST" -c "$CC" | sed 's/^/[lab-testkdb] /'
    rm -f "$CC"
}

status() {
    if [ -f "$DELEG/krb5kdc.pid" ] && kill -0 "$(cat "$DELEG/krb5kdc.pid")" 2>/dev/null; then
        echo "[lab-testkdb] KDC test activo en 127.0.0.1:$KDC_PORT (pid $(cat "$DELEG/krb5kdc.pid"))"
    else
        echo "[lab-testkdb] KDC test parado"
        exit 1
    fi
}

stop_kdc() {
    if [ -f "$DELEG/krb5kdc.pid" ]; then
        kill "$(cat "$DELEG/krb5kdc.pid")" 2>/dev/null && echo "[lab-testkdb] KDC test parado"
        rm -f "$DELEG/krb5kdc.pid"
    else
        echo "[lab-testkdb] no hay pidfile: no está en marcha (o se arrancó a mano)"
    fi
}

case "${1:-install}" in
    install)
        [ -x "$PREFIX/sbin/krb5kdc" ] || { echo "ERROR [lab-testkdb]: falta el lab base ($PREFIX) — ejecuta lab/setup-mit-kdc.sh primero" >&2; exit 1; }
        install_test_plugin
        write_configs
        export_keytabs
        start_kdc
        smoke_test
        echo "[lab-testkdb] Listo. Ciclo completo: charon s4u2proxy --user service/1 --keytab $KEYTABS/service1.keytab --impersonate user --to service/2 -r $REALM --port $KDC_PORT"
        ;;
    status) status ;;
    stop) stop_kdc ;;
    *) echo "uso: $0 [install|status|stop]"; exit 2 ;;
esac
