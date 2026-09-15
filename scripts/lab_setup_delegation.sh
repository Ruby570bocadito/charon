#!/bin/sh
# Setup de delegación en el laboratorio MIT krb5 (LAB.LOCAL).
#
# Crea los dos principales de servicio que necesita `charon s4u2proxy` y
# concede el atributo ok_to_auth_as_delegate al servicio que DELEGA (MS-SFU
# §2.2.3: sin él, MIT emite el evidence ticket de S4U2Self sin FORWARDABLE
# y el KDC rechaza el S4U2Proxy con KDC_ERR_BADOPTION).
#
# Uso (con el KDC del lab en marcha):
#   ./scripts/lab_setup_delegation.sh
#
# Idempotente: si el principal ya existe se continúa; modprinc es
# reaplicable. Contraseñas alfanuméricas a propósito: las comillas dentro
# de kadmin son la trampa documentada del lab (los valores llegan tal cual
# a kadmin y las comillas se vuelven parte del password).
set -u

REALM="LAB.LOCAL"
KADMIN=${KADMIN:-/home/z/charon-lab/krb5/sbin/kadmin.local}
export KRB5_CONFIG=${KRB5_CONFIG:-/home/z/charon-lab/krb5/etc/krb5.conf}

echo "== addprinc svc-api (servicio que DELEGA) =="
"$KADMIN" -q "addprinc -pw SvcApiPass2026 svc-api@${REALM}" || echo "(ya existía: se continúa)"

echo "== addprinc svc-db (servicio DESTINO del ticket delegado) =="
"$KADMIN" -q "addprinc -pw SvcDbPass2026 svc-db@${REALM}" || echo "(ya existía: se continúa)"

echo "== modprinc +ok_to_auth_as_delegate svc-api =="
"$KADMIN" -q "modprinc +ok_to_auth_as_delegate svc-api@${REALM}"

echo "== comprobación =="
"$KADMIN" -q "getprinc svc-api@${REALM}" | grep -E "Attributes|Key: vno" || true
