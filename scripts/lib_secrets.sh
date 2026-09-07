#!/usr/bin/env bash
# =============================================================================
#  lib_secrets.sh — безопасная запись и чтение секретов в config.env
#
#  Зачем. config.env читается через `source`, то есть обычным bash. Значения
#  вида pbkdf2_sha256$200000$соль$хеш, записанные в ДВОЙНЫХ кавычках, bash
#  разворачивает как переменные: $200000 и $соль подставляются пустотой, и от
#  хеша остаётся огрызок — вход перестаёт работать. То же с паролями, где
#  встречаются $, ` или \.
#
#  Поэтому такие значения пишем в ОДИНАРНЫХ кавычках (sq), а при чтении старых
#  конфигов, где они ещё в двойных, берём их из файла напрямую (load_secrets),
#  минуя подстановку.
# =============================================================================

# Ключи, значение которых может содержать спецсимволы оболочки
SECRET_KEYS=(
    LLM_API_KEY
    GRAFANA_ADMIN_PASSWORD
    ALERT_SMTP_PASSWORD
    AUTH_ADMIN_PASSWORD_HASH
    AUTH_SECRET
    LDAP_SEARCH_PASSWORD
    OIDC_CLIENT_SECRET
    INGEST_TOKENS
)

# sq ЗНАЧЕНИЕ — вернуть строку в одинарных кавычках, пригодную для source.
# Одинарная кавычка внутри значения закрывается и вставляется экранированной.
sq() {
    local v="${1-}" out="" i c
    for (( i = 0; i < ${#v}; i++ )); do
        c=${v:i:1}
        # закрываем кавычку, вставляем экранированную, открываем снова
        if [[ $c == "'" ]]; then out+="'\''"; else out+="$c"; fi
    done
    printf "'%s'" "$out"
}

# read_raw ФАЙЛ КЛЮЧ — значение так, как оно лежит в файле, без подстановки.
read_raw() {
    local file="$1" key="$2" line val
    line=$(grep -E "^[[:space:]]*${key}=" "$file" 2>/dev/null | tail -1) || return 1
    [[ -n "$line" ]] || return 1
    val=${line#*=}
    if [[ ${#val} -ge 2 && ${val:0:1} == "'" && ${val: -1} == "'" ]]; then
        val=${val:1:${#val}-2}
        val=${val//"'\''"/"'"}
    elif [[ ${#val} -ge 2 && ${val:0:1} == '"' && ${val: -1} == '"' ]]; then
        val=${val:1:${#val}-2}
    fi
    printf '%s' "$val"
}

# load_secrets ФАЙЛ — перечитать секреты из файла поверх результата source.
# Вызывать сразу после source: чинит конфиги, записанные старыми версиями.
load_secrets() {
    local file="$1" k v
    [[ -f "$file" ]] || return 0
    for k in "${SECRET_KEYS[@]}"; do
        grep -qE "^[[:space:]]*${k}=" "$file" 2>/dev/null || continue
        v=$(read_raw "$file" "$k") || continue
        printf -v "$k" '%s' "$v"
    done
}

# load_config ФАЙЛ — прочитать config.env целиком и починить секреты.
#
# Отдельная функция нужна из-за set -u: в старом конфиге хеш записан как
# "pbkdf2_sha256$200000$...", и на $200000 bash падает с "$2: unbound
# variable", обрывая установку. На время source проверку снимаем — испорченные
# значения тут же перезаписывает load_secrets из того же файла.
load_config() {
    local file="$1" had_u=0
    [[ $- == *u* ]] && had_u=1
    set +u
    # shellcheck disable=SC1090
    source "$file"
    (( had_u )) && set -u
    load_secrets "$file"
}
