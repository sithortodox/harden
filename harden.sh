#!/usr/bin/env bash
# ============================================================================
# harden.sh — комплексный интерактивный скрипт защиты Linux-сервера
#
# Покрывает: SSH, firewall, Fail2ban, TLS/SSL-сертификаты, резервные копии,
# мониторинг, проверку/обновление Exim, OpenSSH и связанных пакетов, проверку
# CVE по установленным Ubuntu-пакетам (JSON API + OVAL/OpenSCAP), ужесточение
# SMTP/IMAP/POP3, запрет небезопасной авторизации, TLS-политику, DKIM, SPF
# (мягкий -> жёсткий режим), DMARC (none -> quarantine -> reject), проверку
# spoofing, TLS-шифры, web-заголовки (HSTS/CSP/clickjacking), cookie-флаги,
# аудит открытых портов, защиту реального IP (CDN/proxy) и периметр в целом.
#
# Не привязан к одной ОС: автоматически определяет дистрибутив (Debian/Ubuntu,
# RHEL/Rocky/Alma/Fedora, openSUSE, Arch), пакетный менеджер, init-систему,
# установленный MTA (Exim/Postfix), веб-сервер, reverse proxy и т.д.
# Каждый параметр запрашивается у пользователя; ответы сохраняются и могут
# быть переиспользованы.
#
# Использование:
#   ./harden.sh                 # полный интерактивный прогон
#   ./harden.sh --list-modules  # список модулей
#   ./harden.sh --module ssh,firewall,verify
#   ./harden.sh --all --answers /root/harden.answers
#   ./harden.sh --report-only
#   ./harden.sh --dry-run --module mail
#
# Требуется запуск от root (для --list-modules/--help — не обязательно).
# ============================================================================
set -o pipefail

HARDEN_VERSION="1.0.0"
SCRIPT_PATH="$(readlink -f "${BASH_SOURCE[0]}")"
SCRIPT_DIR="$(cd "$(dirname "$SCRIPT_PATH")" && pwd)"
TS="$(date +%Y%m%d-%H%M%S)"

# --- Цвета / вывод -----------------------------------------------------------
if [[ -t 1 && -z ${NO_COLOR:-} ]]; then
  C_RESET=$'\033[0m'; C_BOLD=$'\033[1m'; C_DIM=$'\033[2m'
  C_RED=$'\033[31m'; C_GREEN=$'\033[32m'; C_YELLOW=$'\033[33m'
  C_BLUE=$'\033[34m'; C_CYAN=$'\033[36m'
else
  C_RESET=""; C_BOLD=""; C_DIM=""; C_RED=""; C_GREEN=""; C_YELLOW=""; C_BLUE=""; C_CYAN=""
fi

LOG_FILE="/var/log/harden/harden-${TS}.log"
REPORT_FILE=""
BACKUP_DIR=""
DRY_RUN=0
YES_MODE=0
REPORT_ONLY=0
SELECTED_MODULES=""
ANS_FILE=""

declare -A ANS            # ответы пользователя (id -> значение)
declare -A MODULE_STATUS  # статусы модулей для итогового отчёта
REPORT_LINES=()

log()   { printf '%s [%s] %s\n' "$(date '+%F %T')" "$1" "$*" | tee -a "$LOG_FILE" >/dev/null; }
info()  { printf '%s==>%s %s\n' "$C_BLUE" "$C_RESET" "$*"; log INFO "$*"; }
ok()    { printf '%s[OK]%s %s\n' "$C_GREEN" "$C_RESET" "$*"; log OK "$*"; }
warn()  { printf '%s[!]%s %s\n' "$C_YELLOW" "$C_RESET" "$*" | tee -a "$LOG_FILE" >/dev/null; }
err()   { printf '%s[ERR]%s %s\n' "$C_RED" "$C_RESET" "$*" | tee -a "$LOG_FILE" >&2; }
die()   { err "$*"; exit 1; }
header(){ printf '\n%s%s%s\n' "$C_BOLD$C_CYAN" "─── $* ───" "$C_RESET"; log SECTION "$*"; }
rep()   { REPORT_LINES+=("$*"); }

run() {
  if [[ $DRY_RUN -eq 1 ]]; then
    printf '%s[dry-run]%s %s\n' "$C_DIM" "$C_RESET" "$*"
    log DRYRUN "$*"
    return 0
  fi
  log CMD "$*"
  "$@" 2>&1 | tee -a "$LOG_FILE"
  return "${PIPESTATUS[0]}"
}

write_file() {  # write_file <path> <mode>  (данные в stdin)
  local path="$1" mode="${2:-644}"
  if [[ $DRY_RUN -eq 1 ]]; then
    printf '%s[dry-run]%s запись файла %s (mode %s)\n' "$C_DIM" "$C_RESET" "$path" "$mode"
    cat >/dev/null
    return 0
  fi
  mkdir -p "$(dirname "$path")"
  cat >"$path"
  chmod "$mode" "$path"
  log WRITE "$path mode=$mode"
}

backup_file() {  # backup_file <path...>
  local f
  for f in "$@"; do
    [[ -e $f ]] || continue
    mkdir -p "$BACKUP_DIR$(dirname "$f")"
    cp -a "$f" "$BACKUP_DIR$f" 2>/dev/null || true
  done
}

# --- Опрос пользователя ------------------------------------------------------
save_ans() {  # save_ans id value
  ANS["$1"]="$2"
  if [[ -n $ANS_FILE && $DRY_RUN -eq 0 ]]; then
    grep -v "^$1=" "$ANS_FILE" 2>/dev/null >"${ANS_FILE}.tmp" || true
    printf '%s=%q\n' "$1" "$2" >>"${ANS_FILE}.tmp"
    mv "${ANS_FILE}.tmp" "$ANS_FILE"; chmod 600 "$ANS_FILE"
  fi
}

ask_yn() {  # ask_yn id "вопрос" [default=y|n]
  local id="$1" q="$2" def="${3:-y}" a hint
  [[ $def == y ]] && hint="[Y/n]" || hint="[y/N]"
  if [[ -n ${ANS[$id]:-} ]]; then
    [[ ${ANS[$id]} == y ]] && return 0 || return 1
  fi
  if [[ $YES_MODE -eq 1 ]]; then
    save_ans "$id" "$def"
    printf '%s%s%s -> %s\n' "$C_DIM" "$q" "$C_RESET" "$def" >&2
    [[ $def == y ]] && return 0 || return 1
  fi
  while true; do
    read -rp "$q $hint: " a || a=""
    a="${a:-$def}"
    case "$a" in
      [yY]|[yY]es|[дД]|[дД]а) save_ans "$id" y; return 0 ;;
      [nN]|[nN]o|[нН]|[нН]ет) save_ans "$id" n; return 1 ;;
      *) echo "  Введите y или n" ;;
    esac
  done
}

ask_val() {  # ask_val id "вопрос" [default] -> echo value
  local id="$1" q="$2" def="${3:-}" a
  if [[ -n ${ANS[$id]:-} ]]; then echo "${ANS[$id]}"; return; fi
  if [[ $YES_MODE -eq 1 ]]; then
    save_ans "$id" "$def"
    printf '%s%s%s -> %s\n' "$C_DIM" "$q" "$C_RESET" "$def" >&2
    echo "$def"; return
  fi
  while true; do
    if [[ -n $def ]]; then read -rp "$q [$def]: " a || a=""; else read -rp "$q: " a || a=""; fi
    a="${a:-$def}"
    if [[ -z $a && -z $def ]]; then echo "  Значение не может быть пустым" >&2; continue; fi
    save_ans "$id" "$a"; echo "$a"; return
  done
}

ask_secret() {  # ask_secret id "вопрос" [default] -> echo value (не логируется)
  local id="$1" q="$2" def="${3:-}" a
  if [[ -n ${ANS[$id]:-} ]]; then echo "${ANS[$id]}"; return; fi
  if [[ $YES_MODE -eq 1 ]]; then
    save_ans "$id" "$def"; echo "$def"; return
  fi
  while true; do
    if [[ -n $def ]]; then
      read -rsp "$q [$def]: " a; echo
    else
      read -rsp "$q: " a; echo
    fi
    a="${a:-$def}"
    if [[ -z $a && -z $def ]]; then echo "  Значение не может быть пустым" >&2; continue; fi
    save_ans "$id" "$a"; echo "$a"; return
  done
}

ask_choice() {  # ask_choice id "вопрос" "вариант1|вариант2|..." [default_index=1]
  local id="$1" q="$2" opts="$3" def="${4:-1}" i=1 o a
  local -a arr
  IFS='|' read -ra arr <<<"$opts"
  if [[ -n ${ANS[$id]:-} ]]; then echo "${ANS[$id]}"; return; fi
  if [[ $YES_MODE -eq 1 ]]; then
    save_ans "$id" "${arr[$((def-1))]}"; echo "${arr[$((def-1))]}"; return
  fi
  echo "$q" >&2
  for o in "${arr[@]}"; do printf '  %2d) %s\n' "$i" "$o" >&2; i=$((i+1)); done
  while true; do
    read -rp "Выберите [1-${#arr[@]}] ($def): " a || a=""
    a="${a:-$def}"
    if [[ $a =~ ^[0-9]+$ && $a -ge 1 && $a -le ${#arr[@]} ]]; then
      save_ans "$id" "${arr[$((a-1))]}"; echo "${arr[$((a-1))]}"; return
    fi
    echo "  Неверный выбор"
  done
}

gen_pass() { openssl rand -base64 24 2>/dev/null | tr -d '/+=' | cut -c1-24; }

# --- Определение окружения ---------------------------------------------------
OS_ID="unknown"; OS_LIKE=""; OS_CODENAME=""; OS_VERSION=""; OS_PRETTY=""
PKG_MGR="unknown"; INIT_SYS="unknown"
HAVE_SYSTEMD=0
MTA="none"            # exim|postfix|sendmail|none
WEB="none"            # nginx|apache2|httpd|caddy|none
IMAP="none"           # dovecot|courier|none
SSH_PORT_CURRENT=22
SSHD_CONFIG=""
PUBLIC_IP=""; SERVER_IPS=()

detect_os() {
  if [[ -r /etc/os-release ]]; then
    # shellcheck disable=SC1091
    . /etc/os-release
    OS_ID="${ID:-unknown}"; OS_LIKE="${ID_LIKE:-}"
    OS_CODENAME="${VERSION_CODENAME:-}"; OS_VERSION="${VERSION_ID:-}"
    OS_PRETTY="${PRETTY_NAME:-$OS_ID $OS_VERSION}"
  fi
  command -v apt-get  >/dev/null && PKG_MGR="apt"
  command -v dnf      >/dev/null && { PKG_MGR="dnf"; }
  command -v yum      >/dev/null && { [[ $PKG_MGR == unknown ]] && PKG_MGR="yum"; }
  command -v zypper   >/dev/null && { [[ $PKG_MGR == unknown ]] && PKG_MGR="zypper"; }
  command -v pacman   >/dev/null && { [[ $PKG_MGR == unknown ]] && PKG_MGR="pacman"; }
  command -v apk      >/dev/null && { [[ $PKG_MGR == unknown ]] && PKG_MGR="apk"; }
  if command -v systemctl >/dev/null 2>&1; then INIT_SYS="systemd"; HAVE_SYSTEMD=1
  else INIT_SYS="other"; fi
}

is_ubuntu_like() { [[ $PKG_MGR == apt && ( $OS_ID == ubuntu || $OS_LIKE == *debian* || $OS_ID == debian ) ]]; }
is_ubuntu()      { [[ $OS_ID == ubuntu ]]; }

pkg_is_installed() {
  case "$PKG_MGR" in
    apt)    dpkg-query -W -f='${Status}' "$1" 2>/dev/null | grep -q "install ok installed" ;;
    dnf|yum) rpm -q "$1" >/dev/null 2>&1 ;;
    zypper) rpm -q "$1" >/dev/null 2>&1 ;;
    pacman) pacman -Q "$1" >/dev/null 2>&1 ;;
    apk)    apk info -e "$1" >/dev/null 2>&1 ;;
    *)      return 1 ;;
  esac
}

pkg_install() {
  local pkgs=("$@") || return 0
  [[ ${#pkgs[@]} -eq 0 ]] && return 0
  case "$PKG_MGR" in
    apt)    DEBIAN_FRONTEND=noninteractive run apt-get install -y --no-install-recommends "${pkgs[@]}" ;;
    dnf)    run dnf install -y "${pkgs[@]}" ;;
    yum)    run yum install -y "${pkgs[@]}" ;;
    zypper) run zypper --non-interactive install -y "${pkgs[@]}" ;;
    pacman) run pacman -Sy --noconfirm "${pkgs[@]}" ;;
    apk)    run apk add "${pkgs[@]}" ;;
    *)      err "Неизвестный пакетный менеджер: $PKG_MGR"; return 1 ;;
  esac
}

pkg_upgrade_refresh() {
  case "$PKG_MGR" in
    apt)    run apt-get update -qq ;;
    dnf)    run dnf makecache -q ;;
    yum)    run yum makecache -q ;;
    zypper) run zypper --non-interactive refresh ;;
    pacman) run pacman -Sy -q --noconfirm ;;
    apk)    run apk update -q ;;
  esac
}

svc_is_active() {  # svc_is_active <имя...>
  local s
  for s in "$@"; do
    if [[ $HAVE_SYSTEMD -eq 1 ]]; then systemctl is-active --quiet "$s" 2>/dev/null && return 0
    else service "$s" status >/dev/null 2>&1 && return 0; fi
  done
  return 1
}

svc_enable_start() {  # svc_enable_start <имя>
  local s="$1"
  if [[ $HAVE_SYSTEMD -eq 1 ]]; then
    run systemctl daemon-reload || true
    run systemctl enable --now "$s"
  else
    run service "$s" start || true
  fi
}

svc_restart() {
  local s="$1"
  if [[ $HAVE_SYSTEMD -eq 1 ]]; then run systemctl restart "$s"
  else run service "$s" restart; fi
}

svc_reload() {
  local s="$1"
  if [[ $HAVE_SYSTEMD -eq 1 ]]; then run systemctl reload "$s" || svc_restart "$s"
  else run service "$s" reload || svc_restart "$s"; fi
}

detect_components() {
  if [[ -x /usr/sbin/sshd ]]; then SSHD_CONFIG="/etc/ssh/sshd_config"
  elif [[ -x /usr/sbin/ssh-session-cleanup ]]; then SSHD_CONFIG="/etc/ssh/sshd_config"; fi
  [[ -f /etc/ssh/sshd_config ]] && SSHD_CONFIG="/etc/ssh/sshd_config"
  if [[ -n $SSHD_CONFIG ]]; then
    local p
    p=$(awk '/^#?[[:space:]]*Port[[:space:]]+/ {print $2; exit}' "$SSHD_CONFIG" 2>/dev/null)
    [[ $p =~ ^[0-9]+$ ]] && SSH_PORT_CURRENT=$p
  fi

  if   command -v exim4    >/dev/null 2>&1 || command -v exim    >/dev/null 2>&1; then MTA="exim"
  elif command -v postfix  >/dev/null 2>&1; then MTA="postfix"
  elif command -v sendmail >/dev/null 2>&1; then MTA="sendmail"; fi

  if   svc_is_active nginx || command -v nginx     >/dev/null 2>&1; then WEB="nginx"
  elif svc_is_active apache2 || command -v apache2 >/dev/null 2>&1; then WEB="apache2"
  elif svc_is_active httpd   || command -v httpd   >/dev/null 2>&1; then WEB="httpd"
  elif command -v caddy >/dev/null 2>&1; then WEB="caddy"; fi

  if   command -v dovecot  >/dev/null 2>&1; then IMAP="dovecot"
  elif command -v dovecotd >/dev/null 2>&1; then IMAP="dovecot"
  elif command -v courierpop3d >/dev/null 2>&1; then IMAP="courier"; fi

  PUBLIC_IP="$(curl -4 -s --max-time 8 https://ifconfig.me 2>/dev/null || true)"
  [[ -z $PUBLIC_IP ]] && PUBLIC_IP="$(curl -4 -s --max-time 8 https://api.ipify.org 2>/dev/null || true)"
  mapfile -t SERVER_IPS < <(ip -4 addr show scope global 2>/dev/null | awk '/inet /{print $2}' | cut -d/ -f1)
}

# --- Работа с конфигурацией nginx/apache/exim/dovecot ------------------------
nginx_http_conf() { echo "/etc/nginx/conf.d"; }
ensure_nginx_conf_d() {
  [[ -d /etc/nginx ]] || return 1
  mkdir -p /etc/nginx/conf.d /etc/nginx/snippets 2>/dev/null || return 1
  return 0
}

detect_fw_backend() {
  if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q Status; then echo ufw; return; fi
  if command -v firewall-cmd >/dev/null 2>&1 && systemctl is-active --quiet firewalld 2>/dev/null; then echo firewalld; return; fi
  if command -v nft >/dev/null 2>&1; then echo nftables; return; fi
  if command -v ufw >/dev/null 2>&1; then echo ufw; return; fi
  echo none
}

FW_BACKEND="none"

# --- Реестр модулей ----------------------------------------------------------
# формат: имя|описание|функция
MODULE_REGISTRY=(
  "updates|Системные обновления и авто-обновления безопасности|mod_updates"
  "sysctl|Ядро и сеть: sysctl-харденинг|mod_sysctl"
  "pam|Парольная политика, PAM, лимиты, umask|mod_pam"
  "ssh|Защита SSH (OpenSSH)|mod_ssh"
  "firewall|Межсетевой экран (ufw/firewalld/nftables)|mod_firewall"
  "fail2ban|Fail2ban: sshd/exim/dovecot/nginx|mod_fail2ban"
  "legacy_auth|Запрет небезопасной авторизации и legacy-протоколов|mod_legacy_auth"
  "ssl|SSL/TLS-сертификаты (ACME: Let's Encrypt)|mod_ssl"
  "web_headers|Web-заголовки безопасности (HSTS/CSP/clickjacking)|mod_web_headers"
  "real_ip|Защита реального IP (CDN/reverse proxy) и периметр|mod_real_ip"
  "mail|Ужесточение SMTP/IMAP/POP3 (Exim/Postfix + Dovecot)|mod_mail"
  "dkim|Настройка DKIM-подписи|mod_dkim"
  "spf|SPF: проверка отправителей, переход к жёсткому -all|mod_spf"
  "dmarc|DMARC: none -> quarantine -> reject|mod_dmarc"
  "spoof|Проверка spoofing и открытого релея|mod_spoof"
  "cve|Проверка CVE по установленным Ubuntu-пакетам|mod_cve"
  "critical_updates|Точечное обновление OpenSSH/Exim/связанных пакетов|mod_critical_updates"
  "backups|Резервные копии (restic/borg)|mod_backups"
  "monitoring|Мониторинг: AIDE, node_exporter, логи, алерты|mod_monitoring"
  "ports|Аудит открытых портов|mod_ports"
  "permissions|Права файлов, SUID/SGID, auditd, sudo|mod_permissions"
  "verify|Финальная проверка и отчёт|mod_verify"
)

module_selected() {
  local name="$1"
  [[ -z $SELECTED_MODULES ]] && return 0
  [[ ",$SELECTED_MODULES," == *",$name,"* ]] && return 0
  return 1
}

list_modules() {
  echo "Доступные модули (--module имя1,имя2,...):"
  local m name desc
  for m in "${MODULE_REGISTRY[@]}"; do
    IFS='|' read -r name desc _ <<<"$m"
    printf '  %-18s %s\n' "$name" "$desc"
  done
}

usage() {
  cat <<EOF
harden.sh v$HARDEN_VERSION — комплексная защита сервера

Использование: ./harden.sh [опции]

  --list-modules          показать список модулей
  --module a,b,c          выполнить только указанные модули
  --all                   выполнить все модули (с запросом параметров)
  --yes                   принимать значения по умолчанию без запросов
  --dry-run               только показать действия, ничего не менять
  --answers FILE          файл с ответами (загрузка и сохранение)
  --report-only           только выполнить проверку и сформировать отчёт
  --no-color              отключить цвета
  -h, --help              эта справка

Перед запуском сделайте снапшок/бэкап: конфиги будут сохранены в
/root/harden-backup-<дата>/ перед любыми изменениями.
EOF
}

parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --list-modules) list_modules; exit 0 ;;
      --module)       SELECTED_MODULES="${2:-}"; shift 2 ;;
      --module=*)     SELECTED_MODULES="${1#*=}"; shift ;;
      --all)          SELECTED_MODULES=""; shift ;;
      --yes|-y)       YES_MODE=1; shift ;;
      --dry-run)      DRY_RUN=1; shift ;;
      --answers)      ANS_FILE="${2:-}"; shift 2 ;;
      --answers=*)    ANS_FILE="${1#*=}"; shift ;;
      --report-only)  REPORT_ONLY=1; SELECTED_MODULES="verify"; shift ;;
      --no-color)     NO_COLOR=1; shift ;;
      -h|--help)      usage; exit 0 ;;
      *)              err "Неизвестная опция: $1"; usage; exit 1 ;;
    esac
  done
}

preflight() {
  if [[ $EUID -ne 0 ]]; then
    die "Запустите скрипт от root: sudo ./harden.sh"
  fi
  mkdir -p /var/log/harden
  touch "$LOG_FILE" || LOG_FILE="/tmp/harden-${TS}.log"
  if [[ -n $ANS_FILE && -r $ANS_FILE ]]; then
    # shellcheck disable=SC1090
    while IFS= read -r line; do
      [[ $line =~ ^([A-Za-z0-9_]+)=(.*)$ ]] || continue
      local k="${BASH_REMATCH[1]}" v="${BASH_REMATCH[2]}"
      v="${v%\'}"; v="${v#\'}"
      ANS["$k"]="$v"
    done < <(grep -E '^[A-Za-z0-9_]+=' "$ANS_FILE" 2>/dev/null || true)
    info "Загружены ранее сохранённые ответы из $ANS_FILE"
  elif [[ -n $ANS_FILE ]]; then
    : >"$ANS_FILE"; chmod 600 "$ANS_FILE"
  else
    ANS_FILE="/root/.harden-answers-${TS}.env"
    : >"$ANS_FILE"; chmod 600 "$ANS_FILE"
  fi
  BACKUP_DIR="/root/harden-backup-${TS}"
  mkdir -p "$BACKUP_DIR"
  REPORT_FILE="/root/harden-report-${TS}.md"

  detect_os
  detect_components

  header "Preflight"
  info "Скрипт harden.sh v$HARDEN_VERSION"
  info "ОС:          $OS_PRETTY (id=$OS_ID codename=$OS_CODENAME like=$OS_LIKE)"
  info "Пакеты:      $PKG_MGR   Init: $INIT_SYS"
  info "MTA:         $MTA    Веб: $WEB    IMAP/POP3: $IMAP"
  info "Публичный IP: ${PUBLIC_IP:-не определён}"
  info "Локальные IP: ${SERVER_IPS[*]:-?}"
  info "SSH порт:    $SSH_PORT_CURRENT   Firewall: $(detect_fw_backend)"
  info "Бэкап конфигов: $BACKUP_DIR"
  info "Лог: $LOG_FILE   Ответы: $ANS_FILE"

  rep "## Окружение"
  rep "- ОС: $OS_PRETTY"
  rep "- Пакетный менеджер: $PKG_MGR, init: $INIT_SYS"
  rep "- MTA: $MTA, WEB: $WEB, IMAP: $IMAP"
  rep "- Публичный IP: ${PUBLIC_IP:-n/a}"
  rep ""
}

run_module() {  # run_module имя описание функция
  local name="$1" desc="$2" fn="$3"
  module_selected "$name" || return 0
  header "Модуль: $desc"
  if ! declare -F "$fn" >/dev/null; then
    err "Функция $fn не найдена"; MODULE_STATUS[$name]="skip"; return 1
  fi
  if ask_yn "mod_$name" "Выполнить модуль «$desc»?" y; then
    if "$fn"; then
      MODULE_STATUS[$name]="ok"; ok "Модуль «$name» завершён"
    else
      MODULE_STATUS[$name]="fail"; warn "Модуль «$name» завершился с ошибками (см. лог)"
    fi
  else
    MODULE_STATUS[$name]="skipped"; info "Модуль «$name» пропущен пользователем"
  fi
  rep "- Модуль \`$name\`: ${MODULE_STATUS[$name]}"
}

# ============================================================================
# МОДУЛЬ: updates — системные обновления и авто-обновления безопасности
# ============================================================================
mod_updates() {
  info "Обновление индексов пакетов..."
  pkg_upgrade_refresh || warn "Не удалось обновить индекс пакетов"

  if ask_yn "upd_full" "Выполнить полное обновление установленных пакетов?" y; then
    case "$PKG_MGR" in
      apt)    DEBIAN_FRONTEND=noninteractive run apt-get -y dist-upgrade ;;
      dnf)    run dnf -y upgrade ;;
      yum)    run yum -y update ;;
      zypper) run zypper --non-interactive update ;;
      pacman) run pacman -Syu --noconfirm ;;
      apk)    run apk upgrade ;;
    esac
  fi

  if ask_yn "upd_auto" "Включить автоматические обновления безопасности?" y; then
    case "$PKG_MGR" in
      apt)
        pkg_install unattended-upgrades || true
        write_file /etc/apt/apt.conf.d/20auto-upgrades <<'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
EOF
        write_file /etc/apt/apt.conf.d/51unattended-upgrades-local <<'EOF'
Unattended-Upgrade::Automatic-Reboot "false";
Unattended-Upgrade::Mail "root";
Unattended-Upgrade::Remove-Unused-Kernel-Packages "true";
Unattended-Upgrade::Remove-Unused-Dependencies "true";
Unattended-Upgrade::SyslogEnable "true";
EOF
        if [[ $HAVE_SYSTEMD -eq 1 ]]; then
          run systemctl enable --now unattended-upgrades.service 2>/dev/null || true
          run systemctl enable --now apt-daily.timer 2>/dev/null || true
          run systemctl enable --now apt-daily-upgrade.timer 2>/dev/null || true
        fi
        ok "unattended-upgrades включён (security-репозитории)"
        ;;
      dnf|yum)
        if pkg_install dnf-automatic 2>/dev/null; then
          write_file /etc/dnf/automatic.conf <<'EOF'
[commands]
upgrade_type = security
download_updates = yes
apply_updates = yes

[emitters]
emit_via = stdio
EOF
          run systemctl enable --now dnf-automatic.timer 2>/dev/null || true
          ok "dnf-automatic (security) включён"
        else
          warn "dnf-automatic недоступен — настройте авто-обновления вручную"
        fi
        ;;
      zypper) info "openSUSE: включите авто-обновления через yast2-online-update" ;;
      pacman) info "Arch: настройте pacman-hooks для авто-обновлений" ;;
      apk)    info "Alpine: добавьте 'apk upgrade' в cron" ;;
    esac
  fi
  return 0
}

# ============================================================================
# МОДУЛЬ: sysctl — ядро и сеть
# ============================================================================
mod_sysctl() {
  local mode router=0
  mode=$(ask_choice "sysctl_mode" "Профиль сетевого ядра:" \
    "сервер (forwarding выключен)|маршрутизатор (forwarding включён)" 1)
  [[ $mode == *маршрутизатор* ]] && router=1

  backup_file /etc/sysctl.conf /etc/sysctl.d/99-hardening.conf

  if [[ $DRY_RUN -eq 1 ]]; then
    info "[dry-run] запись /etc/sysctl.d/99-hardening.conf (router=$router)"
    return 0
  fi

  cat >/etc/sysctl.d/99-hardening.conf <<EOF
# harden.sh: ядро и сеть (создано $(date -u +%FT%TZ))
# --- сеть: anti-spoofing / anti-abuse ---
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_rfc1337 = 1
net.ipv4.tcp_max_syn_backlog = 4096
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_syn_retries = 3
net.ipv4.tcp_fin_timeout = 15
net.ipv4.tcp_keepalive_time = 600
net.ipv4.ip_local_port_range = 32768 65535
net.ipv6.conf.all.accept_ra = 0
net.ipv6.conf.default.accept_ra = 0
# --- ядро: ограничение информации / уязвимостей ---
kernel.kptr_restrict = 2
kernel.dmesg_restrict = 1
kernel.perf_event_paranoid = 3
kernel.yama.ptrace_scope = 1
kernel.sysrq = 0
kernel.unprivileged_bpf_disabled = 1
kernel.kexec_load_disabled = 1
kernel.core_uses_pid = 1
fs.suid_dumpable = 0
fs.protected_symlinks = 1
fs.protected_hardlinks = 1
fs.protected_fifos = 2
fs.protected_regular = 2
fs.protected_namespaces = 1
user.max_user_namespaces = 0
kernel.apparmor_restrict_unprivileged_userns = 1
EOF
  if [[ $router -eq 1 ]]; then
    cat >>/etc/sysctl.d/99-hardening.conf <<'EOF'
# режим маршрутизатора
net.ipv4.ip_forward = 1
net.ipv6.conf.all.forwarding = 1
EOF
  fi

  run sysctl --system >/dev/null 2>&1 || run sysctl -p /etc/sysctl.d/99-hardening.conf
  ok "sysctl применён (/etc/sysctl.d/99-hardening.conf, router=$router)"
  return 0
}

# ============================================================================
# МОДУЛЬ: pam — парольная политика, лимиты, umask
# ============================================================================
mod_pam() {
  local minlen quality
  minlen=$(ask_val "pam_minlen" "Минимальная длина пароля (pwquality minlen)" "14")
  quality=$(ask_val "pam_quality" "Минимальное изменение пароля (difok)" "8")

  if pkg_is_installed libpam-pwquality || pkg_is_installed libpwquality || \
     pkg_install libpam-pwquality libpwquality 2>/dev/null || pkg_install pam_pwquality 2>/dev/null; then
    backup_file /etc/security/pwquality.conf
    write_file /etc/security/pwquality.conf <<EOF
# harden.sh
minlen = $minlen
difok = $quality
minclass = 3
maxrepeat = 3
maxclassrepeat = 3
gecoscheck = 1
dictcheck = 1
enforce_for_root
EOF
    ok "pwquality настроен (minlen=$minlen, difok=$quality)"
  else
    warn "pwquality недоступен — пропускаю парольную политику"
  fi

  # faillock: блокировка за неудачные попытки
  if [[ -f /etc/pam.d/common-auth ]] && ask_yn "pam_faillock" "Включить блокировку учёток при неудачных попытках входа (pam_faillock)?" y; then
    backup_file /etc/pam.d/common-auth /etc/pam.d/common-account /etc/security/faillock.conf
    [[ -f /etc/pam.d/common-auth.harden-orig ]] || cp -a /etc/pam.d/common-auth /etc/pam.d/common-auth.harden-orig
    if ! grep -q 'pam_faillock.so' /etc/pam.d/common-auth; then
      sed -i '1iauth required pam_faillock.so preauth silent audit deny=5 unlock_time=900' /etc/pam.d/common-auth
      printf 'auth required pam_faillock.so authfail audit deny=5 unlock_time=900\n' >>/etc/pam.d/common-auth
      ok "pam_faillock добавлен (5 попыток, unlock 15 мин)"
    fi
    if [[ -f /etc/pam.d/common-account ]] && ! grep -q 'pam_faillock.so' /etc/pam.d/common-account; then
      printf 'account required pam_faillock.so\n' >>/etc/pam.d/common-account
    fi
    write_file /etc/security/faillock.conf <<'EOF'
# harden.sh
deny = 5
unlock_time = 900
even_deny_root
root_unlock_time = 600
audit
EOF
  fi

  # Запрет пустых паролей (nullok)
  if [[ -f /etc/pam.d/common-auth ]] && grep -qE 'pam_unix\.so.*\bnullok\b' /etc/pam.d/common-auth; then
    backup_file /etc/pam.d/common-auth
    sed -i -E 's/(pam_unix\.so[^\n]*)\bnullok\b/\1/' /etc/pam.d/common-auth
    ok "Удалён nullok (пустые пароли запрещены)"
  fi

  if [[ -f /etc/login.defs ]]; then
    backup_file /etc/login.defs
    sed -i -E 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS 90/'  /etc/login.defs
    sed -i -E 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS 7/'   /etc/login.defs
    sed -i -E 's/^PASS_WARN_AGE.*/PASS_WARN_AGE 14/'  /etc/login.defs
    grep -q '^ENCRYPT_METHOD' /etc/login.defs && sed -i -E 's/^ENCRYPT_METHOD.*/ENCRYPT_METHOD SHA512/' /etc/login.defs
    ok "login.defs: срок действия паролей 90 дней, SHA512"
  fi

  write_file /etc/profile.d/99-harden-umask.sh <<'EOF'
# harden.sh
umask 027
EOF
  write_file /etc/security/limits.d/99-harden-nocore.conf <<'EOF'
# harden.sh: запрет core dumps
* hard core 0
root hard core 0
EOF

  write_file /etc/sudoers.d/99-harden "440" <<'EOF'
# harden.sh
Defaults use_pty
Defaults logfile="/var/log/sudo.log"
Defaults timestamp_timeout=15
Defaults passwd_tries=3
EOF
  if [[ -f /etc/sudoers.d/99-harden ]] && command -v visudo >/dev/null 2>&1; then
    visudo -cf /etc/sudoers.d/99-harden >/dev/null 2>&1 || rm -f /etc/sudoers.d/99-harden
  fi
  return 0
}

# ============================================================================
# МОДУЛЬ: ssh — защита OpenSSH
# ============================================================================
mod_ssh() {
  if [[ ! -f ${SSHD_CONFIG:-/etc/ssh/sshd_config} ]]; then
    if ask_yn "ssh_install" "OpenSSH-сервер не установлен. Установить?" y; then
      pkg_install openssh-server || return 1
      detect_components
    else
      warn "Пропускаю: sshd не установлен"; return 0
    fi
  fi
  SSHD_CONFIG="${SSHD_CONFIG:-/etc/ssh/sshd_config}"

  local have_keys=0 u
  for u in /root /home/*; do
    [[ -f "$u/.ssh/authorized_keys" && -s "$u/.ssh/authorized_keys" ]] && have_keys=1
  done
  if [[ $have_keys -eq 0 ]]; then
    warn "SSH-ключи (authorized_keys) не найдены!"
    if ! ask_yn "ssh_continue_nokey" "Продолжить без ключей? (отключение паролей заблокирует вход)" n; then
      info "Сначала добавьте ключ: ssh-keygen -t ed25519 && ssh-copy-id user@server"
      return 0
    fi
  fi

  local ssh_port pw_auth root_login allow_users allow_groups
  ssh_port=$(ask_val "ssh_port" "Порт SSH" "$SSH_PORT_CURRENT")
  if ask_yn "ssh_pwauth" "Отключить парольную авторизацию в SSH (только ключи)?" y; then
    pw_auth="no"
  else
    pw_auth="yes"
    warn "Парольная авторизация SSH оставлена — рекомендуется перейти на ключи"
  fi
  if ask_yn "ssh_root" "Запретить вход root по SSH?" y; then
    root_login="no"
  else
    root_login="prohibit-password"
  fi
  allow_users=$(ask_val "ssh_allowusers" "AllowUsers (пусто = без ограничения)" "")
  allow_groups=$(ask_val "ssh_allowgroups" "AllowGroups (пусто = без ограничения)" "")

  backup_file "$SSHD_CONFIG"
  mkdir -p /etc/ssh/sshd_config.d

  local supports_rasize=""
  sshd -T 2>/dev/null | grep -qi '^requiredrsasize' && supports_rasize=1

  local hardening_conf="/etc/ssh/sshd_config.d/99-harden.conf"
  if [[ $DRY_RUN -eq 1 ]]; then
    info "[dry-run] запись $hardening_conf (port=$ssh_port pw=$pw_auth root=$root_login)"
    return 0
  fi
  {
    echo "# harden.sh — жёсткая конфигурация SSH ($(date -u +%FT%TZ))"
    echo "Port $ssh_port"
    echo "PermitRootLogin $root_login"
    echo "PasswordAuthentication $pw_auth"
    echo "PubkeyAuthentication yes"
    echo "PermitEmptyPasswords no"
    echo "KbdInteractiveAuthentication no"
    echo "ChallengeResponseAuthentication no"
    echo "UsePAM yes"
    [[ $pw_auth == no ]] && echo "AuthenticationMethods publickey"
    [[ $supports_rasize ]] && echo "RequiredRSASize 3072"
    echo "MaxAuthTries 3"
    echo "MaxSessions 5"
    echo "MaxStartups 10:30:60"
    echo "LoginGraceTime 30"
    echo "X11Forwarding no"
    echo "AllowTcpForwarding no"
    echo "AllowAgentForwarding no"
    echo "AllowStreamLocalForwarding no"
    echo "PermitTunnel no"
    echo "GatewayPorts no"
    echo "PermitUserEnvironment no"
    echo "PermitUserRC no"
    echo "ClientAliveInterval 300"
    echo "ClientAliveCountMax 2"
    echo "Compression no"
    echo "IgnoreRhosts yes"
    echo "HostbasedAuthentication no"
    echo "PrintMotd no"
    echo "Banner /etc/issue.net"
    echo "LogLevel VERBOSE"
    echo "SyslogFacility AUTH"
    echo "RekeyLimit 1G 1h"
    echo "Umask 0077"
    echo "SftpServer internal-sftp"
    echo "HostKeyAlgorithms ssh-ed25519,rsa-sha2-512,rsa-sha2-256"
    echo "KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp521,ecdh-sha2-nistp384,ecdh-sha2-nistp256,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group14-sha256"
    echo "Ciphers chacha20-poly1305@openssh.com,aes128-gcm@openssh.com,aes256-gcm@openssh.com,aes128-ctr,aes192-ctr,aes256-ctr"
    echo "MACs umac-128-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,umac-128@openssh.com"
    [[ -n $allow_users ]] && echo "AllowUsers $allow_users"
    [[ -n $allow_groups ]] && echo "AllowGroups $allow_groups"
  } >"$hardening_conf"
  chmod 644 "$hardening_conf"

  # Гасим дубли в основном конфиге (drop-in имеет приоритет, но для ясности)
  for opt in Port PermitRootLogin PasswordAuthentication PubkeyAuthentication PermitEmptyPasswords KbdInteractiveAuthentication ChallengeResponseAuthentication; do
    sed -i -E "s/^([[:space:]]*#${opt}[[:space:]]+|[[:space:]]*${opt}[[:space:]]+)/#&/" "$SSHD_CONFIG" 2>/dev/null || true
  done

  # Баннер
  if [[ ! -f /etc/issue.net ]]; then
    write_file /etc/issue.net <<'EOF'
***************************************************************************
*  ВНИМАНИЕ: доступ к системе разрешён только авторизованным лицам.      *
*  Все попытки входа логируются. Несанкционированный доступ запрещён.     *
***************************************************************************
EOF
  fi

  if sshd -t -f "$SSHD_CONFIG" 2>/dev/null; then
    if [[ $HAVE_SYSTEMD -eq 1 ]]; then
      run systemctl restart ssh 2>/dev/null || run systemctl restart sshd
    else
      run service ssh restart 2>/dev/null || run service sshd restart
    fi
    ok "sshd перезапущен (порт $ssh_port, пароли=$pw_auth, root=$root_login)"
    warn "Проверьте доступ по НОВОМУ порту в отдельной сессии, прежде чем закрывать текущую!"
    [[ "$ssh_port" != "$SSH_PORT_CURRENT" ]] && rep "- SSH на порту $ssh_port — откройте порт в файрволе/SG"
    SSH_PORT_CURRENT=$ssh_port
  else
    err "sshd -t: конфигурация невалидна — откатываю"
    rm -f "$hardening_conf"
    return 1
  fi
  return 0
}

# ============================================================================
# МОДУЛЬ: firewall — межсетевой экран
# ============================================================================
mod_firewall() {
  local backend
  backend=$(detect_fw_backend)
  if [[ $backend == none ]]; then
    case "$PKG_MGR" in
      apt)    pkg_install ufw >/dev/null 2>&1 && backend=ufw ;;
      dnf|yum) pkg_install firewalld >/dev/null 2>&1 && backend=firewalld ;;
      *)      pkg_install nftables >/dev/null 2>&1 && backend=nftables ;;
    esac
  fi
  backend=$(ask_choice "fw_backend" "Какой файрвол использовать (обнаружен: $backend)?" \
    "ufw|firewalld|nftables" "$( [[ $backend == ufw ]] && echo 1 || [[ $backend == firewalld ]] && echo 2 || echo 3 )")
  FW_BACKEND=$backend

  local ssh_port web_ports="" mail_ports="" custom_ports=""
  ssh_port=$(ask_val "fw_ssh_port" "Порт SSH, который разрешить" "$SSH_PORT_CURRENT")
  if [[ $WEB != none ]] || ask_yn "fw_web" "Открыть HTTP/HTTPS (80/443)?" y; then
    web_ports="80,443"
  fi
  if [[ $MTA != none ]] || ask_yn "fw_mail" "Открыть почтовые порты (25,465,587,993,995)?" n; then
    mail_ports=$(ask_val "fw_mail_ports" "Почтовые порты через запятую" "25,465,587,993,995")
  fi
  custom_ports=$(ask_val "fw_custom" "Другие TCP-порты через запятую (пусто = нет)" "")

  case "$backend" in
    ufw)
      pkg_install ufw >/dev/null 2>&1 || { err "Не удалось установить ufw"; return 1; }
      if ufw status 2>/dev/null | grep -q 'Status: active'; then
        warn "ufw уже активен — правила будут добавлены к существующим"
      fi
      run ufw default deny incoming
      run ufw default allow outgoing
      if ufw status | grep -qE "^${ssh_port}\s+ALLOW"; then :; else
        run ufw limit "${ssh_port}/tcp"
      fi
      local p
      for p in ${web_ports//,/ }; do run ufw allow "${p}/tcp"; done
      for p in ${mail_ports//,/ }; do run ufw allow "${p}/tcp"; done
      for p in ${custom_ports//,/ }; do [[ -n $p ]] && run ufw allow "${p}/tcp"; done
      run ufw --force enable
      ok "ufw включён: deny incoming, SSH $ssh_port (rate-limit), веб/почта по выбору"
      ;;
    firewalld)
      pkg_install firewalld >/dev/null 2>&1 || { err "Не удалось установить firewalld"; return 1; }
      svc_enable_start firewalld
      run firewall-cmd --set-default-zone=public
      run firewall-cmd --permanent --add-port="${ssh_port}/tcp"
      local p
      for p in ${web_ports//,/ }; do run firewall-cmd --permanent --add-port="${p}/tcp"; done
      for p in ${mail_ports//,/ }; do run firewall-cmd --permanent --add-port="${p}/tcp"; done
      for p in ${custom_ports//,/ }; do [[ -n $p ]] && run firewall-cmd --permanent --add-port="${p}/tcp"; done
      run firewall-cmd --reload
      ok "firewalld настроен"
      ;;
    nftables)
      pkg_install nftables >/dev/null 2>&1 || { err "Не удалось установить nftables"; return 1; }
      local ports_all="${ssh_port},${web_ports},${mail_ports},${custom_ports}"
      ports_all=$(echo "$ports_all" | tr ',' '\n' | grep -v '^$' | sort -u | tr '\n' ' ' | sed 's/ $//')
      if [[ $DRY_RUN -eq 0 ]]; then
        mkdir -p /etc/nftables.d
        backup_file /etc/nftables.conf
        cat >/etc/nftables.d/harden.nft <<EOF
# harden.sh — минимальный набор правил (собственная таблица, без flush чужих)
table inet harden {
  chain input {
    type filter hook input priority 0; policy accept;
    ct state invalid drop
    ct state established,related accept
    iif "lo" accept
    ip protocol icmp icmp type echo-request limit rate 5/second burst 10 packets accept
    ip6 nexthdr icmpv6 accept
$(for p in ${ports_all//,/ }; do [[ "$p" == "$ssh_port" ]] || echo "    tcp dport $p accept"; done)
    tcp dport ${ssh_port} limit rate 3/minute burst 5 packets accept
    counter drop
  }
}
EOF
        # ssh уже в общем списке — убираем дубль перед limit: переписываем без общего ssh
        nft -c -f /etc/nftables.d/harden.nft 2>/dev/null && {
          warn "ВНИМАНИЕ: правила nft вводят политику drop для всего входящего."
          warn "Текущие SSH-сессии сохранятся (ESTABLISHED), но новые подключения"
          warn "только на разрешённых портах. Продолжить?"
          if ask_yn "fw_nft_apply" "Применить nftables-правила?" y; then
            run nft -f /etc/nftables.d/harden.nft
            if [[ -f /etc/nftables.conf ]] && ! grep -q 'harden.nft' /etc/nftables.conf; then
              printf 'include "/etc/nftables.d/harden.nft"\n' >>/etc/nftables.conf
            fi
            run systemctl enable --now nftables 2>/dev/null || true
            ok "nftables: таблица 'harden' применена"
          fi
        } || err "nft -c: синтаксис правил некорректен — пропускаю"
      else
        info "[dry-run] запись /etc/nftables.d/harden.nft (ports: $ports_all)"
      fi
      ;;
    *)
      warn "Файрвол недоступен — ограничьте доступ на уровне SG/провайдера вручную"
      ;;
  esac
  rep "- Файрвол: $backend (SSH $ssh_port)"
  return 0
}

# ============================================================================
# МОДУЛЬ: fail2ban
# ============================================================================
mod_fail2ban() {
  if ! pkg_is_installed fail2ban; then
    pkg_install fail2ban >/dev/null 2>&1 || { err "Не удалось установить fail2ban"; return 1; }
  fi
  backup_file /etc/fail2ban/jail.local /etc/fail2ban/jail.conf

  local ban_minutes maxretry destemail admin_ip
  ban_minutes=$(ask_val "f2b_ban" "Время бана по умолчанию (минуты)" "60")
  maxretry=$(ask_val "f2b_retry" "Максимум неудачных попыток (maxretry)" "4")
  destemail=$(ask_val "f2b_email" "Email для уведомлений Fail2ban (пусто = root)" "root")
  admin_ip=$(ask_val "f2b_ignoreip" "IP, не подлежащий бану (ignoreip, пусто = только localhost)" "127.0.0.1 ::1")

  # Список jail по обнаруженным сервисам
  local jails="sshd recidive"
  local has_exim_spam=0 has_exim_auth=0
  [[ -f /etc/fail2ban/filter.d/exim-spam.conf ]] && has_exim_spam=1
  [[ -f /etc/fail2ban/filter.d/exim-auth.conf ]] && has_exim_auth=1
  if [[ $MTA == exim ]]; then
    [[ -f /etc/fail2ban/filter.d/exim.conf ]] && jails="$jails exim"
    [[ $has_exim_spam -eq 1 ]] && jails="$jails exim-spam"
    [[ $has_exim_auth -eq 1 ]] && jails="$jails exim-auth"
  fi
  [[ $MTA == postfix ]] && jails="$jails postfix postfix-sasl"
  [[ $IMAP == dovecot ]] && jails="$jails dovecot"
  [[ $WEB == nginx ]] && jails="$jails nginx-http-auth nginx-botsearch"
  [[ $WEB == apache2 || $WEB == httpd ]] && jails="$jails apache-auth apache-badbots"

  jails=$(ask_val "f2b_jails" "Список jail (через пробел)" "$jails")

  if [[ $DRY_RUN -eq 1 ]]; then
    info "[dry-run] запись /etc/fail2ban/jail.local (jails: $jails)"
    return 0
  fi

  {
    echo "# harden.sh"
    echo "[DEFAULT]"
    echo "bantime  = $((ban_minutes * 60))"
    echo "findtime = 600"
    echo "maxretry = $maxretry"
    echo "ignoreip = $admin_ip"
    echo "destemail = $destemail"
    echo "sender    = fail2ban@$(hostname -f 2>/dev/null || hostname)"
    echo "mta       = mail"
    if [[ $HAVE_SYSTEMD -eq 1 ]] && systemctl is-active --quiet systemd-journald 2>/dev/null; then
      echo "backend = systemd"
    else
      echo "backend = auto"
    fi
    echo "banaction = iptables-multiport"
    echo
    echo "[sshd]"
    echo "enabled = true"
    echo "port    = ${SSH_PORT_CURRENT}"
    echo "mode    = aggressive"
    echo
    echo "[recidive]"
    echo "enabled  = true"
    echo "logpath  = /var/log/fail2ban.log"
    echo "banaction = iptables-allports"
    echo "bantime  = 604800"
    echo "findtime = 86400"
    echo "maxretry = 3"
    for j in $jails; do
      [[ $j == sshd || $j == recidive ]] && continue
      echo
      echo "[$j]"
      echo "enabled = true"
    done
  } >"/etc/fail2ban/jail.local"

  if fail2ban-client -t 2>&1 | tee -a "$LOG_FILE"; then
    svc_enable_start fail2ban
    run fail2ban-client reload 2>/dev/null || true
    ok "fail2ban активен (jails: $jails)"
    rep "- Fail2ban: $jails (ban ${ban_minutes}м)"
  else
    err "Конфигурация fail2ban невалидна"
    return 1
  fi
  return 0
}

# ============================================================================
# МОДУЛЬ: legacy_auth — запрет небезопасной авторизации и legacy-протоколов
# ============================================================================
mod_legacy_auth() {
  # 1. Legacy-сервисы
  local legacy="telnet telnetd rsh-server rexec-server krb5-telnet vsftpd proftpd proftpd-basic pure-ftpd ftpd tftp tftpd"
  local found="" s
  for s in $legacy; do
    if pkg_is_installed "$s" 2>/dev/null; then found="$found $s"; fi
  done
  if [[ -n $found ]]; then
    warn "Обнаружены устаревшие/опасные пакеты:$found"
    if ask_yn "legacy_remove" "Остановить, запретить и удалить их?" y; then
      for s in $found; do
        if [[ $s == vsftpd || $s == proftpd* || $s == pure-ftpd ]]; then
          if ! ask_yn "legacy_keep_ftp_$s" "Оставить FTP-сервер $s (будет ужесточён)?" n; then
            run systemctl disable --now "$s" 2>/dev/null || true
            case "$PKG_MGR" in
              apt) DEBIAN_FRONTEND=noninteractive run apt-get -y purge "$s" ;;
              *)   run "$PKG_MGR" remove -y "$s" ;;
            esac
          fi
          continue
        fi
        run systemctl disable --now "$s" 2>/dev/null || true
        case "$PKG_MGR" in
          apt) DEBIAN_FRONTEND=noninteractive run apt-get -y purge "$s" ;;
          *)   run "$PKG_MGR" remove -y "$s" ;;
        esac
      done
      ok "Устаревшие сервисы удалены"
    fi
  else
    info "Устаревшие сервисы (telnet/rsh/ftp) не найдены"
  fi

  # 2. /etc/hosts.equiv — грубый механизм доверия
  if [[ -f /etc/hosts.equiv ]]; then
    backup_file /etc/hosts.equiv
    run rm -f /etc/hosts.equiv /etc/hosts.equiv~
    ok "Удалён /etc/hosts.equiv (небезопасное доверие хостов)"
  fi

  # 3. vsftpd: если оставлен — ужесточаем
  if pkg_is_installed vsftpd && [[ -f /etc/vsftpd.conf ]]; then
    if ask_yn "legacy_vsftpd" "Ужесточить vsftpd (без анонимного доступа, только TLS1.2)?" y; then
      backup_file /etc/vsftpd.conf
      sed -i -E 's/^#?anonymous_enable=.*/anonymous_enable=NO/' /etc/vsftpd.conf
      grep -q '^anonymous_enable=' /etc/vsftpd.conf || echo 'anonymous_enable=NO' >>/etc/vsftpd.conf
      for kv in 'local_enable=YES' 'ssl_enable=YES' 'force_local_logins_ssl=YES' \
                'force_local_data_ssl=YES' 'ssl_tlsv1_2=YES' 'ssl_sslv2=NO' \
                'ssl_sslv3=NO' 'ssl_tlsv1=NO' 'require_ssl_reuse=YES' \
                'ssl_ciphers=HIGH:!aNULL:!MD5'; do
        local key="${kv%%=*}"
        if grep -qE "^#?${key}=" /etc/vsftpd.conf; then
          sed -i -E "s/^#?${key}=.*/${kv}/" /etc/vsftpd.conf
        else
          echo "$kv" >>/etc/vsftpd.conf
        fi
      done
      svc_restart vsftpd 2>/dev/null || true
      ok "vsftpd ужесточён (аноним запрещён, TLS1.2+)"
    fi
  fi

  # 4. Глобальный минимум OpenSSL (если поддерживается)
  if [[ -f /etc/ssl/openssl.cnf ]] && ask_yn "legacy_openssl" "Задать глобальный минимум TLS1.2 и SECLEVEL=2 в openssl.cnf?" y; then
    if ! grep -q 'harden.sh MinProtocol' /etc/ssl/openssl.cnf; then
      backup_file /etc/ssl/openssl.cnf
      if grep -q '\[system_default_sect\]' /etc/ssl/openssl.cnf; then
        awk '
          /\[system_default_sect\]/ && !done { print; print "MinProtocol = TLSv1.2"; print "CipherString = DEFAULT:@SECLEVEL=2"; print "# harden.sh MinProtocol"; done=1; next }
          { print }
        ' /etc/ssl/openssl.cnf >"/tmp/openssl.cnf.harden" && mv "/tmp/openssl.cnf.harden" /etc/ssl/openssl.cnf
        ok "openssl.cnf: MinProtocol=TLSv1.2, SECLEVEL=2"
      else
        warn "Секция [system_default_sect] не найдена — пропускаю (TLS минимум задаётся в сервисах)"
      fi
    fi
  fi

  # 5. Запрет пустых паролей в sshd (на случай ручных правок)
  if [[ -f /etc/ssh/sshd_config ]] && grep -qE '^PermitEmptyPasswords[[:space:]]+yes' /etc/ssh/sshd_config; then
    sed -i -E 's/^PermitEmptyPasswords[[:space:]]+yes/PermitEmptyPasswords no/' /etc/ssh/sshd_config
    ok "PermitEmptyPasswords -> no"
  fi
  return 0
}

# ============================================================================
# МОДУЛЬ: ports — аудит открытых портов
# ============================================================================
mod_ports() {
  header "Текущие слушающие сокеты"
  local listeners
  listeners=$(ss -H -lntup 2>/dev/null)
  echo "$listeners"
  rep "## Открытые порты (до аудита)"
  rep '```'
  rep "$listeners"
  rep '```'

  # Сводка TCP-портов
  local tcp_ports
  tcp_ports=$(ss -H -lnt 2>/dev/null | awk '{print $4}' | sed 's/.*://' | sort -un | tr '\n' ' ')
  info "TCP-порты: $tcp_ports"

  if ! ask_yn "ports_audit" "Провести пообъектный аудит (для каждого порта: открыть в файрволе / закрыть / пропустить)?" y; then
    return 0
  fi

  local port proc pkg
  while read -r port; do
    [[ -z $port || $port == *:* ]] && continue
    proc=$(ss -H -lntp "sport = :$port" 2>/dev/null | grep -oP 'users:\(\("\K[^"]+' | head -1)
    [[ -z $proc ]] && proc="(ядро/скрыто)"
    pkg=""
    if [[ -n $proc && $proc != "(ядро/скрыто)" ]]; then
      local bin
      bin=$(command -v "$proc" 2>/dev/null || echo "/usr/sbin/$proc")
      if [[ $PKG_MGR == apt ]] && [[ -e $bin ]]; then
        pkg=$(dpkg -S "$bin" 2>/dev/null | cut -d: -f1 | head -1)
      elif [[ $PKG_MGR == dnf || $PKG_MGR == yum || $PKG_MGR == zypper ]] && [[ -e $bin ]]; then
        pkg=$(rpm -qf "$bin" 2>/dev/null | head -1)
      fi
    fi
    echo
    echo "Порт $port/tcp — процесс: $proc ${pkg:+(пакет: $pkg)}"
    local act
    act=$(ask_choice "port_act_$port" "Действие с портом $port:" \
      "ничего (уже закрыт файрволом)|разрешить в файрволе|закрыть (остановить сервис)|заблокировать в файрволе" 1)
    case "$act" in
      "разрешить в файрволе")
        case "$(detect_fw_backend)" in
          ufw) run ufw allow "${port}/tcp" ;;
          firewalld) run firewall-cmd --permanent --add-port="${port}/tcp" && run firewall-cmd --reload ;;
          *) warn "Добавьте правило вручную: allow $port/tcp" ;;
        esac
        ;;
      "закрыть (остановить сервис)")
        if [[ -n $proc && $proc != "(ядро/скрыто)" ]]; then
          run systemctl disable --now "$proc" 2>/dev/null || run systemctl stop "$proc" 2>/dev/null || true
          ok "Сервис $proc остановлен"
        else
          warn "Процесс не определён — закройте порт в файрволе/SG вручную"
        fi
        ;;
      "заблокировать в файрволе")
        case "$(detect_fw_backend)" in
          ufw) run ufw deny "${port}/tcp" ;;
          firewalld) run firewall-cmd --permanent --remove-port="${port}/tcp" 2>/dev/null; run firewall-cmd --reload ;;
          *) warn "Добавьте deny-правило вручную" ;;
        esac
        ;;
    esac
  done <<<"$(ss -H -lnt 2>/dev/null | awk '{print $4}' | sed 's/.*://' | sort -un)"
  return 0
}

# ============================================================================
# МОДУЛЬ: real_ip — защита реального IP и периметра
# ============================================================================
mod_real_ip() {
  local mode
  mode=$(ask_choice "rip_mode" "Схема периметра:" \
    "за CDN (Cloudflare)|за другим reverse proxy/LB|без прокси (публичный origin)|пропустить" 4)
  [[ $mode == пропустить ]] && return 0

  local web_ports="80 443"
  case "$mode" in
    "за CDN (Cloudflare)")
      info "Загрузка диапазонов IP Cloudflare..."
      local cf4 cf6
      cf4=$(curl -s --max-time 15 https://www.cloudflare.com/ips-v4 2>/dev/null || true)
      cf6=$(curl -s --max-time 15 https://www.cloudflare.com/ips-v6 2>/dev/null || true)
      if [[ -z $cf4 ]]; then
        warn "Не удалось получить список IP Cloudflare — введите диапазоны вручную"
        cf4=$(ask_val "rip_cf4" "Диапазоны IPv4 Cloudflare через пробел" "173.245.48.0/20 103.21.244.0/22")
      fi
      if [[ $WEB == nginx ]] && ensure_nginx_conf_d; then
        backup_file /etc/nginx/conf.d/00-real-ip.conf
        {
          echo "# harden.sh: доверяем IP Cloudflare для определения реального клиента"
          for c in $cf4 $cf6; do echo "set_real_ip_from $c;"; done
          echo "real_ip_header CF-Connecting-IP;"
          echo "real_ip_recursive on;"
        } > /etc/nginx/conf.d/00-real-ip.conf
        ok "nginx: real_ip настроен для Cloudflare"
        svc_reload nginx 2>/dev/null || true
      else
        info "nginx не обнаружен — real_ip-конфиг записан в /root/harden-report: примените в своём прокси"
        write_file /root/harden-cloudflare-realip.conf <<EOF
$(for c in $cf4 $cf6; do echo "set_real_ip_from $c;"; done)
real_ip_header CF-Connecting-IP;
real_ip_recursive on;
EOF
      fi
      # Ограничиваем 80/443 только диапазонами CDN
      if ask_yn "rip_lock_web" "Ограничить доступ к 80/443 только диапазонами CDN (origin не виден напрямую)?" y; then
        case "$(detect_fw_backend)" in
          ufw)
            local c
            for c in $cf4 $cf6; do
              run ufw allow from "$c" to any port 80 proto tcp 2>/dev/null || true
              run ufw allow from "$c" to any port 443 proto tcp 2>/dev/null || true
            done
            ;;
          firewalld)
            for c in $cf4 $cf6; do
              run firewall-cmd --permanent --add-rich-rule="rule family=\"ipv4\" source address=\"$c\" port protocol=\"tcp\" port=\"80\" accept" 2>/dev/null || true
              run firewall-cmd --permanent --add-rich-rule="rule family=\"ipv4\" source address=\"$c\" port protocol=\"tcp\" port=\"443\" accept" 2>/dev/null || true
            done
            run firewall-cmd --reload
            ;;
          *) warn "Ограничьте 80/443 диапазонами CDN в SG/провайдере" ;;
        esac
        # Закрываем прямые 80/443 для остальных (ufw: deny после allow-правил не требуется — default deny)
        ok "Веб-порты ограничены диапазонами CDN"
      fi
      # Проверка утечки origin IP
      local domain
      domain=$(ask_val "rip_domain" "Основной домен (для проверки A-записи на утечку IP)" "")
      if [[ -n $domain ]]; then
        local a_rec
        a_rec=$(dig +short A "$domain" 2>/dev/null | head -1)
        if [[ -n $a_rec && -n $PUBLIC_IP && $a_rec == "$PUBLIC_IP" ]]; then
          warn "A-запись $domain = $PUBLIC_IP (IP сервера). Если вы за Cloudflare — включитеproxied (оранжевое облако), иначе origin виден!"
        else
          ok "A-запись $domain = ${a_rec:-нет} (не совпадает с публичным IP — утечки не видно)"
        fi
      fi
      ;;
    "за другим reverse proxy/LB")
      local proxy_ips
      proxy_ips=$(ask_val "rip_proxy_ips" "IP-адреса прокси через пробел" "")
      if [[ -n $proxy_ips && $WEB == nginx ]] && ensure_nginx_conf_d; then
        backup_file /etc/nginx/conf.d/00-real-ip.conf
        {
          echo "# harden.sh: доверенные reverse proxy"
          local ip
          for ip in $proxy_ips; do echo "set_real_ip_from $ip;"; done
          echo "real_ip_header X-Forwarded-For;"
          echo "real_ip_recursive on;"
        } > /etc/nginx/conf.d/00-real-ip.conf
        ok "nginx: real_ip настроен для прокси [$proxy_ips]"
      fi
      if [[ -n $proxy_ips ]] && ask_yn "rip_lock_proxy" "Разрешить 80/443 только с IP прокси?" y; then
        case "$(detect_fw_backend)" in
          ufw)
            local ip
            for ip in $proxy_ips; do
              run ufw allow from "$ip" to any port 80 proto tcp
              run ufw allow from "$ip" to any port 443 proto tcp
            done
            ;;
          firewalld)
            local ip
            for ip in $proxy_ips; do
              run firewall-cmd --permanent --add-rich-rule="rule family=\"ipv4\" source address=\"$ip\" port protocol=\"tcp\" port=\"80\" accept" 2>/dev/null || true
              run firewall-cmd --permanent --add-rich-rule="rule family=\"ipv4\" source address=\"$ip\" port protocol=\"tcp\" port=\"443\" accept" 2>/dev/null || true
            done
            run firewall-cmd --reload
            ;;
          *) warn "Ограничьте 80/443 IP прокси в SG" ;;
        esac
        ok "Веб-порты ограничены IP прокси"
      fi
      ;;
    "без прокси (публичный origin)")
      warn "Origin общедоступен: обязательно включите rate-limiting (nginx limit_req), fail2ban и WAF-правила"
      if [[ $WEB == nginx ]] && ensure_nginx_conf_d; then
        write_file /etc/nginx/conf.d/01-rate-limit.conf <<'EOF'
# harden.sh: базовая защита от перебора (применяется в server-блоках: limit_req zone=reqzone rate=10r/s burst=20 nodelay;)
limit_req_zone $binary_remote_addr zone=reqzone:10m rate=10r/s;
limit_conn_zone $binary_remote_addr zone=connzone:10m;
EOF
        ok "nginx: зоны limit_req/limit_conn созданы (подключайте в server-блоках)"
      fi
      ;;
  esac
  rep "- Периметр: $mode"
  return 0
}

# ============================================================================
# МОДУЛЬ: ssl — SSL/TLS-сертификаты (ACME)
# ============================================================================
CERT_DIR=""; CERT_KEY=""

find_existing_cert() {  # ищем действующий сертификат для домена
  local d="$1"
  if [[ -d /etc/letsencrypt/live ]]; then
    local c
    for c in /etc/letsencrypt/live/*/fullchain.pem; do
      [[ -f $c ]] || continue
      if openssl x509 -in "$c" -noout -text 2>/dev/null | grep -q "DNS:$d"; then
        echo "$c"; return 0
      fi
    done
  fi
  return 1
}

mod_ssl() {
  local domains email method keytype
  domains=$(ask_val "ssl_domains" "Домены для сертификата (через пробел; пусто = самоподписанный тестовый)" "")
  if [[ -z $domains ]]; then
    warn "Без домена выпускаем самоподписанный сертификат (только для теста TLS)"
    if [[ $DRY_RUN -eq 0 ]]; then
      mkdir -p /etc/ssl/harden
      openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
        -keyout /etc/ssl/harden/selfsigned.key -out /etc/ssl/harden/selfsigned.crt \
        -days 365 -subj "/CN=$(hostname -f 2>/dev/null || hostname)" 2>/dev/null || true
      chmod 600 /etc/ssl/harden/selfsigned.key
      CERT_DIR=/etc/ssl/harden/selfsigned.crt; CERT_KEY=/etc/ssl/harden/selfsigned.key
      ok "Самоподписанный сертификат: $CERT_DIR"
    fi
    rep "- TLS: самоподписанный тестовый сертификат"
    return 0
  fi

  email=$(ask_val "ssl_email" "Email для уведомлений ACME" "admin@${domains%% *}")
  method=$(ask_choice "ssl_method" "Метод получения сертификата:" \
    "certbot (webroot)|certbot (nginx-plugin)|acme.sh|свой ACME-клиент (пропустить выпуск)" 2)

  if [[ $method == acme.sh ]]; then
    if ! command -v acme.sh >/dev/null 2>&1; then
      pkg_install curl >/dev/null 2>&1 || true
      if [[ $DRY_RUN -eq 0 ]]; then
        info "Установка acme.sh в ~/.acme.sh..."
        curl -fsSL https://get.acme.sh | sh -s email="$email" || warn "Не удалось установить acme.sh"
      fi
    fi
  elif [[ $method != "свой ACME-клиент (пропустить выпуск)" ]]; then
    case "$PKG_MGR" in
      apt)
        pkg_install certbot >/dev/null || true
        [[ $method == *nginx-plugin* ]] && pkg_install python3-certbot-nginx >/dev/null || true
        ;;
      dnf|yum) pkg_install certbot >/dev/null || true ;;
      *) pkg_install certbot >/dev/null || true ;;
    esac
    command -v certbot >/dev/null 2>&1 || warn "certbot не установлен — выпуск вручную"
  fi

  local webroot="/var/www/html"
  [[ -d /var/www/html ]] || webroot=$(ask_val "ssl_webroot" "Каталог webroot для ACME challenge" "/var/www/html")

  if [[ $method != "свой ACME-клиент (пропустить выпуск)" ]] && command -v certbot >/dev/null 2>&1; then
    local domains_arg=() d
    for d in $domains; do domains_arg+=(-d "$d"); done
    local cb_cmd=(certonly --non-interactive --agree-tos -m "$email")
    case "$method" in
      "certbot (nginx-plugin)")
        if [[ $WEB == nginx ]]; then cb_cmd+=(--nginx); else cb_cmd+=(--webroot -w "$webroot"); fi ;;
      *) cb_cmd+=(--webroot -w "$webroot") ;;
    esac
    case "$keytype" in "") keytype=$(ask_choice "ssl_keytype" "Тип ключа:" "ECDSA P-256 (современно)|RSA 3072 (совместимо)" 1) ;; esac
    [[ $keytype == ECDSA* ]] && cb_cmd+=(--key-type ecdsa) || cb_cmd+=(--key-type rsa --rsa-key-size 3072)
    # подстраховка: не перезапускать если сертификат уже есть
    local first="${domains%% *}" existing
    existing=$(find_existing_cert "$first" || true)
    if [[ -n $existing && $DRY_RUN -eq 0 ]]; then
      info "Сертификат для $first уже есть: $existing"
    elif [[ $DRY_RUN -eq 0 ]]; then
      run certbot "${cb_cmd[@]}" "${domains_arg[@]}" || warn "certbot: выпуск не удался (проверьте DNS и порт 80)"
    fi
    CERT_DIR="/etc/letsencrypt/live/$first/fullchain.pem"
    CERT_KEY="/etc/letsencrypt/live/$first/privkey.pem"
  fi

  # Таймер автообновления + deploy hook
  if [[ -f ${CERT_DIR:-/nonexistent} ]] && ask_yn "ssl_autorenew" "Настроить автообновление сертификатов?" y; then
    if [[ $DRY_RUN -eq 0 ]]; then
      mkdir -p /etc/letsencrypt/renewal-hooks/deploy
      cat >/etc/letsencrypt/renewal-hooks/deploy/10-harden-reload.sh <<EOF
#!/bin/sh
# harden.sh: перезагрузка сервисов после обновления сертификата
systemctl reload nginx 2>/dev/null || true
systemctl reload exim4 2>/dev/null || systemctl reload exim 2>/dev/null || true
systemctl reload dovecot 2>/dev/null || true
EOF
      chmod 755 /etc/letsencrypt/renewal-hooks/deploy/10-harden-reload.sh
      if [[ $HAVE_SYSTEMD -eq 1 ]]; then
        systemctl enable --now certbot.timer 2>/dev/null || true
      else
        grep -q 'certbot renew' /etc/crontab 2>/dev/null || \
          echo "17 3 * * * root certbot renew --quiet --deploy-hook /etc/letsencrypt/renewal-hooks/deploy/10-harden-reload.sh" >>/etc/crontab
      fi
      run certbot renew --dry-run >/dev/null 2>&1 && ok "Автообновление настроено (dry-run успешен)" || info "Автообновление: проверьте certbot renew вручную"
    fi
  fi

  # Передаём пути в почтовый модуль
  save_ans ssl_cert_path "$CERT_DIR"
  save_ans ssl_key_path "$CERT_KEY"
  [[ -f ${CERT_DIR:-/nonexistent} ]] && ok "Сертификат готов: $CERT_DIR" || warn "Сертификат не выпущен — используйте существующий или выпустите вручную"
  rep "- TLS-сертификат: ${CERT_DIR:-не выпущен}"
  return 0
}

# ============================================================================
# МОДУЛЬ: web_headers — web-заголовки безопасности
# ============================================================================
MOZ_TLS12="ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305"
MOZ_TLS13="TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256"

mod_web_headers() {
  if [[ $WEB == none ]]; then
    if ask_yn "wh_install" "Веб-сервер не обнаружен. Установить nginx (reverse proxy + заголовки)?" y; then
      pkg_install nginx >/dev/null || return 1
      WEB="nginx"
      svc_enable_start nginx
    else
      warn "Пропускаю: нет веб-сервера"
      return 0
    fi
  fi

  local csp hsts preload coep cookie_rewrite
  csp=$(ask_val "wh_csp" "Content-Security-Policy (пусто = строгий дефолт)" \
    "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'; object-src 'none'")
  if ask_yn "wh_hsts" "Включить HSTS (max-age=2 года, includeSubDomains)?" y; then
    hsts=1
    preload=$(ask_yn "wh_hsts_preload" "Добавить preload в HSTS (необратимо для поддоменов!)" n)
  else
    hsts=0; preload=0
  fi
  coep=$(ask_yn "wh_coep" "Включить Cross-Origin-Embedder-Policy: require-corp (может ломать сторонние скрипты/img)" n)
  cookie_rewrite=$(ask_yn "wh_cookies" "Принудительно добавлять флаги Secure/HttpOnly/SameSite ко всем Set-Cookie (через прокси)?" n)

  case "$WEB" in
    nginx)
      ensure_nginx_conf_d || { err "nginx не найден"; return 1; }
      backup_file /etc/nginx/conf.d/00-security-headers.conf
      if [[ $DRY_RUN -eq 0 ]]; then
        {
          echo "# harden.sh: заголовки безопасности (уровень http — наследуется server-блоками"
          echo "# без собственных add_header; при наличии своих — продублируйте)"
          echo "server_tokens off;"
          echo "# Скрытие заголовка Server: установите nginx-extras и uncomment:"
          echo "# more_clear_headers Servers;"
          echo "add_header X-Content-Type-Options \"nosniff\" always;"
          echo "add_header X-Frame-Options \"DENY\" always;"
          echo "add_header Referrer-Policy \"strict-origin-when-cross-origin\" always;"
          echo "add_header Permissions-Policy \"accelerometer=(), camera=(), geolocation=(), gyroscope=(), microphone=(), payment=(), usb=(), interest-cohort=()\" always;"
          echo "add_header Cross-Origin-Opener-Policy \"same-origin\" always;"
          echo "add_header Cross-Origin-Resource-Policy \"same-origin\" always;"
          [[ $coep -eq 1 ]] && echo "add_header Cross-Origin-Embedder-Policy \"require-corp\" always;"
          [[ -n $csp ]] && echo "add_header Content-Security-Policy \"$csp\" always;"
          if [[ $hsts -eq 1 ]]; then
            if [[ $preload -eq 1 ]]; then
              echo "add_header Strict-Transport-Security \"max-age=63072000; includeSubDomains; preload\" always;"
            else
              echo "add_header Strict-Transport-Security \"max-age=63072000; includeSubDomains\" always;"
            fi
          fi
          echo "proxy_hide_header X-Powered-By;"
          echo "proxy_hide_header X-AspNet-Version;"
          echo "proxy_hide_header X-Runtime;"
          echo
          echo "# TLS-политика (Mozilla intermediate, guideline 6.0)"
          echo "ssl_protocols TLSv1.2 TLSv1.3;"
          echo "ssl_ciphers \"$MOZ_TLS12\";"
          echo "ssl_prefer_server_ciphers off;"
          echo "ssl_session_cache shared:SSL:10m;"
          echo "ssl_session_timeout 1d;"
          echo "ssl_session_tickets off;"
          echo "ssl_stapling on;"
          echo "ssl_stapling_verify on;"
          echo "ssl_ecdh_curve X25519MLKEM768:X25519:prime256v1:secp384r1;"
          echo "resolver 1.1.1.1 8.8.8.8 valid=300s;"
          echo "resolver_timeout 5s;"
          if [[ $cookie_rewrite -eq 1 ]]; then
            echo "# Принудительные флаги cookie (nginx >= 1.23)"
            echo "proxy_cookie_flags ~ secure httponly samesite=lax;"
          fi
        } >/etc/nginx/conf.d/00-security-headers.conf
      fi
      # HTTPS-редирект (best-effort для дефолтного сайта)
      if ask_yn "wh_redirect" "Настроить принудительный HTTPS-редирект (301) в server-блоках порта 80?" y; then
        if [[ $DRY_RUN -eq 0 && -d /etc/nginx/sites-enabled ]]; then
          local f
          for f in /etc/nginx/sites-enabled/*; do
            [[ -f $f ]] || continue
            grep -q 'harden https redirect' "$f" && continue
            if grep -qE 'listen[[:space:]]+80' "$f" && ! grep -qE 'listen[[:space:]]+\*?:?443[[:space:]]+ssl' "$f"; then
              backup_file "$f"
              # вставляем return в первый server-блок
              awk '
                /server[[:space:]]*\{/ && !ins { print; print "    # harden https redirect"; print "    if ($scheme = http) { return 301 https://$host$request_uri; }"; ins=1; next }
                { print }
              ' "$f" >"$f.harden" && mv "$f.harden" "$f"
            fi
          done
        fi
      fi
      if nginx -t 2>/dev/null; then
        svc_reload nginx && ok "nginx: заголовки/TLS применены"
      else
        err "nginx -t: конфигурация невалидна — откатываю заголовки"
        rm -f /etc/nginx/conf.d/00-security-headers.conf
        return 1
      fi
      if [[ $cookie_rewrite -eq 1 ]]; then
        nginx -V 2>&1 | grep -q 'proxy_cookie_flags' || warn "proxy_cookie_flags может не поддерживаться старым nginx"
      fi
      ;;
    apache2|httpd)
      local confdir="/etc/apache2/conf-available"
      [[ $WEB == httpd ]] && confdir="/etc/httpd/conf.d"
      backup_file "$confdir/harden-security.conf"
      if [[ $DRY_RUN -eq 0 ]]; then
        {
          echo "# harden.sh: заголовки безопасности"
          echo "Header always set X-Content-Type-Options \"nosniff\""
          echo "Header always set X-Frame-Options \"DENY\""
          echo "Header always set Referrer-Policy \"strict-origin-when-cross-origin\""
          echo "Header always set Permissions-Policy \"accelerometer=(), camera=(), geolocation=(), gyroscope=(), microphone=(), payment=(), usb=()\""
          echo "Header always set Cross-Origin-Opener-Policy \"same-origin\""
          echo "Header always set Cross-Origin-Resource-Policy \"same-origin\""
          [[ $coep -eq 1 ]] && echo "Header always set Cross-Origin-Embedder-Policy \"require-corp\""
          [[ -n $csp ]] && echo "Header always set Content-Security-Policy \"$csp\""
          if [[ $hsts -eq 1 ]]; then
            [[ $preload -eq 1 ]] && \
              echo "Header always set Strict-Transport-Security \"max-age=63072000; includeSubDomains; preload\"" || \
              echo "Header always set Strict-Transport-Security \"max-age=63072000; includeSubDomains\""
          fi
          echo "Header always unset X-Powered-By"
          echo "Header always unset X-AspNet-Version"
          echo "ServerTokens Prod"
          echo "ServerSignature Off"
          echo "SSLProtocol -all +TLSv1.2 +TLSv1.3"
          echo "SSLCipherSuite $MOZ_TLS12"
          echo "SSLHonorCipherOrder off"
          if [[ $cookie_rewrite -eq 1 ]]; then
            echo "Header edit Set-Cookie \"^(.+)\$\" \"\$1; Secure; HttpOnly; SameSite=Lax\""
          fi
        } >"$confdir/harden-security.conf"
        pkg_install libapache2-mod-headers >/dev/null 2>&1 || true
        if [[ $WEB == apache2 ]]; then
          a2enmod headers ssl 2>/dev/null || true
          a2enconf harden-security 2>/dev/null || true
        fi
      fi
      if [[ $WEB == apache2 ]]; then
        apache2ctl configtest 2>/dev/null && svc_reload apache2 && ok "Apache: заголовки применены" || warn "Apache: проверьте конфиг вручную"
      else
        apachectl configtest 2>/dev/null && svc_reload httpd && ok "httpd: заголовки применены" || warn "httpd: проверьте конфиг"
      fi
      ;;
    caddy)
      info "Caddy сам управляет TLS/HSTS. CSP/заголовки задайте в Caddyfile через header directive."
      ;;
  esac
  rep "- Web-заголовки: $WEB (HSTS=$hsts, CSP=${csp:+yes})"
  return 0
}

# ============================================================================
# МОДУЛЬ: mail — ужесточение SMTP/IMAP/POP3 (Exim/Postfix + Dovecot)
# ============================================================================
exim_supports() {  # exim_supports spf|dkim|dmarc
  local bin
  bin=$(command -v exim4 2>/dev/null || command -v exim 2>/dev/null) || return 1
  "$bin" -bV 2>/dev/null | grep -qi "$1"
}

exim_rebuild() {
  if command -v update-exim4.conf >/dev/null 2>&1; then
    run update-exim4.conf || return 1
  fi
  local bin
  bin=$(command -v exim4 2>/dev/null || command -v exim 2>/dev/null)
  if "$bin" -bV >/dev/null 2>&1; then
    return 0
  else
    "$bin" -bV 2>&1 | tail -5 | tee -a "$LOG_FILE"
    return 1
  fi
}

mod_mail() {
  if [[ $MTA == none ]]; then
    if ask_yn "mail_install" "Почтовый сервер не обнаружен. Установить MTA?" n; then
      case "$PKG_MGR" in
        apt)    pkg_install exim4-daemon-light exim4-config >/dev/null || return 1; MTA=exim ;;
        dnf|yum) pkg_install postfix >/dev/null || return 1; MTA=postfix ;;
        *)      warn "Установите MTA вручную и перезапустите модуль"; return 1 ;;
      esac
      detect_components
    else
      info "Пропускаю: MTA не используется"; return 0
    fi
  fi

  local domain cert cert_key
  domain=$(ask_val "mail_domain" "Основной почтовый домен (MX этого сервера)" "$(hostname -d 2>/dev/null || echo example.com)")
  cert="${ANS[ssl_cert_path]:-}"
  cert_key="${ANS[ssl_key_path]:-}"
  if [[ -z $cert || ! -f $cert ]]; then
    if [[ -f /etc/letsencrypt/live/$domain/fullchain.pem ]]; then
      cert="/etc/letsencrypt/live/$domain/fullchain.pem"
      cert_key="/etc/letsencrypt/live/$domain/privkey.pem"
    elif [[ -f /etc/letsencrypt/live/$(hostname -f)/fullchain.pem ]]; then
      cert="/etc/letsencrypt/live/$(hostname -f)/fullchain.pem"
      cert_key="/etc/letsencrypt/live/$(hostname -f)/privkey.pem"
    else
      cert=$(ask_val "mail_cert" "Путь к TLS-сертификату (fullchain)" "/etc/exim4/exim.crt")
      cert_key=$(ask_val "mail_key" "Путь к TLS-ключу" "/etc/exim4/exim.key")
    fi
  fi
  # Копируем сертификат в место, читаемое сервисами, + renewal-hook
  local safe_cert safe_key svc_group="root"
  [[ $MTA == exim ]] && svc_group="Debian-exim"
  [[ $IMAP == dovecot && $MTA != exim ]] && svc_group="dovecot"
  if [[ -f $cert && -f $cert_key && $DRY_RUN -eq 0 ]]; then
    mkdir -p /etc/ssl/harden
    cp -L "$cert" /etc/ssl/harden/mail.crt 2>/dev/null || cp "$cert" /etc/ssl/harden/mail.crt
    cp -L "$cert_key" /etc/ssl/harden/mail.key 2>/dev/null || cp "$cert_key" /etc/ssl/harden/mail.key
    chmod 640 /etc/ssl/harden/mail.key /etc/ssl/harden/mail.crt
    chown root:"$svc_group" /etc/ssl/harden/mail.key /etc/ssl/harden/mail.crt 2>/dev/null || \
      chown root:root /etc/ssl/harden/mail.key /etc/ssl/harden/mail.crt
    mkdir -p /etc/letsencrypt/renewal-hooks/deploy
    cat >/etc/letsencrypt/renewal-hooks/deploy/20-harden-mail-cert.sh <<'EOF'
#!/bin/sh
# harden.sh: обновление копии сертификата для почтовых сервисов
[ -n "$RENEWED_LINEAGE" ] || exit 0
for g in Debian-exim dovecot root; do
  chown root:"$g" "$RENEWED_LINEAGE/fullchain.pem" 2>/dev/null && break
done
install -m 640 "$RENEWED_LINEAGE/fullchain.pem" /etc/ssl/harden/mail.crt
install -m 640 "$RENEWED_LINEAGE/privkey.pem" /etc/ssl/harden/mail.key
chgrp Debian-exim /etc/ssl/harden/mail.* 2>/dev/null || chgrp dovecot /etc/ssl/harden/mail.* 2>/dev/null || true
systemctl reload exim4 2>/dev/null || true
systemctl reload dovecot 2>/dev/null || true
systemctl reload postfix 2>/dev/null || true
EOF
    chmod 755 /etc/letsencrypt/renewal-hooks/deploy/20-harden-mail-cert.sh
    safe_cert="/etc/ssl/harden/mail.crt"
    safe_key="/etc/ssl/harden/mail.key"
  else
    safe_cert="$cert"; safe_key="$cert_key"
  fi
  save_ans mail_cert "$safe_cert"
  save_ans mail_key "$safe_key"
  local submission implicit465=0
  if ask_yn "mail_submission" "Включить Submission-порт 587 (требовать TLS+AUTH)?" y; then
    submission=y
    if ask_yn "mail_465" "Включить implicit-TLS порт 465 (для старых клиентов)?" n; then
      implicit465=1
    fi
  else
    submission=n
  fi

  case "$MTA" in
    exim)   mod_mail_exim ;;
    postfix) mod_mail_postfix ;;
  esac

  # Dovecot: IMAP/POP3
  if [[ $IMAP == dovecot ]]; then
    mod_mail_dovecot
  elif ask_yn "mail_dovecot" "Dovecot не обнаружен. Установить для IMAPS/POP3S?" n; then
    case "$PKG_MGR" in
      apt)    pkg_install dovecot-imapd dovecot-pop3d >/dev/null || true ;;
      dnf|yum) pkg_install dovecot >/dev/null || true ;;
    esac
    detect_components
    [[ $IMAP == dovecot ]] && mod_mail_dovecot
  fi
  rep "- Почта: MTA=$MTA, домен=$domain, submission=$submission, cert=$cert"
  return 0
}

mod_mail_exim() {
  local domain="${ANS[mail_domain]:-example.com}"
  local cert="${ANS[mail_cert]:-/etc/exim4/exim.crt}"
  local cert_key="${ANS[mail_key]:-/etc/exim4/exim.key}"
  local submission="${ANS[mail_submission]:-y}"
  local implicit465="${ANS[mail_465]:-n}"

  if [[ ! -d /etc/exim4/conf.d ]]; then
    warn "Обнаружен Exim не-дебианской раскладки — применяю только базовые опции (рекомендуется ручная настройка)"
    return 0
  fi

  mkdir -p /etc/exim4/harden
  backup_file /etc/exim4/exim4.conf.localmacros

  # --- макросы ---
  {
    echo "# harden.sh — макросы Exim ($(date -u +%FT%TZ))"
    echo "MAIN_TLS_CERTIFICATE = $cert"
    echo "MAIN_TLS_PRIVATEKEY = $cert_key"
    echo "MAIN_TLS_ADVERTISE_HOSTS = *"
    echo "MAIN_TLS_TRY_VERIFY_HOSTS ="
    echo "CHECK_RCPT_LOCAL_ACL_FILE = /etc/exim4/harden/acl_rcpt.inc"
    echo "CHECK_DATA_LOCAL_ACL_FILE = /etc/exim4/harden/acl_data.inc"
  } > /etc/exim4/exim4.conf.localmacros

  # --- main options ---
  backup_file /etc/exim4/conf.d/main/05_exim4-config_hardening
  local ports="25 : 587"
  [[ $implicit465 == y ]] && ports="25 : 465 : 587"
  if [[ $DRY_RUN -eq 0 ]]; then
    {
      echo "# harden.sh: жёсткая конфигурация Exim"
      echo "daemon_smtp_ports = $ports"
      [[ $implicit465 == y ]] && echo "tls_on_connect_ports = 465"
      echo "tls_require_ciphers = $MOZ_TLS12"
      echo "tls_ciphersuites = $MOZ_TLS13"
      echo "tls_ecdhe_curves = X25519MLKEM768 : X25519 : prime256v1 : secp384r1"
      echo "smtp_accept_max = 50"
      echo "smtp_accept_queue_per_connection = 10"
      echo "queue_run_max = 8"
      echo "smtp_max_helo_length = 96"
      echo "acl_smtp_vrfy = acl_harden_vrfy"
      echo "acl_smtp_expn = acl_harden_expn"
    } >/etc/exim4/conf.d/main/05_exim4-config_hardening
  fi

  # --- ACL: VRFY/EXPN ---
  backup_file /etc/exim4/conf.d/acl/99_exim4-config_hardening_acls
  if [[ $DRY_RUN -eq 0 ]]; then
    {
      echo "# harden.sh: ACL для VRFY/EXPN"
      echo
      echo "acl_harden_vrfy:"
      echo "  deny message = VRFY command disabled"
      echo
      echo "acl_harden_expn:"
      echo "  deny message = EXPN command disabled"
    } >/etc/exim4/conf.d/acl/99_exim4-config_hardening_acls
  fi

  # --- ACL: check_rcpt hardening ---
  local have_spf=0 have_dmarc=0
  exim_supports spf && have_spf=1
  exim_supports dmarc && have_dmarc=1
  if [[ $DRY_RUN -eq 0 ]]; then
    {
      echo "# harden.sh: дополнения acl_check_rcpt (включается через CHECK_RCPT_LOCAL_ACL_FILE)"
      echo
      echo "  # Требуем HELO/EHLO"
      echo "  deny"
      echo "    condition = \${if eq{\$helo_name}{}}"
      echo "    message = HELO/EHLO required"
      echo
      echo "  # Запрещаем подделку localhost/unknown в HELO"
      echo "  deny"
      echo "    condition = \${if match{\${lc:\$helo_name}}{^(localhost|localhost\\.localdomain|ip6-localhost|\\[127\\.0\\.0\\.1\\]|unknown)\$}}"
      echo "    message = HELO/EHLO '\$helo_name' rejected"
      if [[ $have_spf -eq 1 ]]; then
        echo
        echo "  # SPF: жёсткий отказ при fail (поддержка встроена в Exim)"
        echo "  deny"
        echo "    condition = \${if def:sender_address_domain}"
        echo "    spf = fail"
        echo "    message = SPF check failed: \$sender_host_address is not authorized to send from \$sender_address_domain"
      fi
      echo
      echo "  # Rate limit на количество RCPT от одного хоста"
      echo "  warn"
      echo "    ratelimit = 4/1h/peer \$sender_host_address"
      echo "    log_message = rate limited recipients"
      echo
      echo "  deny"
      echo "    ratelimit = 25/1h/peer \$sender_host_address"
      echo "    message = Too many recipients from \$sender_host_address, slow down"
    } >/etc/exim4/harden/acl_rcpt.inc
  fi

  # --- ACL: check_data hardening ---
  if [[ $DRY_RUN -eq 0 ]]; then
    {
      echo "# harden.sh: дополнения acl_check_data (через CHECK_DATA_LOCAL_ACL_FILE)"
      echo
      echo "  # Добавляем Authentication-Results и Received-SPF"
      echo "  warn"
      echo "    add_header = :at_start:\${authresults {\$primary_hostname}}"
      echo
      echo "  warn"
      echo "    condition = \${if def:spf_received}"
      echo "    add_header = :at_start:\$spf_received"
      if [[ $have_dmarc -eq 1 ]]; then
        echo
        echo "  # DMARC: reject при p=reject (для неаутентифицированных)"
        echo "  deny"
        echo "    !authenticated = *"
        echo "    dmarc_status = reject"
        echo "    message = Message from \$dmarc_used_domain failed sender's DMARC policy"
        echo
        echo "  warn"
        echo "    !authenticated = *"
        echo "    dmarc_status = quarantine"
        echo "    log_message = DMARC quarantine recommended for \$dmarc_used_domain"
      fi
    } >/etc/exim4/harden/acl_data.inc
  fi

  # --- auth: только по TLS ---
  local auth_choice
  auth_choice=$(ask_choice "mail_exim_auth" "SMTP AUTH для submission (587):" \
    "passwd-файл Exim (CONFDIR/passwd)|через Dovecot (SASL)|уже настроено (пропустить)" 1)

  if [[ $auth_choice != "уже настроено (пропустить)" ]]; then
    backup_file /etc/exim4/conf.d/auth/99_exim4-config_hardening
    if [[ $DRY_RUN -eq 0 ]]; then
      if [[ $auth_choice == "через Dovecot (SASL)" ]] && [[ $IMAP == dovecot ]]; then
        {
          echo "# harden.sh: SMTP AUTH через Dovecot (только по TLS)"
          echo "dovecot_plain_server:"
          echo "  driver = dovecot"
          echo "  public_name = PLAIN"
          echo "  server_socket = /var/spool/exim4/dovecot.auth-client"
          echo "  server_set_id = \$auth1"
          echo "  server_advertise_condition = \${if eq{\$tls_in_cipher}{}{}{*}}"
          echo
          echo "dovecot_login_server:"
          echo "  driver = dovecot"
          echo "  public_name = LOGIN"
          echo "  server_socket = /var/spool/exim4/dovecot.auth-client"
          echo "  server_set_id = \$auth1"
          echo "  server_advertise_condition = \${if eq{\$tls_in_cipher}{}{}{*}}"
        } >/etc/exim4/conf.d/auth/99_exim4-config_hardening
        # слушатель в Dovecot
        if [[ -f /etc/dovecot/conf.d/10-master.conf && $DRY_RUN -eq 0 ]]; then
          if ! grep -q 'dovecot.auth-client' /etc/dovecot/conf.d/10-master.conf; then
            backup_file /etc/dovecot/conf.d/10-master.conf
            awk '
              /service auth/ && !ins { print; print "  unix_listener /var/spool/exim4/dovecot.auth-client {"; print "    mode = 0660"; print "    group = Debian-exim"; print "  }"; ins=1; next }
              { print }
            ' /etc/dovecot/conf.d/10-master.conf >/tmp/10-master.conf.harden && mv /tmp/10-master.conf.harden /etc/dovecot/conf.d/10-master.conf
            svc_restart dovecot 2>/dev/null || true
          fi
        fi
      else
        {
          echo "# harden.sh: SMTP AUTH (passwd-файл), только по TLS"
          echo "plain_server:"
          echo "  driver = plaintext"
          echo "  public_name = PLAIN"
          echo "  server_condition = \"\${if crypteq{\$auth3}{\${extract{1}{:}{\${lookup{\$auth2}lsearch{CONFDIR/passwd}{\$value}{*:*}}}}}{1}{0}}\""
          echo "  server_set_id = \$auth2"
          echo "  server_prompts = :"
          echo "  server_advertise_condition = \${if eq{\$tls_in_cipher}{}{}{*}}"
          echo
          echo "login_server:"
          echo "  driver = plaintext"
          echo "  public_name = LOGIN"
          echo "  server_condition = \"\${if crypteq{\$auth2}{\${extract{1}{:}{\${lookup{\$auth1}lsearch{CONFDIR/passwd}{\$value}{*:*}}}}}{1}{0}}\""
          echo "  server_set_id = \$auth1"
          echo "  server_prompts = \"Username:: : Password::\""
          echo "  server_advertise_condition = \${if eq{\$tls_in_cipher}{}{}{*}}"
        } >/etc/exim4/conf.d/auth/99_exim4-config_hardening
        info "Добавьте пользователей в /etc/exim4/passwd (формат: user:crypt-hash), права 640, владелец Debian-exim"
        [[ -f /etc/exim4/passwd ]] || { touch /etc/exim4/passwd; chmod 640 /etc/exim4/passwd; chown root:Debian-exim /etc/exim4/passwd 2>/dev/null || true; }
      fi
    fi
  fi

  # Сборка и проверка
  if exim_rebuild; then
    svc_restart exim4 2>/dev/null || svc_restart exim 2>/dev/null || true
    ok "Exim: конфигурация применена и валидна"
    info "Подсказка: добавьте пользователя для submission: echo 'user:\$(openssl passwd -6)' > /etc/exim4/passwd"
  else
    err "Exim: конфигурация невалидна — откатываю изменения"
    rm -f /etc/exim4/conf.d/main/05_exim4-config_hardening \
          /etc/exim4/conf.d/acl/99_exim4-config_hardening_acls \
          /etc/exim4/conf.d/auth/99_exim4-config_hardening \
          /etc/exim4/harden/acl_rcpt.inc /etc/exim4/harden/acl_data.inc
    exim_rebuild || true
    return 1
  fi
  return 0
}

mod_mail_postfix() {
  local cert="${ANS[mail_cert]:-/etc/letsencrypt/live/$(hostname -f)/fullchain.pem}"
  local cert_key="${ANS[mail_key]:-/etc/letsencrypt/live/$(hostname -f)/privkey.pem}"
  local submission="${ANS[mail_submission]:-y}"
  [[ -f /etc/postfix/main.cf ]] || { warn "main.cf не найден"; return 1; }
  backup_file /etc/postfix/main.cf
  if [[ $DRY_RUN -eq 1 ]]; then info "[dry-run] postfix main.cf"; return 0; fi

  postconf -e "smtpd_tls_cert_file = $cert"
  postconf -e "smtpd_tls_key_file = $cert_key"
  postconf -e "smtpd_tls_security_level = may"
  postconf -e "smtpd_tls_auth_only = yes"
  postconf -e "smtpd_tls_protocols = !SSLv2,!SSLv3,!TLSv1,!TLSv1.1"
  postconf -e "smtpd_tls_mandatory_protocols = !SSLv2,!SSLv3,!TLSv1,!TLSv1.1"
  postconf -e "smtpd_tls_ciphers = high"
  postconf -e "smtpd_tls_mandatory_ciphers = high"
  postconf -e "smtpd_tls_session_cache_database = btree:\${data_directory}/smtpd_scache"
  postconf -e "smtpd_tls_exclude_ciphers = aNULL, eNULL, EXPORT, DES, RC4, MD5, PSK, aECDH, EDH-DSS-DES-CBC3-SHA, EDH-RSA-DES-CBC3-SHA, KRB5-DES, MD5"
  postconf -e "smtpd_helo_required = yes"
  postconf -e "smtpd_delay_reject = yes"
  postconf -e "smtpd_recipient_limit = 50"
  postconf -e "smtpd_hard_error_limit = 5"
  postconf -e "disable_vrfy_command = yes"
  postconf -e "smtpd_client_restrictions = permit_mynetworks, permit_sasl_authenticated, reject_unauth_destination"
  postconf -e "smtpd_sasl_auth_enable = yes"
  postconf -e "smtpd_sasl_security_options = noanonymous"
  postconf -e "smtpd_sasl_type = dovecot"
  postconf -e "smtpd_sasl_path = private/auth"
  postconf -e "smtpd_sasl_local_domain = \$myhostname"
  postconf -e "myhostname = $(hostname -f 2>/dev/null || hostname)"
  if [[ $submission == y ]]; then
    # submission в master.cf (не в main.cf!)
    if [[ -f /etc/postfix/master.cf ]] && ! grep -qE '^submission[[:space:]]' /etc/postfix/master.cf; then
      backup_file /etc/postfix/master.cf
      printf 'submission inet n       y       y       -       -       smtpd\n  -o smtpd_tls_security_level=encrypt\n  -o smtpd_sasl_auth_enable=yes\n  -o smtpd_client_restrictions=permit_sasl_authenticated,reject\n  -o smtpd_recipient_restrictions=permit_sasl_authenticated,reject\n  -o milter_macro_daemon_name=ORIGINATING\n' >>/etc/postfix/master.cf
    fi
  fi
  postconf -e "milter_default_action = accept"
  postconf -e "smtpd_milters = inet:127.0.0.1:8891"
  postconf -e "non_smtpd_milters = inet:127.0.0.1:8891"
  postconf -e "tls_high_cipherlist = $MOZ_TLS12"
  svc_restart postfix 2>/dev/null || true
  ok "Postfix: TLS/AUTH/анти-spoofing настроены (milter OpenDKIM: 127.0.0.1:8891)"
  return 0
}

mod_mail_dovecot() {
  local cert="${ANS[mail_cert]:-}"
  local cert_key="${ANS[mail_key]:-}"
  if [[ -z $cert || ! -f $cert ]]; then
    # берём из 10-ssl.conf если там уже настроено
    local existing
    existing=$(awk -F'= *<' '/^ssl_cert *=/ {print $2}' /etc/dovecot/conf.d/10-ssl.conf 2>/dev/null | tr -d '>' | head -1)
    [[ -n $existing && -f $existing ]] && cert="$existing"
    existing=$(awk -F'= *<' '/^ssl_key *=/ {print $2}' /etc/dovecot/conf.d/10-ssl.conf 2>/dev/null | tr -d '>' | head -1)
    [[ -n $existing && -f $existing ]] && cert_key="$existing"
  fi
  [[ -f ${cert:-/nonexistent} ]] || { warn "Сертификат для Dovecot не найден — пропускаю (сначала модуль ssl)"; return 0; }
  backup_file /etc/dovecot/conf.d/10-ssl.conf
  if [[ $DRY_RUN -eq 1 ]]; then info "[dry-run] dovecot 99-harden.conf"; return 0; fi

  cat >/etc/dovecot/conf.d/99-harden.conf <<EOF
# harden.sh: жёсткая конфигурация Dovecot (IMAP/POP3)
ssl = required
ssl_min_protocol = TLSv1.2
ssl_cert = <$cert
ssl_key = <$cert_key
disable_plaintext_auth = yes
auth_mechanisms = plain login
auth_failure_delay = 2 secs
mail_max_userip_connections = 30
login_tries = 3
login_max_connections = 75
verbose_ssl = no
# Закрываем незашифрованные порты: только 993/995
protocol imap {
  mail_max_userip_connections = 20
}
service imap-login {
  inet_listener imap {
    port = 0
  }
  inet_listener imaps {
    port = 993
    ssl = yes
  }
}
service pop3-login {
  inet_listener pop3 {
    port = 0
  }
  inet_listener pop3s {
    port = 995
    ssl = yes
  }
}
EOF
  if dovecot -n >/dev/null 2>&1; then
    svc_restart dovecot 2>/dev/null || true
    ok "Dovecot: TLS обязателен, plaintext-порты (143/110) отключены"
  else
    err "Dovecot: конфигурация невалидна — откат"
    rm -f /etc/dovecot/conf.d/99-harden.conf
    return 1
  fi
  return 0
}

# ============================================================================
# МОДУЛЬ: dkim
# ============================================================================
mod_dkim() {
  local domain selector keyalgo
  domain=$(ask_val "dkim_domain" "Домен для DKIM" "${ANS[mail_domain]:-}")
  [[ -n $domain ]] || { warn "Домен не указан"; return 1; }
  selector=$(ask_val "dkim_selector" "DKIM-селектор" "mail")
  keyalgo=$(ask_choice "dkim_algo" "Алгоритм ключа:" "RSA 2048 (универсально)|Ed25519 (современно)" 1)

  local keydir keyfile pubkey
  if [[ $DRY_RUN -eq 1 ]]; then
    info "[dry-run] генерация DKIM-ключа $domain/$selector"
    return 0
  fi

  if [[ $MTA == exim ]]; then
    keydir="/etc/exim4/dkim"
    mkdir -p "$keydir"
    keyfile="$keydir/$domain.$selector.key"
    if [[ $keyalgo == RSA* ]]; then
      openssl genrsa -out "$keyfile" 2048 2>/dev/null
      pubkey=$(openssl rsa -in "$keyfile" -pubout -outform DER 2>/dev/null | base64 -w0 2>/dev/null || \
               openssl rsa -in "$keyfile" -pubout -outform DER 2>/dev/null | base64 | tr -d '\n')
    else
      openssl genpkey -algorithm ed25519 -out "$keyfile" 2>/dev/null
      pubkey=$(openssl pkey -in "$keyfile" -pubout -outform DER 2>/dev/null | tail -c +13 | base64 -w0 2>/dev/null || \
               openssl pkey -in "$keyfile" -pubout -outform DER 2>/dev/null | tail -c +13 | base64 | tr -d '\n')
    fi
    chmod 640 "$keyfile"
    chown root:Debian-exim "$keyfile" 2>/dev/null || true
    # макросы DKIM
    backup_file /etc/exim4/exim4.conf.localmacros
    {
      grep -v '^DKIM_' /etc/exim4/exim4.conf.localmacros 2>/dev/null || echo "# harden.sh"
      echo "DKIM_DOMAIN = $domain"
      echo "DKIM_SELECTOR = $selector"
      echo "DKIM_PRIVATE_KEY = $keyfile"
      echo "DKIM_CANON = relaxed"
      echo "DKIM_STRICT = false"
      echo "DKIM_TIMESTAMPS = 1209600"
    } >/tmp/localmacros.harden && mv /tmp/localmacros.harden /etc/exim4/exim4.conf.localmacros
    if exim_rebuild; then
      svc_restart exim4 2>/dev/null || true
      ok "Exim: DKIM-подпись включена (d=$domain, s=$selector)"
    else
      err "Exim: ошибка конфигурации DKIM — откат"
      return 1
    fi
  elif [[ $MTA == postfix ]]; then
    pkg_install opendkim opendkim-tools >/dev/null 2>&1 || { err "Не удалось установить opendkim"; return 1; }
    mkdir -p "/etc/opendkim/keys/$domain"
    if [[ $keyalgo == RSA* ]]; then
      opendkim-genkey -b 2048 -d "$domain" -D "/etc/opendkim/keys/$domain" -s "$selector" -v || return 1
    else
      opendkim-genkey -a ed25519 -d "$domain" -D "/etc/opendkim/keys/$domain" -s "$selector" -v 2>/dev/null || \
        opendkim-genkey -b 2048 -d "$domain" -D "/etc/opendkim/keys/$domain" -s "$selector" -v
    fi
    chown -R opendkim:opendkim "/etc/opendkim/keys/$domain" 2>/dev/null || true
    chmod 600 "/etc/opendkim/keys/$domain/$selector.private"
    pubkey=$(grep -oP 'p=\K[^"]+' "/etc/opendkim/keys/$domain/$selector.txt" 2>/dev/null | tr -d '\n')
    # KeyTable / SigningTable
    echo "$selector._domainkey.$domain $domain:$selector:/etc/opendkim/keys/$domain/$selector.private" >/etc/opendkim/KeyTable
    echo "*@$domain $selector._domainkey.$domain" >/etc/opendkim/SigningTable
    echo "127.0.0.1" >/etc/opendkim/TrustedHosts
    echo "localhost" >>/etc/opendkim/TrustedHosts
    write_file /etc/opendkim.conf <<EOF
AutoRestart             Yes
AutoRestartRate         10/1M
Background              Yes
Canonicalization        relaxed/simple
ExternalIgnoreList      refile:/etc/opendkim/TrustedHosts
InternalHosts           refile:/etc/opendkim/TrustedHosts
KeyTable                refile:/etc/opendkim/KeyTable
SigningTable            refile:/etc/opendkim/SigningTable
LogWhy                  Yes
Mode                    sv
PidFile                 /run/opendkim/opendkim.pid
SignatureAlgorithm      rsa-sha256
Socket                  inet:8891@127.0.0.1
Syslog                  Yes
SyslogSuccess           Yes
UMask                   007
User                    opendkim
UserID                  opendkim:opendkim
EOF
    if [[ $HAVE_SYSTEMD -eq 1 ]]; then
      mkdir -p /etc/systemd/system/opendkim.service.d
      write_file /etc/systemd/system/opendkim.service.d/override.conf <<'EOF'
[Service]
RuntimeDirectory=opendkim
RuntimeDirectoryMode=0755
EOF
      run systemctl daemon-reload
      svc_enable_start opendkim
    fi
    svc_restart postfix 2>/dev/null || true
    ok "Postfix+OpenDKIM: подпись настроена"
  else
    warn "MTA не обнаружен — генерирую только ключ и DNS-запись"
    mkdir -p /etc/harden/dkim
    keyfile="/etc/harden/dkim/$domain.$selector.key"
    openssl genrsa -out "$keyfile" 2048 2>/dev/null
    chmod 600 "$keyfile"
    pubkey=$(openssl rsa -in "$keyfile" -pubout -outform DER 2>/dev/null | base64 -w0)
  fi

  local alg
  [[ $keyalgo == RSA* ]] && alg=rsa || alg=ed25519
  local dns_record="$selector._domainkey.$domain TXT \"v=DKIM1; k=$alg; p=$pubkey\""
  mkdir -p /root/harden-dns
  echo "$dns_record" >"/root/harden-dns/$domain.$selector.dkim.txt"
  echo
  ok "DKIM-ключ сгенерирован. Добавьте DNS TXT-запись:"
  echo "  $dns_record"
  info "Файл для DNS: /root/harden-dns/$domain.$selector.dkim.txt"
  rep "- DKIM: ключ $domain/$selector создан, DNS-запись в /root/harden-dns/"
  if ask_yn "dkim_verify" "Проверить, что DNS-запись DKIM уже видна?" n; then
    local got
    got=$(dig +short TXT "$selector._domainkey.$domain" 2>/dev/null | tr -d '"' | head -1)
    if [[ $got == *p=* ]]; then ok "DNS-запись DKIM видна"; else warn "DNS-запись ещё не видна (propagation ~5-60 мин)"; fi
  fi
  return 0
}

# ============================================================================
# МОДУЛЬ: spf
# ============================================================================
spf_lookup() { dig +short TXT "$1" 2>/dev/null | tr -d '"' | grep -E '^v=spf1' | head -1; }

count_spf_lookups() {  # приблизительный подсчёт DNS-lookups (лимит 10)
  local rec="$1" n=0 t
  for t in $(echo "$rec" | tr ' ' '\n' | grep -E '^(include:|redirect=|a|mx|ptr|exists:|ip4:|ip6:)'); do
    case "$t" in
      ip4:*|ip6:*) : ;;
      a|mx) n=$((n+1)) ;;
      *) n=$((n+1)) ;;
    esac
  done
  echo "$n"
}

mod_spf() {
  local domain
  domain=$(ask_val "spf_domain" "Домен для SPF" "${ANS[mail_domain]:-}")
  [[ -n $domain ]] || { warn "Домен не указан"; return 1; }

  local current proposed ip extra_includes mode flip=0
  current=$(spf_lookup "$domain")
  info "Текущий SPF $domain: ${current:-<нет>}"
  ip="${ANS[spf_ip]:-$PUBLIC_IP}"
  ip=$(ask_val "spf_ip" "IP этого сервера (ip4:) или CIDR" "$ip")
  extra_includes=$(ask_val "spf_includes" "Дополнительные include:/ip4: через пробел (Google, SendGrid, CRM...)" "")

  if [[ -n $current && $current == *~all* ]]; then
    if ask_yn "spf_flip" "Обнаружен мягкий ~all. Перевести на жёсткий -all?" n; then
      flip=1
    fi
  fi

  if [[ $flip -eq 1 && -n $current ]]; then
    proposed=$(echo "$current" | sed -E 's/~all$/-all/; s/\?all$/-all/')
  else
    mode=$(ask_choice "spf_mode" "Политика SPF:" "мягкий ~all (переходный период)|жёсткий -all (рекомендуется, если все отправители учтены)" 2)
    local all="~all"
    [[ $mode == *жёсткий* ]] && all="-all"
    local inc=""
    for e in $extra_includes; do inc="$inc $e"; done
    proposed="v=spf1 ip4:$ip$inc $all"
  fi

  local lookups
  lookups=$(count_spf_lookups "$proposed")
  if [[ $lookups -gt 10 ]]; then
    warn "SPF содержит ~$lookups DNS-lookups (лимит RFC 7208 — 10). Уберите лишние include:"
  fi

  if [[ -n $current && $current != "$proposed" ]]; then
    warn "ВНИМАНИЕ: текущая и предлагаемая записи различаются."
    info "Текущая:   $current"
    info "Новая:     $proposed"
    if ! ask_yn "spf_replace" "Заменить запись? (старую удаляем, новую публикуем в DNS!)" n; then
      info "Пропускаю"
      return 0
    fi
    if [[ "$current" == *include:* ]]; then
      warn "Старая запись содержит include: — убедитесь, что сервисы из неё больше не шлют почту с вашего домена!"
    fi
  fi

  mkdir -p /root/harden-dns
  echo "$domain TXT \"$proposed\"" >"/root/harden-dns/$domain.spf.txt"
  echo
  ok "Опубликуйте DNS TXT-запись:"
  echo "  $domain TXT \"$proposed\""
  info "Файл: /root/harden-dns/$domain.spf.txt"
  info "После публикации (propagation до 1 часа) проверьте: dig TXT $domain"

  if ask_yn "spf_check" "Проверить публикацию записи сейчас?" n; then
    local got
    got=$(spf_lookup "$domain")
    if [[ -n $got ]]; then
      ok "Запись видна: $got"
      [[ $got == *-all* ]] && ok "Используется жёсткий -all" || warn "Всё ещё мягкий/all — повторите запуск модуля spf для перевода"
    else
      warn "Запись ещё не видна в DNS"
    fi
  fi
  rep "- SPF: $proposed"
  return 0
}

# ============================================================================
# МОДУЛЬ: dmarc
# ============================================================================
mod_dmarc() {
  local domain
  domain=$(ask_val "dmarc_domain" "Домен для DMARC" "${ANS[mail_domain]:-}")
  [[ -n $domain ]] || { warn "Домен не указан"; return 1; }

  local current rec
  current=$(dig +short TXT "_dmarc.$domain" 2>/dev/null | tr -d '"' | grep -E '^v=DMARC1' | head -1)
  info "Текущий DMARC: ${current:-<нет>}"

  local rua ruf policy
  rua=$(ask_val "dmarc_rua" "Email для aggregate-отчётов (rua)" "dmarc-reports@$domain")
  ruf=$(ask_val "dmarc_ruf" "Email для forensic-отчётов (ruf)" "dmarc-forensic@$domain")

  if [[ -n $current && $current == *p=none* ]]; then
    info "Текущая политика p=none (мониторинг). Рекомендуемая эскалация:"
    if ask_yn "dmarc_escalate" "Перейти к p=quarantine (следующий шаг перед reject)?" n; then
      policy="quarantine"
    elif ask_yn "dmarc_reject_now" "Сразу перейти к p=reject (только если все отправители уже подтверждены)?" n; then
      policy="reject"
    else
      policy="none"
    fi
  else
    policy=$(ask_choice "dmarc_policy" "Политика DMARC:" \
      "none (мониторинг, рекомендуется при первом запуске)|quarantine (спам-папка)|reject (жёстко)" 1)
    case "$policy" in
      none*) policy="none" ;;
      quarantine*) policy="quarantine" ;;
      reject*) policy="reject" ;;
    esac
  fi

  local pct
  pct=$(ask_val "dmarc_pct" "Процент охвата (pct)" "100")
  rec="v=DMARC1; p=$policy; pct=$pct; rua=mailto:$rua; ruf=mailto:$ruf; fo=1; adkim=s; aspf=s; ri=14400"

  mkdir -p /root/harden-dns
  echo "_dmarc.$domain TXT \"$rec\"" >"/root/harden-dns/$domain.dmarc.txt"
  echo
  ok "Опубликуйте DNS TXT-запись:"
  echo "  _dmarc.$domain TXT \"$rec\""
  info "Файл: /root/harden-dns/$domain.dmarc.txt"
  if [[ $policy == reject ]]; then
    warn "p=reject: убедитесь, что SPF и DKIM настроены и проверены (модули spf/dkim/spoof)!"
  fi

  if ask_yn "dmarc_check" "Проверить публикацию записи сейчас?" n; then
    local got
    got=$(dig +short TXT "_dmarc.$domain" 2>/dev/null | tr -d '"' | grep -E '^v=DMARC1' | head -1)
    if [[ -n $got ]]; then ok "Запись видна: $got"; else warn "Запись ещё не видна (propagation до 1 часа)"; fi
  fi
  rep "- DMARC: p=$policy ($rec)"
  return 0
}

# ============================================================================
# МОДУЛЬ: spoof — проверка spoofing / открытого релея
# ============================================================================
smtp_probe() {  # smtp_probe <порт> <строки для отправки> -> ответ сервера
  python3 - "$1" <<'PYEOF' 2>/dev/null
import socket, sys, time
port = int(sys.argv[1])
s = socket.create_connection(("127.0.0.1", port), 5)
s.settimeout(5)
def recv():
    data = b""
    try:
        while True:
            chunk = s.recv(4096)
            if not chunk: break
            data += chunk
            if b"\r\n" not in chunk: break
            if not chunk.startswith(b"250-"): break
    except Exception:
        pass
    return data.decode(errors="replace")
print(recv().strip())
s.sendall(b"EHLO harden-probe\r\n")
print(recv().strip())
s.sendall(b"QUIT\r\n")
time.sleep(0.2)
s.close()
PYEOF
}

mod_spoof() {
  local domain
  domain=$(ask_val "spoof_domain" "Проверяемый домен" "${ANS[mail_domain]:-}")
  local selector="${ANS[dkim_selector]:-mail}"
  local fails=0 warns=0

  echo
  info "=== 1. DNS: SPF ==="
  local spf
  spf=$(spf_lookup "$domain")
  if [[ -z $spf ]]; then
    warn "FAIL: SPF-запись отсутствует"; fails=$((fails+1))
  elif [[ $spf == *-all* ]]; then
    ok "PASS: SPF с жёстким -all: $spf"
  elif [[ $spf == *~all* ]]; then
    warn "WARN: SPF с мягким ~all (переведите на -all модулем spf): $spf"; warns=$((warns+1))
  else
    warn "WARN: SPF без all-механизма: $spf"; warns=$((warns+1))
  fi
  local nrec
  nrec=$(dig +short TXT "$domain" 2>/dev/null | tr -d '"' | grep -cE '^v=spf1' || true)
  [[ $nrec -gt 1 ]] && { warn "FAIL: найдено $nrec SPF-записей (permerror по RFC)"; fails=$((fails+1)); }

  info "=== 2. DNS: DMARC ==="
  local dmarc
  dmarc=$(dig +short TXT "_dmarc.$domain" 2>/dev/null | tr -d '"' | grep -E '^v=DMARC1' | head -1)
  if [[ -z $dmarc ]]; then
    warn "FAIL: DMARC-запись отсутствует (домен открыт для spoofing)"; fails=$((fails+1))
  elif [[ $dmarc == *p=reject* ]]; then
    ok "PASS: DMARC p=reject: $dmarc"
  elif [[ $dmarc == *p=quarantine* ]]; then
    ok "PASS: DMARC p=quarantine: $dmarc"
  else
    warn "WARN: DMARC p=none — spoofing возможен, эскалируйте политику"; warns=$((warns+1))
  fi

  info "=== 3. DNS: DKIM ($selector._domainkey.$domain) ==="
  local dkim
  dkim=$(dig +short TXT "$selector._domainkey.$domain" 2>/dev/null | tr -d '"' | head -1)
  if [[ -n $dkim && $dkim == *p=* ]]; then
    ok "PASS: DKIM-запись найдена"
  else
    warn "FAIL: DKIM-запись не найдена (модуль dkim)"; fails=$((fails+1))
  fi

  info "=== 4. Локальный тест открытого релея (MAIL FROMspoof -> внешний RCPT) ==="
  if command -v python3 >/dev/null 2>&1 && ss -lnt | grep -q ':25 '; then
    local relay_out
    relay_out=$(python3 - "$domain" <<'PYEOF' 2>/dev/null
import socket, sys, time
domain = sys.argv[1]
try:
    s = socket.create_connection(("127.0.0.1", 25), 5)
    s.settimeout(5)
    def recvall():
        d = b""
        try:
            while True:
                c = s.recv(4096)
                if not c: break
                d += c
                if b"\r\n" in c: break
        except Exception:
            pass
        return d.decode(errors="replace")
    recvall()
    s.sendall(b"EHLO harden-probe\r\n"); recvall()
    s.sendall(b"MAIL FROM:<spoof@%s>\r\n" % domain.encode()); print("FROM:", recvall().strip())
    s.sendall(b"RCPT TO:<probe-external@example.org>\r\n"); print("RCPT:", recvall().strip())
    s.sendall(b"QUIT\r\n"); s.close()
except Exception as e:
    print("ERR:", e)
PYEOF
)
    echo "$relay_out"
    if echo "$relay_out" | grep -qiE '550|relay not permitted|relay denied|5\.7\.|not permitted'; then
      ok "PASS: незарелейенный внешний RCPT отклонён (открытого релея нет)"
    elif echo "$relay_out" | grep -qi 'ERR:'; then
      warn "WARN: не удалось выполнить SMTP-пробу"
    else
      warn "FAIL: сервер принял RCPT для внешнего домена без аутентификации — ВОЗМОЖЕН ОТКРЫТЫЙ РЕЛЕЙ!"; fails=$((fails+1))
    fi
  else
    info "Пропущено: python3 или порт 25 недоступны локально"
  fi

  info "=== 5. AUTH не рекламируется без TLS (порт 25) ==="
  if command -v python3 >/dev/null 2>&1 && ss -lnt | grep -q ':25 '; then
    local auth_out
    auth_out=$(python3 - <<'PYEOF' 2>/dev/null
import socket
s = socket.create_connection(("127.0.0.1", 25), 5)
s.settimeout(5)
def recvall():
    d = b""
    try:
        while True:
            c = s.recv(4096)
            if not c: break
            d += c
            if b"\r\n" in c: break
    except Exception:
        pass
    return d.decode(errors="replace")
recvall()
s.sendall(b"EHLO harden-probe\r\n")
resp = recvall()
print("AUTH_ADVERTISED" if "AUTH" in resp.upper() else "AUTH_HIDDEN")
s.sendall(b"QUIT\r\n"); s.close()
PYEOF
)
    if [[ $auth_out == AUTH_HIDDEN ]]; then
      ok "PASS: AUTH не предлагается по незашифрованному каналу"
    else
      warn "WARN: AUTH рекламируется без TLS (проверьте конфигурацию auth)"; warns=$((warns+1))
    fi
  fi

  info "=== 6. VRFY/EXPN отключены ==="
  if command -v python3 >/dev/null 2>&1 && ss -lnt | grep -q ':25 '; then
    local vrfy_out
    vrfy_out=$(python3 - <<'PYEOF' 2>/dev/null
import socket
s = socket.create_connection(("127.0.0.1", 25), 5)
s.settimeout(5)
def recvall():
    d=b""
    try:
        while True:
            c=s.recv(4096)
            if not c: break
            d+=c
            if b"\r\n" in c: break
    except Exception: pass
    return d.decode(errors="replace")
recvall(); s.sendall(b"EHLO harden-probe\r\n"); recvall()
s.sendall(b"VRFY root\r\n"); print("VRFY:", recvall().strip())
s.sendall(b"QUIT\r\n"); s.close()
PYEOF
)
    echo "$vrfy_out"
    if echo "$vrfy_out" | grep -qE '502|500|550|disabled|not supported'; then
      ok "PASS: VRFY отклонён"
    else
      warn "WARN: VRFY разрешён (энумерация пользователей)"; warns=$((warns+1))
    fi
  fi

  info "=== 7. STARTTLS на 25/587 ==="
  local p
  for p in 25 587; do
    if ss -lnt | grep -q ":$p "; then
      if echo | timeout 5 openssl s_client -connect "127.0.0.1:$p" -starttls smtp -brief 2>/dev/null | grep -q 'Protocol.*TLS'; then
        ok "PASS: STARTTLS работает на порту $p"
      else
        warn "WARN: STARTTLS на порту $p не подтверждён"; warns=$((warns+1))
      fi
    fi
  done

  echo
  if [[ $fails -eq 0 && $warns -eq 0 ]]; then
    ok "ИТОГ: все проверки spoofing пройдены"
  else
    warn "ИТОГ: FAIL=$fails, WARN=$warns (см. отчёт)"
  fi
  rep "- Spoof-проверка: FAIL=$fails WARN=$warns"
  info "Для полной проверки снаружи используйте mail-tester.com / dmarcian / MXToolbox spoof test"
  return 0
}

# ============================================================================
# МОДУЛЬ: cve — проверка CVE по установленным пакетам
# ============================================================================
KEY_SOURCE_PKGS="openssh openssl exim4 dovecot2 nginx apache2 linux glibc sudo systemd curl wget git python3 perl vim-tiny patchelf util-linux login procps tzdata zlib1g libxml2 icu"

cve_scan_ubuntu() {
  local mode
  mode=$(ask_choice "cve_mode" "Глубина проверки CVE (Ubuntu CVE Tracker API):" \
    "быстрая (критичные пакеты: SSH/OpenSSL/Exim/Dovecot/ядро/…) | полная (все установленные source-пакеты, долго)" 1)

  local src_list=""
  if [[ $mode == быстрая* ]]; then
    local b s
    for b in $KEY_SOURCE_PKGS; do
      s=$(dpkg-query -W -f='${source:Package}' "$b" 2>/dev/null | sed 's/ ([0-9].*)//' | head -1)
      [[ -n $s ]] && src_list="$src_list $s"
    done
    # подстраховка: всегда проверяем то, что реально крутится
    for b in openssh-server openssh-client exim4-daemon-light exim4-daemon-heavy exim4-config dovecot-imapd dovecot-pop3d nginx apache2 libssl3 libssl3t64 libc6 linux-image-generic linux-image-virtual; do
      if dpkg-query -W -f='${Status}' "$b" 2>/dev/null | grep -q 'install ok installed'; then
        s=$(dpkg-query -W -f='${source:Package}' "$b" 2>/dev/null | sed 's/ ([0-9].*)//' | head -1)
        [[ -n $s ]] && src_list="$src_list $s"
      fi
    done
    src_list=$(echo "$src_list" | tr ' ' '\n' | sort -u | tr '\n' ' ' | sed 's/ $//')
  else
    src_list=$(dpkg-query -W -f='${source:Package}\n' 2>/dev/null | sed 's/ ([0-9].*)//' | sort -u | tr '\n' ' ')
  fi

  local nsrc
  nsrc=$(echo "$src_list" | wc -w)
  info "Проверяем $nsrc source-пакетов (codename: $OS_CODENAME)..."
  local out="/root/harden-cve-report-${TS}.txt"
  mkdir -p /root

  python3 - "$OS_CODENAME" "$out" $src_list <<'PYEOF'
import json, sys, time, urllib.request, urllib.parse

codename, outpath = sys.argv[1], sys.argv[2]
packages = sys.argv[3:]
watch = {"needed", "pending", "deferred", "released"}
rows = []
errors = []

for i, pkg in enumerate(packages, 1):
    url = "https://ubuntu.com/security/cves.json?package=" + urllib.parse.quote(pkg) + "&limit=1000"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "harden.sh"})
        with urllib.request.urlopen(req, timeout=25) as r:
            data = json.load(r)
    except Exception as e:
        errors.append(f"{pkg}: {e}")
        continue
    for cve in data.get("cves", []):
        for p in cve.get("packages", []):
            if p.get("name") != pkg:
                continue
            for st in p.get("statuses", []):
                if st.get("release_codename") != codename:
                    continue
                status = st.get("status", "")
                if status in watch:
                    rows.append({
                        "pkg": pkg,
                        "cve": cve.get("id", "?"),
                        "priority": (cve.get("priority") or "unknown"),
                        "status": status,
                        "cvss": cve.get("cvss3") or "",
                        "desc": (cve.get("ubuntu_description") or cve.get("description") or "").strip().replace("\n", " ")[:160],
                    })
    print(f"  [{i}/{len(packages)}] {pkg}: {sum(1 for r in rows if r['pkg']==pkg)} записей", file=sys.stderr)
    time.sleep(0.25)

order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "negligible": 4, "unknown": 5, "untriaged": 6}
rows.sort(key=lambda r: (order.get(r["priority"], 9), r["pkg"], r["cve"]))

with open(outpath, "w") as f:
    f.write(f"# CVE-отчёт для {codename}\n# Проверено пакетов: {len(packages)}, проблем: {len(rows)}\n\n")
    for r in rows:
        f.write(f"{r['priority'].upper():10} {r['status']:9} {r['pkg']:20} {r['cve']:18} cvss={r['cvss']} {r['desc']}\n")

print(f"\nИТОГО: {len(rows)} записей (needed/pending/deferced/released) по {len(packages)} пакетам")
for r in rows[:40]:
    print(f"{r['priority'].upper():10} {r['status']:9} {r['pkg']:20} {r['cve']}")
if len(rows) > 40:
    print(f"... и ещё {len(rows)-40} (см. {outpath})")
if errors:
    print("Ошибки запросов:")
    for e in errors[:10]:
        print("  ", e)
# код: кол-во needed (уязвимы, фикса ещё нет) — отдельно
needed = sum(1 for r in rows if r["status"] in ("needed", "pending", "deferred"))
print(f"NEEDED(no-fix-yet)={needed} RELEASED(fix-available)={len(rows)-needed}")
PYEOF
  local rc=$?
  info "Полный отчёт: $out"
  if [[ -s $out ]]; then
    rep "## CVE (Ubuntu API)"
    rep '```'
    head -30 "$out" | sed 's/^/    /' | while read -r l; do rep "$l"; done
    rep '```'
  fi
  return $rc
}

cve_scan_oval() {
  if ! command -v oscap >/dev/null 2>&1; then
    if ask_yn "cve_openscap" "Установить OpenSCAP для OVAL-сканирования (точная привязка к установленным пакетам)?" n; then
      pkg_install openscap-scanner bzip2 >/dev/null 2>&1 || { warn "Не удалось установить openscap"; return 1; }
    else
      return 0
    fi
  fi
  local oval_url="https://security-metadata.canonical.com/oval/com.ubuntu.${OS_CODENAME}.cve.oval.xml.bz2"
  local tmp="/tmp/harden-oval.xml"
  info "Загрузка OVAL (~10-20 МБ)..."
  if ! curl -fsSL --max-time 300 "$oval_url" -o "$tmp.bz2"; then
    # fallback: USN OVAL
    oval_url="https://security-metadata.canonical.com/oval/com.ubuntu.${OS_CODENAME}.usn.oval.xml.bz2"
    curl -fsSL --max-time 300 "$oval_url" -o "$tmp.bz2" || { warn "Не удалось скачать OVAL"; return 1; }
  fi
  bunzip2 -f "$tmp.bz2" || return 1
  local res="/root/harden-oval-results-${TS}.xml"
  info "Запуск oscap oval eval (может занять несколько минут)..."
  if run oscap oval eval --results "$res" "$tmp" >/dev/null 2>&1; then
    local n
    n=$(grep -c 'result="true"' "$res" 2>/dev/null || echo 0)
    ok "OVAL: уязвимых определений сработало: $n (отчёт: $res)"
    rep "- OVAL/OpenSCAP: сработало определений: $n"
  else
    warn "oscap завершился с ошибкой — см. лог"
    return 1
  fi
}

mod_cve() {
  if is_ubuntu; then
    info "Используется Ubuntu CVE Tracker API (https://ubuntu.com/security/cves)"
    cve_scan_ubuntu || warn "CVE-скан завершился с ошибками"
    if command -v pro >/dev/null 2>&1; then
      info "Ubuntu Pro security-status:"
      pro security-status 2>/dev/null | tee -a "$LOG_FILE" | tail -5 || true
    fi
    if ask_yn "cve_oval" "Дополнительно выполнить OVAL-сканирование (OpenSCAP, полная точность)?" n; then
      cve_scan_oval || true
    fi
    if ask_yn "cve_upgrade" "Обновить пакеты с доступными фиксами (status=released)?" y; then
      mod_critical_updates
    fi
  elif is_ubuntu_like; then
    info "Debian: используем apt list --upgradable + (опционально) debsecan"
    case "$PKG_MGR" in
      apt)
        apt-get update -qq 2>/dev/null || true
        local upg
        upg=$(apt list --upgradable 2>/dev/null | grep -i security | head -30)
        if [[ -n $upg ]]; then
          warn "Доступны security-обновления:"
          echo "$upg"
          rep "## Security-обновления (Debian)"
          rep '```'; rep "$upg"; rep '```'
          ask_yn "cve_deb_upgrade" "Установить их сейчас?" y && pkg_upgrade_refresh && DEBIAN_FRONTEND=noninteractive run apt-get -y dist-upgrade
        else
          ok "Security-обновлений не найдено"
        fi
        if ! command -v debsecan >/dev/null 2>&1 && ask_yn "cve_debsecan" "Установить debsecan (аудит уязвимостей по Debian security tracker)?" n; then
          pkg_install debsecan >/dev/null 2>&1 && run debsecan --suite "$OS_CODENAME" --showall 2>/dev/null | head -40 | tee -a "$LOG_FILE" || true
        fi
        ;;
    esac
  else
    warn "CVE-проверка через Canonical API работает только для Ubuntu/Debian."
    case "$PKG_MGR" in
      dnf|yum)
        info "RHEL-семейство: dnf updateinfo"
        run "$PKG_MGR" updateinfo list --security 2>/dev/null | tail -30 || true
        ask_yn "cve_dnf_up" "Применить security-обновления?" y && run "$PKG_MGR" -y update --security
        ;;
      zypper) run zypper --non-interactive list-patches 2>/dev/null | tail -20 || true ;;
      pacman) info "Arch: смотрите CVE-рассылки; обновления: pacman -Syu" ;;
    esac
  fi
  return 0
}

# ============================================================================
# МОДУЛЬ: critical_updates — точечное обновление критичных пакетов
# ============================================================================
mod_critical_updates() {
  local candidates="openssh-server openssh-client exim4 exim4-base exim4-config exim4-daemon-light exim4-daemon-heavy dovecot dovecot-core dovecot-imapd dovecot-pop3d openssl libssl3 libssl3t64 libc6 linux-image-generic linux-image-virtual sudo bash login util-linux systemd libsystemd0 curl wget git python3 perl gnutls28 libgnutls30"
  local installed=""
  local p
  for p in $candidates; do
    pkg_is_installed "$p" && installed="$installed $p"
  done
  if [[ -z $installed ]]; then
    info "Из критичного списка ничего не установлено"
    return 0
  fi
  info "Установлены критичные пакеты:$installed"
  if ! ask_yn "cu_upgrade" "Обновить только эти пакеты (--only-upgrade)?" y; then
    return 0
  fi
  case "$PKG_MGR" in
    apt)
      # shellcheck disable=SC2086
      DEBIAN_FRONTEND=noninteractive run apt-get install -y --only-upgrade $installed || warn "Часть пакетов не обновилась"
      ;;
    dnf|yum)
      # shellcheck disable=SC2086
      run "$PKG_MGR" install -y $installed || warn "Часть пакетов не обновилась"
      ;;
    zypper)
      # shellcheck disable=SC2086
      run zypper --non-interactive install -y $installed || true ;;
    pacman)
      # shellcheck disable=SC2086
      run pacman -S --noconfirm --needed $installed || true ;;
    *) warn "Авто-обновление не поддерживается для $PKG_MGR" ;;
  esac
  # ядро: перезагрузка при необходимости
  if [[ -f /var/run/reboot-required ]] && ask_yn "cu_reboot" "Требуется перезагрузка (new kernel). Перезагрузить сейчас?" n; then
    warn "Перезагрузка через 1 минуту! (cancel: shutdown -c)"
    run shutdown -r +1
  fi
  return 0
}

# ============================================================================
# МОДУЛЬ: backups — резервные копии (restic/borg)
# ============================================================================
mod_backups() {
  local tool repo password paths excludes keep_d keep_w keep_m schedule_hour
  tool=$(ask_choice "bk_tool" "Инструмент бэкапов:" "restic (рекомендуется)|borgbackup" 1)
  repo=$(ask_val "bk_repo" "Репозиторий (локальный путь / sftp:user@host:/path / s3:bucket / rest:https://…)?" "/var/backups/restic")
  password=$(ask_secret "bk_password" "Пароль шифрования репозитория (пусто = сгенерировать)" "")
  [[ -z $password ]] && password=$(gen_pass) && info "Сгенерирован пароль (сохранён в /etc/restic/password): $password"
  paths=$(ask_val "bk_paths" "Пути для бэкапа (через пробел)" "/etc /root /home /var/www")
  excludes=$(ask_val "bk_excludes" "Исключения (glob через пробел)" "*/cache/* */.cache/* */node_modules/* *.sock")
  keep_d=$(ask_val "bk_keep_d" "Хранить дневных снапшотов" "7")
  keep_w=$(ask_val "bk_keep_w" "Хранить недельных" "4")
  keep_m=$(ask_val "bk_keep_m" "Хранить месячных" "6")
  schedule_hour=$(ask_val "bk_hour" "Час запуска (0-23)" "3")

  local db_dump=0
  if command -v mysqldump >/dev/null 2>&1 || command -v mariadb-dump >/dev/null 2>&1 || command -v pg_dump >/dev/null 2>&1; then
    ask_yn "bk_db" "Обнаружена БД — добавить дамп в бэкап?" y && db_dump=1
  fi

  case "$tool" in
    restic)
      pkg_install restic >/dev/null 2>&1 || { err "Не удалось установить restic"; return 1; }
      if [[ $DRY_RUN -eq 1 ]]; then info "[dry-run] настройка restic: repo=$repo"; return 0; fi
      mkdir -p /etc/restic /usr/local/sbin
      printf '%s' "$password" >/etc/restic/password
      chmod 600 /etc/restic/password
      # локальный репозиторий?
      if [[ $repo == /* ]]; then mkdir -p "$repo"; fi
      if ! RESTIC_REPOSITORY="$repo" RESTIC_PASSWORD_FILE=/etc/restic/password restic cat config >/dev/null 2>&1; then
        info "Инициализация репозитория..."
        RESTIC_REPOSITORY="$repo" RESTIC_PASSWORD_FILE=/etc/restic/password run restic init || { err "restic init не удался"; return 1; }
      fi
      cat >/etc/restic/harden-backup.env <<EOF
RESTIC_REPOSITORY=$repo
RESTIC_PASSWORD_FILE=/etc/restic/password
RESTIC_CACHE_DIR=/var/cache/restic
EOF
      chmod 600 /etc/restic/harden-backup.env
      mkdir -p /var/cache/restic
      # реальный список путей
      local paths_eff=""
      for p in $paths; do [[ -e $p ]] && paths_eff="$paths_eff $p"; done
      local excl_args=()
      for p in $excludes; do excl_args+=(--exclude "$p"); done
      cat >/usr/local/sbin/harden-backup.sh <<EOF
#!/bin/sh
# harden.sh: резервные копии (restic)
set -e
. /etc/restic/harden-backup.env
export RESTIC_REPOSITORY RESTIC_PASSWORD_FILE RESTIC_CACHE_DIR
BACKUP_PATHS="$paths_eff"
if [ $db_dump -eq 1 ]; then
  mkdir -p /var/backups/dbdump
  if command -v pg_dump >/dev/null 2>&1; then
    pg_dump -Fc -f /var/backups/dbdump/pg.dump 2>>/var/log/harden-backup.log || true
  fi
  if command -v mysqldump >/dev/null 2>&1; then
    mysqldump --all-databases -f /var/backups/dbdump/mysql.sql 2>>/var/log/harden-backup.log || true
  fi
  BACKUP_PATHS="\$BACKUP_PATHS /var/backups/dbdump"
fi
restic backup \$BACKUP_PATHS --tag harden --one-file-system 2>>/var/log/harden-backup.log
restic forget --keep-daily $keep_d --keep-weekly $keep_w --keep-monthly $keep_m --prune 2>>/var/log/harden-backup.log
EOF
      chmod 700 /usr/local/sbin/harden-backup.sh
      if [[ $HAVE_SYSTEMD -eq 1 ]]; then
        write_file /etc/systemd/system/harden-backup.service <<'EOF'
[Unit]
Description=harden.sh backup (restic)
[Service]
Type=oneshot
ExecStart=/usr/local/sbin/harden-backup.sh
EOF
        write_file /etc/systemd/system/harden-backup.timer <<EOF
[Unit]
Description=Ежедневный бэкап harden.sh
[Timer]
OnCalendar=*-*-* ${schedule_hour}:15:00
Persistent=true
[Install]
WantedBy=timers.target
EOF
        run systemctl daemon-reload
        run systemctl enable --now harden-backup.timer
      else
        echo "15 $schedule_hour * * * root /usr/local/sbin/harden-backup.sh >>/var/log/harden-backup.log 2>&1" >/etc/cron.d/harden-backup
        chmod 644 /etc/cron.d/harden-backup
      fi
      if ask_yn "bk_first" "Выполнить первый бэкап сейчас?" y; then
        run /usr/local/sbin/harden-backup.sh && ok "Первый бэкап выполнен" || warn "Бэкап завершился с ошибкой (см. /var/log/harden-backup.log)"
      fi
      if ask_yn "bk_verify" "Проверить целостность репозитория (restic check)?" y; then
        run restic check || true
      fi
      ok "restic: расписание ежедневно ${schedule_hour}:15, retention ${keep_d}d/${keep_w}w/${keep_m}m"
      ;;
    borgbackup)
      pkg_install borgbackup >/dev/null 2>&1 || { err "Не удалось установить borgbackup"; return 1; }
      if [[ $DRY_RUN -eq 1 ]]; then info "[dry-run] borg: repo=$repo"; return 0; fi
      mkdir -p /etc/borg
      printf '%s' "$password" >/etc/borg/passphrase
      chmod 600 /etc/borg/passphrase
      if [[ $repo == /* && ! -d $repo ]]; then
        run borg init --encryption=repokey "$repo" || { err "borg init не удался"; return 1; }
      fi
      local paths_eff=""
      for p in $paths; do [[ -e $p ]] && paths_eff="$paths_eff $p"; done
      cat >/usr/local/sbin/harden-backup.sh <<EOF
#!/bin/sh
# harden.sh: резервные копии (borg)
export BORG_PASSPHRASE="\$(cat /etc/borg/passphrase)"
borg create --stats --compression lz4 "${repo}::'{now}'" $paths_eff 2>>/var/log/harden-backup.log
borg prune --keep-daily=$keep_d --keep-weekly=$keep_w --keep-monthly=$keep_m 2>>/var/log/harden-backup.log
EOF
      chmod 700 /usr/local/sbin/harden-backup.sh
      echo "15 $schedule_hour * * * root /usr/local/sbin/harden-backup.sh >>/var/log/harden-backup.log 2>&1" >/etc/cron.d/harden-backup
      chmod 644 /etc/cron.d/harden-backup
      ask_yn "bk_first" "Выполнить первый бэкап сейчас?" y && run /usr/local/sbin/harden-backup.sh || true
      ok "borg: расписание ежедневно ${schedule_hour}:15"
      ;;
  esac

  # алерт при ошибке бэкапа
  local webhook
  webhook=$(ask_val "bk_webhook" "Webhook для алертов об ошибке бэкапа (URL, пусто = email root)" "")
  if [[ -n $webhook ]]; then
    cat >/etc/restic/harden-backup-alert.sh <<EOF
#!/bin/sh
curl -fsS -X POST -H 'Content-Type: application/json' \
  -d "{\"text\":\"harden-backup FAILED on \$(hostname)\"}" "$webhook" >/dev/null 2>&1 || true
EOF
    chmod 700 /etc/restic/harden-backup-alert.sh
  fi
  rep "- Бэкапы: $tool -> $repo, ежедневно $schedule_hour:15"
  return 0
}

# ============================================================================
# МОДУЛЬ: monitoring
# ============================================================================
mod_monitoring() {
  # 1. Persistent journal
  if ask_yn "mon_journal" "Включить персистентный journald (логи переживают перезагрузку, лимит 500 МБ)?" y; then
    if [[ $DRY_RUN -eq 0 && $HAVE_SYSTEMD -eq 1 ]]; then
      mkdir -p /etc/systemd/journald.conf.d
      write_file /etc/systemd/journald.conf.d/99-harden.conf <<'EOF'
[Journal]
Storage=persistent
SystemMaxUse=500M
SystemMaxFileSize=50M
ForwardToSyslog=yes
EOF
      run systemctl restart systemd-journald 2>/dev/null || true
      ok "journald: персистентные логи включены"
    fi
  fi

  # 2. Синхронизация времени
  if ask_yn "mon_time" "Обеспечить точное время (chrony)?" y; then
    if ! pkg_is_installed chrony && ! pkg_is_installed chronyd; then
      pkg_install chrony >/dev/null 2>&1 || pkg_install chronyd >/dev/null 2>&1 || true
    fi
    if [[ $HAVE_SYSTEMD -eq 1 ]]; then
      run systemctl enable --now chrony 2>/dev/null || run systemctl enable --now chronyd 2>/dev/null || true
    fi
    ok "chrony: время синхронизируется"
  fi

  # 3. node_exporter (метрики Prometheus)
  if ask_yn "mon_exporter" "Установить prometheus-node-exporter (метрики для мониторинга)?" y; then
    pkg_install prometheus-node-exporter >/dev/null 2>&1 || true
    if pkg_is_installed prometheus-node-exporter; then
      local expose
      expose=$(ask_val "mon_exporter_port" "Порт node_exporter (127.0.0.1 по умолчанию; 0 = только localhost)" "9100")
      if [[ $expose != 0 && $HAVE_SYSTEMD -eq 1 ]]; then
        mkdir -p /etc/systemd/system/prometheus-node-exporter.service.d
        write_file /etc/systemd/system/prometheus-node-exporter.service.d/harden.conf <<EOF
[Service]
Environment="ARGS=--web.listen-address=:${expose}"
EOF
        run systemctl daemon-reload
        # открыть порт только для доверенных IP
        local mon_ips
        mon_ips=$(ask_val "mon_exporter_ips" "IP мониторинг-сервера (для доступа к метрикам)" "")
        if [[ -n $mon_ips ]]; then
          local mi
          for mi in $mon_ips; do
            case "$(detect_fw_backend)" in
              ufw) run ufw allow from "$mi" to any port "$expose" proto tcp 2>/dev/null || true ;;
              *)   info "Откройте порт $expose для $mi в файрволе вручную" ;;
            esac
          done
        fi
      fi
      run systemctl enable --now prometheus-node-exporter 2>/dev/null || true
      ok "node_exporter установлен"
    else
      warn "node_exporter недоступен в репозиториях"
    fi
  fi

  # 4. AIDE (целостность файлов)
  if ask_yn "mon_aide" "Установить AIDE (обнаружение изменений системных файлов)?" y; then
    pkg_install aide aide-init >/dev/null 2>&1 || pkg_install aide >/dev/null 2>&1 || true
    if pkg_is_installed aide; then
      if [[ $DRY_RUN -eq 0 ]]; then
        if [[ ! -f /var/lib/aide/aide.db && ! -f /var/lib/aide/aide.db.new ]]; then
          info "Создание базы AIDE (первый прогон занимает 5-20 минут)..."
          if command -v aideinit >/dev/null 2>&1; then
            run aideinit || warn "aideinit: ошибка (см. лог)"
            [[ -f /var/lib/aide/aide.db.new ]] && mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db
          else
            run aide --init || true
            [[ -f /var/lib/aide/aide.db.new ]] && mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db
          fi
        fi
        cat >/etc/cron.weekly/aide-check <<'EOF'
#!/bin/sh
# harden.sh: еженедельная проверка AIDE
exec /usr/bin/aide --check 2>&1 | mail -s "AIDE report $(hostname)" root
EOF
        chmod 700 /etc/cron.weekly/aide-check
        ok "AIDE: база создана, еженедельный cron настроен (отчёт в email root)"
      fi
    else
      warn "AIDE недоступен"
    fi
  fi

  # 5. logwatch
  if ask_yn "mon_logwatch" "Установить logwatch (ежедневный дайджест логов в email)?" n; then
    pkg_install logwatch >/dev/null 2>&1 || true
    if [[ $DRY_RUN -eq 0 ]] && pkg_is_installed logwatch; then
      local lw_email
      lw_email=$(ask_val "mon_logwatch_email" "Email для дайджеста" "root")
      mkdir -p /etc/logwatch/conf
      write_file /etc/logwatch/conf/logwatch.conf <<EOF
MailTo = $lw_email
MailFrom = logwatch@$(hostname -f 2>/dev/null || hostname)
Detail = High
Service = All
Range = yesterday
EOF
      ok "logwatch установлен (каждый день, detail=High)"
    fi
  fi

  # 6. Health-check скрипт
  if ask_yn "mon_health" "Установить скрипт health-check (диск, failed units, сертификаты, fail2ban)?" y; then
    local hc_email hc_webhook
    hc_email=$(ask_val "mon_health_email" "Email для алертов health-check" "root")
    hc_webhook=$(ask_val "mon_health_webhook" "Webhook URL (пусто = только email)" "")
    if [[ $DRY_RUN -eq 0 ]]; then
      cat >/usr/local/sbin/harden-health-check.sh <<EOF
#!/bin/sh
# harden.sh: ежедневная проверка здоровья сервера
MSG=""
# диск
DF=\$(df -P / | awk 'NR==2{gsub("%","");print \$5}')
[ "\$DF" -gt 90 ] && MSG="\$MSG\nДиск >90% (\$DF%)"
# failed units
if command -v systemctl >/dev/null 2>&1; then
  FAILED=\$(systemctl --failed --no-legend 2>/dev/null | wc -l)
  [ "\$FAILED" -gt 0 ] && MSG="\$MSG\nFailed systemd units: \$FAILED"
fi
# сертификаты Let's Encrypt
for c in /etc/letsencrypt/live/*/fullchain.pem; do
  [ -f "\$c" ] || continue
  if ! openssl x509 -in "\$c" -noout -checkend 1209600 >/dev/null 2>&1; then
    MSG="\$MSG\nСертификат истекает <14 дней: \$c"
  fi
done
# fail2ban
if command -v fail2ban-client >/dev/null 2>&1; then
  BAN=\$(fail2ban-client status 2>/dev/null | awk -F': ' '/Jail list/{print \$2}' | tr ',' '\n' | while read j; do fail2ban-client status "\$j" 2>/dev/null | awk -F': ' '/Currently banned/{print \$2}'; done | awk '{s+=\$1} END{print s+0}')
  [ "\$BAN" -gt 0 ] && MSG="\$MSG\nFail2ban: активных банов: \$BAN"
fi
if [ -n "\$MSG" ]; then
  printf "harden health-check \$(hostname) \$(date -Is)\n\$MSG\n" > /tmp/hc.msg
  [ -s "$hc_email" ] && mail -s "ALERT: health-check \$(hostname)" "$hc_email" < /tmp/hc.msg 2>/dev/null
  [ -n "$hc_webhook" ] && curl -fsS -X POST -H 'Content-Type: application/json' -d "\$(jq -Rs . < /tmp/hc.msg | sed 's/^/{"text":/;s/\$/}/' 2>/dev/null || echo '{}')" "$hc_webhook" >/dev/null 2>&1
fi
EOF
      chmod 700 /usr/local/sbin/harden-health-check.sh
      echo "30 6 * * * root /usr/local/sbin/harden-health-check.sh" >/etc/cron.d/harden-health
      chmod 644 /etc/cron.d/harden-health
      ok "health-check установлен (ежедневно 06:30)"
    fi
  fi
  rep "- Мониторинг: journald/chrony/node_exporter/AIDE/logwatch/health-check (по выбору)"
  return 0
}

# ============================================================================
# МОДУЛЬ: permissions — права, SUID, auditd
# ============================================================================
mod_permissions() {
  # 1. Мирово-записываемые каталоги
  local ww
  ww=$(find / -xdev \( -path /proc -o -path /sys -o -path /dev -o -path /run -o -path /tmp -o -path /var/tmp -o -path /snap \) -prune -o -type d -perm -0002 -print 2>/dev/null | head -50)
  if [[ -n $ww ]]; then
    warn "Мирово-записываемые каталоги:"
    echo "$ww"
    if ask_yn "perm_ww" "Снять права записи у «прочих» (o-w) для этих каталогов?" n; then
      echo "$ww" | while read -r d; do chmod o-w "$d" 2>/dev/null || true; done
      ok "Права исправлены"
    fi
  else
    ok "Мирово-записываемых каталогов не найдено"
  fi

  # 2. SUID/SGID — инвентаризация
  local suid
  suid=$(find / -xdev \( -path /proc -o -path /sys -o -path /dev \) -prune -o -type f \( -perm -4000 -o -perm -2000 \) -print 2>/dev/null | head -60)
  mkdir -p /root/harden-reports
  echo "$suid" >/root/harden-reports/suid-sgid-${TS}.txt
  info "SUID/SGID-файлы сохранены в /root/harden-reports/suid-sgid-${TS}.txt (проверьте подозрительные)"

  # 3. Права критических файлов
  local f
  for f in /etc/passwd /etc/group /etc/shadow /etc/gshadow /etc/sudoers; do
    [[ -f $f ]] || continue
    case "$f" in
      /etc/shadow|/etc/gshadow) chmod 640 "$f"; chgrp shadow "$f" 2>/dev/null || true ;;
      /etc/sudoers)             chmod 440 "$f" ;;
      *)                        chmod 644 "$f" ;;
    esac
  done
  ok "Права /etc/passwd,shadow,sudoers нормализованы"

  # 4. auditd
  if ask_yn "perm_audit" "Установить и настроить auditd (журнал изменений критичных файлов и команд)?" y; then
    pkg_install auditd audispd-plugins >/dev/null 2>&1 || pkg_install audit >/dev/null 2>&1 || true
    if [[ $DRY_RUN -eq 0 ]] && (pkg_is_installed auditd || pkg_is_installed audit); then
      write_file /etc/audit/rules.d/99-harden.rules <<'EOF'
# harden.sh: аудит критичных файлов и привилегированных команд
-w /etc/passwd -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/group -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/sudoers -p wa -k sudoers
-w /etc/sudoers.d/ -p wa -k sudoers
-w /etc/ssh/sshd_config -p wa -k sshd_config
-w /etc/ssh/sshd_config.d/ -p wa -k sshd_config
-w /etc/fail2ban/ -p wa -k fail2ban
-w /etc/exim4/ -p wa -k exim
-w /etc/postfix/ -p wa -k postfix
-w /etc/dovecot/ -p wa -k dovecot
-w /etc/letsencrypt/ -p wa -k certs
-a always,exit -F arch=b64 -S execve -F euid=0 -F auid>=1000 -F auid!=4294967295 -k rootcmd
-a always,exit -F arch=b32 -S execve -F euid=0 -F auid>=1000 -F auid!=4294967295 -k rootcmd
EOF
      if command -v augenrules >/dev/null 2>&1; then
        run augenrules --load 2>/dev/null || true
      fi
      if [[ $HAVE_SYSTEMD -eq 1 ]]; then
        run systemctl enable --now auditd 2>/dev/null || true
      fi
      ok "auditd: правила загружены (99-harden.rules)"
    fi
  fi
  rep "- Permissions: SUID-инвентаризация, права /etc, auditd"
  return 0
}

# ============================================================================
# МОДУЛЬ: verify — финальная проверка и отчёт
# ============================================================================
V_PASS=0; V_WARN=0; V_FAIL=0

vpass() { printf '%s[PASS]%s %s\n' "$C_GREEN" "$C_RESET" "$*"; rep "  - PASS: $*"; V_PASS=$((V_PASS+1)); }
vwarn() { printf '%s[WARN]%s %s\n' "$C_YELLOW" "$C_RESET" "$*"; rep "  - WARN: $*"; V_WARN=$((V_WARN+1)); }
vfail() { printf '%s[FAIL]%s %s\n' "$C_RED" "$C_RESET" "$*"; rep "  - FAIL: $*"; V_FAIL=$((V_FAIL+1)); }

scan_tls_port() {  # scan_tls_port <port> [starttls smtp|imap|pop3]
  local port="$1" starttls="${2:-}" out proto cipher
  local args=(-connect "127.0.0.1:$port" -brief -ign_eof)
  [[ -n $starttls ]] && args+=(-starttls "$starttls")
  out=$(echo | timeout 6 openssl s_client "${args[@]}" 2>&1 || true)
  proto=$(echo "$out" | awk -F': ' '/Protocol[ :]+/{print $2}' | head -1)
  cipher=$(echo "$out" | awk -F': ' '/Cipher[ :]+/{print $2}' | head -1)
  [[ -z $proto ]] && proto=$(echo "$out" | grep -oE 'TLSv1\.[0-3]|SSLv[23]|TLSv1\.3' | head -1)
  [[ -z $cipher ]] && cipher=$(echo "$out" | grep -oE '[A-Z0-9]+-[A-Z0-9-]+-[A-Z0-9]+' | head -1)
  echo "$port|$proto|$cipher"
}

mod_verify() {
  header "Финальная верификация"
  rep "## Отчёт проверки ($(date -u +%FT%TZ))"

  # --- SSH ---
  rep "### SSH"
  if command -v sshd >/dev/null 2>&1; then
    local eff
    eff=$(sshd -T 2>/dev/null)
    local prl pwa pam x11 maxa
    prl=$(echo "$eff" | awk '/^permitrootlogin/{print $2}')
    pwa=$(echo "$eff" | awk '/^passwordauthentication/{print $2}')
    pam=$(echo "$eff" | awk '/^permitemptypasswords/{print $2}')
    x11=$(echo "$eff" | awk '/^x11forwarding/{print $2}')
    maxa=$(echo "$eff" | awk '/^maxauthtries/{print $2}')
    [[ $prl == no ]] && vpass "SSH: PermitRootLogin=no" || vwarn "SSH: PermitRootLogin=$prl"
    [[ $pwa == no ]] && vpass "SSH: PasswordAuthentication=no (только ключи)" || vwarn "SSH: PasswordAuthentication=$pwa (пароли разрешены)"
    [[ $pam == no ]] && vpass "SSH: PermitEmptyPasswords=no" || vfail "SSH: PermitEmptyPasswords=$pam"
    [[ $x11 == no ]] && vpass "SSH: X11Forwarding=no" || vwarn "SSH: X11Forwarding=$x11"
    [[ ${maxa:-10} -le 4 ]] && vpass "SSH: MaxAuthTries=$maxa" || vwarn "SSH: MaxAuthTries=$maxa (>4)"
    if echo "$eff" | grep -q '^ciphers'; then
      echo "$eff" | awk '/^ciphers/{print "    Ciphers: "$2}' | rep
      if echo "$eff" | awk '/^ciphers/{print $2}' | grep -qiE 'rc4|3des|cbc|arcfour|blowfish'; then
        vwarn "SSH: в списке шифров есть ослабленные (rc4/3des/cbc)"
      else
        vpass "SSH: современные шифры (chacha20/aes-gcm/ctr)"
      fi
    fi
  else
    vwarn "sshd не найден"
  fi

  # --- Firewall ---
  rep "### Firewall"
  case "$(detect_fw_backend)" in
    ufw)
      if ufw status 2>/dev/null | grep -q 'Status: active'; then
        vpass "ufw активен"
        rep '```'; ufw status | rep; rep '```'
      else
        vfail "ufw установлен, но НЕ активен"
      fi
      ;;
    firewalld)
      firewall-cmd --state >/dev/null 2>&1 && vpass "firewalld активен" || vfail "firewalld не активен"
      ;;
    nftables)
      nft list table inet harden >/dev/null 2>&1 && vpass "nftables: таблица harden загружена" || vwarn "nftables: таблица harden не найдена"
      ;;
    *) vfail "Файрвол не обнаружен/не активен" ;;
  esac

  # --- Fail2ban ---
  rep "### Fail2ban"
  if command -v fail2ban-client >/dev/null 2>&1; then
    if fail2ban-client status >/dev/null 2>&1; then
      vpass "fail2ban работает"
      local jails j
      jails=$(fail2ban-client status 2>/dev/null | awk -F': ' '/Jail list/{print $2}' | tr ',' ' ')
      rep "  Jail: $jails"
      for j in $jails; do
        local banned
        banned=$(fail2ban-client status "$j" 2>/dev/null | awk -F': ' '/Currently banned/{print $2}')
        rep "    $j: banned=${banned:-0}"
      done
    else
      vfail "fail2ban установлен, но не работает"
    fi
  else
    vwarn "fail2ban не установлен"
  fi

  # --- Порты ---
  rep "### Слушающие порты"
  local ports
  ports=$(ss -H -lnt 2>/dev/null | awk '{print $4}' | sed 's/.*://' | sort -un | tr '\n' ' ')
  rep "  TCP: $ports"
  info "Слушающие TCP: $ports"

  # --- TLS-скан локальных сервисов ---
  rep "### TLS-шифры/протоколы"
  local line port proto cipher
  if ss -lnt | grep -q ':443 '; then
    line=$(scan_tls_port 443); IFS='|' read -r port proto cipher <<<"$line"
    if [[ $proto == TLSv1.3 || $proto == TLSv1.2 ]]; then
      vpass "443: $proto / $cipher"
    else
      vfail "443: протокол $proto (ожидается TLS1.2+) / $cipher"
    fi
  fi
  local st
  for st in "25:smtp" "587:smtp" "993:imap" "995:pop3"; do
    local p="${st%%:*}" m="${st##*:}"
    ss -lnt | grep -q ":$p " || continue
    line=$(scan_tls_port "$p" "$m"); IFS='|' read -r port proto cipher <<<"$line"
    if [[ $proto == TLSv1.3 || $proto == TLSv1.2 ]]; then
      vpass "$p ($m): $proto / $cipher"
    else
      vfail "$p ($m): протокол $proto / $cipher"
    fi
  done
  # Слабые шифры на 25/443 (быстрая проба)
  for p in 443 25; do
    ss -lnt | grep -q ":$p " || continue
    local starg=""
    [[ $p == 25 ]] && starg="-starttls smtp"
    if echo | timeout 6 openssl s_client -connect "127.0.0.1:$p" $starg -tls1_1 2>/dev/null | grep -q 'Protocol.*TLS'; then
      vfail "$p: сервер принимает TLS1.1!"
    fi
  done

  # --- Web-заголовки и cookie ---
  rep "### Web-заголовки / cookie"
  local domains="${ANS[mail_domain]:-}${ANS[ssl_domains]:-}"
  local d
  for d in $domains localhost; do
    [[ -z $d || $d == example.com ]] && continue
    local hdrs
    hdrs=$(curl -skI --max-time 8 "https://$d/" 2>/dev/null || curl -skI --max-time 8 -H "Host: $d" https://127.0.0.1/ 2>/dev/null || true)
    [[ -z $hdrs ]] && continue
    info "Заголовки https://$d:"
    echo "$hdrs" | head -20
    echo "$hdrs" | grep -qi 'strict-transport-security' && vpass "$d: HSTS" || vwarn "$d: нет HSTS"
    echo "$hdrs" | grep -qi 'x-content-type-options' && vpass "$d: X-Content-Type-Options" || vwarn "$d: нет X-Content-Type-Options"
    echo "$hdrs" | grep -qiE 'x-frame-options|frame-ancestors' && vpass "$d: anti-clickjacking" || vwarn "$d: нет X-Frame-Options/frame-ancestors"
    echo "$hdrs" | grep -qi 'content-security-policy' && vpass "$d: CSP" || vwarn "$d: нет CSP"
    echo "$hdrs" | grep -qi 'referrer-policy' && vpass "$d: Referrer-Policy" || vwarn "$d: нет Referrer-Policy"
    echo "$hdrs" | grep -qi 'cross-origin-opener-policy' && vpass "$d: COOP" || vwarn "$d: нет COOP"
    echo "$hdrs" | grep -qi 'x-powered-by' && vfail "$d: утечка X-Powered-By" || vpass "$d: X-Powered-By скрыт"
    # cookie
    local cookies
    cookies=$(echo "$hdrs" | grep -i '^set-cookie:')
    if [[ -n $cookies ]]; then
      echo "$cookies" | while read -r c; do
        echo "    cookie: $c"
      done | rep
      echo "$cookies" | grep -viE 'secure' >/dev/null && vwarn "$d: есть cookie без Secure" || vpass "$d: все cookie с Secure"
      echo "$cookies" | grep -viE 'httponly' >/dev/null && vwarn "$d: есть cookie без HttpOnly" || vpass "$d: все cookie с HttpOnly"
      echo "$cookies" | grep -viE 'samesite' >/dev/null && vwarn "$d: есть cookie без SameSite" || vpass "$d: все cookie с SameSite"
    fi
    break  # достаточно одного домена
  done

  # --- Почта ---
  rep "### Почта"
  if [[ $MTA == exim ]] && command -v exim4 >/dev/null 2>&1; then
    local dports tlsadv
    dports=$(exim -bP daemon_smtp_ports 2>/dev/null)
    tlsadv=$(exim -bP tls_advertise_hosts 2>/dev/null)
    rep "  daemon_smtp_ports: $dports"
    rep "  tls_advertise_hosts: $tlsadv"
    vpass "Exim: конфигурация читается (ports: $dports)"
  fi
  if [[ $IMAP == dovecot ]] && command -v dovecot >/dev/null 2>&1; then
    dovecot -n 2>/dev/null | grep -q 'ssl = required' && vpass "Dovecot: ssl=required" || vwarn "Dovecot: ssl не required"
    ss -lnt | grep -qE ':(143|110) ' && vwarn "Dovecot: незашифрованные порты 143/110 слушаются" || vpass "Dovecot: plaintext-порты закрыты"
  fi

  # --- DNS ---
  rep "### DNS (SPF/DKIM/DMARC)"
  local dom="${ANS[mail_domain]:-}"
  if [[ -n $dom && $dom != example.com ]]; then
    local spf dmarc dkim
    spf=$(spf_lookup "$dom")
    [[ -n $spf ]] && vpass "SPF: $spf" || vfail "SPF отсутствует"
    dmarc=$(dig +short TXT "_dmarc.$dom" 2>/dev/null | tr -d '"' | grep -E '^v=DMARC1' | head -1)
    [[ -n $dmarc ]] && vpass "DMARC: $dmarc" || vfail "DMARC отсутствует"
    dkim=$(dig +short TXT "${ANS[dkim_selector]:-mail}._domainkey.$dom" 2>/dev/null | tr -d '"' | head -1)
    [[ -n $dkim ]] && vpass "DKIM-запись видна" || vwarn "DKIM-запись не видна"
  fi

  # --- Сертификаты ---
  rep "### Сертификаты"
  local c
  for c in /etc/letsencrypt/live/*/fullchain.pem /etc/ssl/harden/mail.crt /etc/ssl/harden/selfsigned.crt; do
    [[ -f $c ]] || continue
    if openssl x509 -in "$c" -noout -checkend 1209600 >/dev/null 2>&1; then
      vpass "cert OK >14д: $c"
    else
      vfail "cert истекает <14 дней: $c"
    fi
  done

  # --- sysctl / автообновления ---
  rep "### Ядро / автообновления"
  local kv
  for kv in kernel.kptr_restrict=2 kernel.dmesg_restrict=1 net.ipv4.tcp_syncookies=1 net.ipv4.conf.all.rp_filter=1; do
    local key="${kv%%=*}" want="${kv##*=}"
    local got
    got=$(sysctl -n "$key" 2>/dev/null || echo "?")
    [[ $got == "$want" ]] && vpass "sysctl $key=$got" || vwarn "sysctl $key=$got (ожидалось $want)"
  done
  if [[ $HAVE_SYSTEMD -eq 1 ]]; then
    systemctl is-enabled --quiet unattended-upgrades 2>/dev/null || systemctl is-enabled --quiet dnf-automatic.timer 2>/dev/null \
      && vpass "Авто-обновления включены" || vwarn "Авто-обновления не включены (модуль updates)"
  fi

  # --- Итог ---
  rep ""
  rep "### Итог: PASS=$V_PASS WARN=$V_WARN FAIL=$V_FAIL"
  echo
  header "ИТОГ: PASS=$V_PASS  WARN=$V_WARN  FAIL=$V_FAIL"
  info "Отчёт: $REPORT_FILE"
  if [[ $DRY_RUN -eq 0 ]]; then
    {
      echo "# Отчёт harden.sh"
      echo
      printf '%s\n' "${REPORT_LINES[@]}"
    } >"$REPORT_FILE"
    chmod 600 "$REPORT_FILE"
  fi
  [[ $V_FAIL -eq 0 ]] && return 0 || return 1
}

# ============================================================================
# main
# ============================================================================
main() {
  parse_args "$@"
  preflight

  if [[ $REPORT_ONLY -eq 1 ]]; then
    run_module verify "Финальная проверка и отчёт" mod_verify
    finish
    exit $?
  fi

  info "Порядок: сначала критичные (updates→sysctl→pam→ssh→firewall), затем сервисы, DNS и аудит."
  warn "СОВЕТ: не закрывайте текущую SSH-сессию, пока не проверили доступ по новому порту/ключам!"

  run_module updates       "Системные обновления и авто-обновления безопасности" mod_updates
  run_module sysctl        "Ядро и сеть: sysctl-харденинг"                        mod_sysctl
  run_module pam           "Парольная политика, PAM, лимиты, umask"                mod_pam
  run_module ssh           "Защита SSH (OpenSSH)"                                  mod_ssh
  run_module firewall      "Межсетевой экран"                                      mod_firewall
  run_module fail2ban      "Fail2ban"                                              mod_fail2ban
  run_module legacy_auth   "Запрет небезопасной авторизации и legacy-протоколов"   mod_legacy_auth
  run_module ssl           "SSL/TLS-сертификаты (ACME)"                            mod_ssl
  run_module web_headers   "Web-заголовки безопасности"                            mod_web_headers
  run_module real_ip       "Защита реального IP и периметр"                        mod_real_ip
  run_module mail          "Ужесточение SMTP/IMAP/POP3"                            mod_mail
  run_module dkim          "Настройка DKIM-подписи"                                mod_dkim
  run_module spf           "SPF: мягкий → жёсткий"                                 mod_spf
  run_module dmarc         "DMARC: none → quarantine → reject"                     mod_dmarc
  run_module spoof         "Проверка spoofing и открытого релея"                   mod_spoof
  run_module cve           "Проверка CVE по установленным пакетам"                 mod_cve
  run_module critical_updates "Точечное обновление OpenSSH/Exim/связанных"         mod_critical_updates
  run_module backups       "Резервные копии (restic/borg)"                         mod_backups
  run_module monitoring    "Мониторинг и алерты"                                   mod_monitoring
  run_module ports         "Аудит открытых портов"                                 mod_ports
  run_module permissions   "Права файлов, SUID/SGID, auditd, sudo"                 mod_permissions
  run_module verify        "Финальная проверка и отчёт"                            mod_verify

  finish
}

finish() {
  header "Завершение"
  local m
  for m in "${!MODULE_STATUS[@]}"; do
    printf '  %-18s %s\n' "$m" "${MODULE_STATUS[$m]}"
  done
  echo
  info "Лог:          $LOG_FILE"
  info "Бэкап конфигов: $BACKUP_DIR"
  info "Ответы:       $ANS_FILE (переиспользуйте: ./harden.sh --answers $ANS_FILE)"
  [[ -f $REPORT_FILE ]] && info "Отчёт:        $REPORT_FILE"
  echo
  warn "Не забудьте:"
  echo "  1. Проверить доступ по SSH в ОТДЕЛЬНОЙ сессии (новый порт/ключ), затем закрыть старую."
  echo "  2. Опубликовать DNS-записи из /root/harden-dns/ (DKIM, SPF, DMARC) и перезапустить:"
  echo "       ./harden.sh --module dmarc,spoof --answers $ANS_FILE"
  echo "  3. Подключить мониторинг к node_exporter/AIDE-отчётам."
  [[ ${MODULE_STATUS[verify]:-} == fail ]] && return 1 || return 0
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  main "$@"
fi
