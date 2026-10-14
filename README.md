# server-hardening — комплексная защита Linux-сервера

Интерактивный скрипт **`harden.sh`** (bash) и его зеркальный **Ansible-вариант**
для укрепления свежего или действующего Linux-сервера: SSH, файрвол, Fail2ban,
TLS-сертификаты, почта (SMTP/IMAP/POP3), DKIM/SPF/DMARC, проверка CVE,
резервные копии, мониторинг и аудит.

Каждый параметр запрашивается у оператора перед применением. Все изменения
конфигов бэкапятся, перед запуском предусмотрены `--dry-run` и
`--report-only`, есть функция `--verify` для проверки результата.

```
harden.sh v1.0.0
22 модуля · 2 интерфейса (bash + Ansible) · без перезагрузки по умолчанию
```

---

## Содержание

- [Возможности](#возможности)
- [Требования](#требования)
- [Быстрый старт](#быстрый-старт)
- [Вариант 1: harden.sh](#вариант-1-hardensh)
- [Вариант 2: Ansible](#вариант-2-ansible)
- [Список модулей](#список-модулей)
- [Почтовые DNS-записи: порядок ввода](#почтовые-dns-записи-порядок-ввода)
- [Безопасность запуска](#безопасность-запуска)
- [Откат изменений](#откат-изменений)
- [Отчёты и логи](#отчёты-и-логи)
- [Структура проекта](#структура-проекта)
- [Совместимость ОС](#совместимость-ос)
- [Troubleshooting](#troubleshooting)

---

## Возможности

| Область | Что делает |
|---|---|
| **Ядро и сеть (sysctl)** | `rp_filter`, `tcp_syncookies`, `tcp_rfc1337`, запрет ICMP-redirect/source-route, `log_martians`, `kptr_restrict=2`, `dmesg_restrict=1`, `yama.ptrace_scope=1`, `unprivileged_bpf_disabled=1`, запрет core dumps, `protected_symlinks/hardlinks` |
| **SSH** | Только pubkey-авторизация (опционально), запрет root-логина, `MaxAuthTries=3`, отключены X11/TCP-agent-forwarding, `UsePAM`, `internal-sftp`, `LogLevel VERBOSE`, жёсткие `KexAlgorithms`/`Ciphers`/`MACs` (OpenSSH ≥ 7.6, только AEAD + ChaCha20) |
| **PAM / пароли** | `pwquality` (minlen=14, difok=8, minclass=3), `pam_faillock` (5 попыток / 15 мин, включая root), `PASS_MAX_DAYS=90`, umask 027, `nullok` удалён, sudo: `use_pty`, лог в `/var/log/sudo.log` |
| **Файрвол** | ufw (Debian) или firewalld (RHEL): default deny incoming, limit SSH, 80/443/почтовые порты по выбору |
| **Fail2ban** | Jail: sshd (aggressive), exim, exim-spam, exim-auth, dovecot, nginx-http-auth, nginx-botsearch, recidive (7 дней на все порты) |
| **TLS** | Сертификат Let's Encrypt (certbot, webroot), TLS 1.2/1.3 по Mozilla guideline 6.0 (intermediate), session tickets off, OCSP stapling, автопродление с deploy-hook для MTA |
| **Web-заголовки** | HSTS (max-age 63072000, опционально preload), CSP (stricter), `X-Content-Type-Options`, `X-Frame-Options: DENY`, `Referrer-Policy`, `Permissions-Policy`, COOP/CORP/(COEP) для nginx и Apache |
| **Реальный IP** | За CDN/proxy: `set_real_ip_from` из Cloudflare-диапазонов (или своих), ufw-правила только на доверенные IP |
| **Почта** | Exim: AUTH только по TLS, запрет VRFY/EXPN, rate limit, SPF-проверка в ACL (native, без milter), DKIM native, `tls_require_ciphers`, DoS-лимиты. Postfix: submission (587) с SASL, без plaintext. Dovecot: `ssl=required`, TLSv1.2+, только imaps/pop3s |
| **DKIM/SPF/DMARC** | Генерация RSA-2048 ключа + DNS-запись, SPF `~all`→`-all`, DMARC `none`→`quarantine`→`reject` с rua-отчётами, проверка spoofing и открытого релея |
| **CVE (Ubuntu)** | Опрос API Canonical (`ubuntu.com/security/cves.json?package=`) по установленным source-пакетам; фильтр по текущему релизу (`needed`/`pending`/`deferred`/`released`); fallback на OVAL; авто-обновление затронутых пакетов |
| **Критичные обновления** | Точечный апгрейд OpenSSH/Exim/Dovecot/OpenSSL/nginx/curl/git |
| **Бэкапы** | restic: шифрование, ежедневный бэкап `/etc /root /home /var/www`, `forget --prune`, systemd-timer, лог в `/var/log/harden-backup.log` |
| **Мониторинг** | journald persistent (500M), chrony, node_exporter (только localhost:9100), AIDE (еженедельный check + mail), health-check (диск >90%, failed units, SSL <14 дней, fail2ban) |
| **Аудит и права** | auditd: лог изменений `/etc/passwd`, `/etc/shadow`, `sshd_config`, `sudoers`, exim/postfix/dovecot/letsencrypt; world-writable → chmod; права 0640 на shadow/gshadow |

---

## Требования

- **ОС:** Ubuntu/Debian — полное покрытие; RHEL/CentOS/Fedora/SUSE/Alpine — базовые модули (детект пакетного менеджера: apt/dnf/yum/zypper/pacman/apk).
- **Права:** root (или `sudo`).
- **systemd:** желателен (скрипт работает и без него, с оговорками в выводе).
- **Сеть:** доступ к репозиториям ОС; для CVE — `ubuntu.com`; для real_ip — `cloudflare.com/ips-v4|v6`; для ACME — `acme-v02.api.letsencrypt.org`.
- **Зависимости bash-варианта:** `curl`, `dig` (dnsutils), `openssl`, `ss`, `systemctl` — недостающее ставится автоматически по ходу.
- **Для Ansible-варианта:** `ansible-core ≥ 2.15` на управляющей машине, Python 3 на целевом сервере.

---

## Быстрый старт

### Вариант 1 — bash (на сервере)

```bash
git clone git@github.com:sithortodox/harden.git
cd harden
sudo ./harden.sh            # интерактивно: задаст все вопросы
```

### Вариант 2 — Ansible (с рабочей машины)

```bash
git clone git@github.com:sithortodox/harden.git
cd harden/ansible
cp inventory/hosts.example.yml inventory/hosts.yml
# отредактируйте hosts.yml: адрес, пользователь, порт
ansible-playbook harden.yml    # vars_prompt задаст все вопросы
```

---

## Вариант 1: harden.sh

### CLI-опции

```
sudo ./harden.sh [опции]

  --list-modules          показать список модулей
  --module a,b,c          выполнить только указанные модули
  --all                   выполнить все модули (с запросом параметров)
  --yes                   принимать значения по умолчанию без запросов
  --dry-run               только показать действия, ничего не менять
  --answers FILE          файл с ответами (загрузка и сохранение)
  --report-only           только выполнить проверку и сформировать отчёт
  --no-color              отключить цвета
  -h, --help              эта справка
```

### Примеры

```bash
# Полный прогон с интерактивными вопросами
sudo ./harden.sh --all

# Только SSH + файрвол + fail2ban
sudo ./harden.sh --module ssh,firewall,fail2ban

# Посмотреть, что скрипт собирается сделать (ничего не меняя)
sudo ./harden.sh --module mail,dkim,spf --dry-run

# Повторный запуск с прежними ответами (например, после правки DNS)
sudo ./harden.sh --answers /root/harden-answers.txt

# Автоматический режим (CI, пакетное применение) — все ответы по умолчанию
sudo ./harden.sh --yes

# Проверить состояние сервера без изменений
sudo ./harden.sh --report-only
```

### Файл ответов (`--answers`)

Формат — `id=значение` (bash `%q`-квотирование), создаётся с правами `0600`.
Файл пишется автоматически при каждом ответе и пригоден для повторного
прогона: после заполнения оставьте только нужные строки и запустите снова —
скрипт не спросит уже известные параметры.

```bash
# пример
ssh_port=2222
ssh_password_auth=n
enable_mail=y
mail_domain=example.com
```

### Порядок модулей

Скрипт исполняет модули в фиксированном порядке (можно ограничить
`--module`):

```
updates → sysctl → pam → ssh → firewall → fail2ban → legacy_auth → ssl →
web_headers → real_ip → mail → dkim → spf → dmarc → spoof → cve →
critical_updates → backups → monitoring → ports → permissions → verify
```

Для почтовой цепочки обязательно соблюдайте порядок
`ssl → mail → dkim → spf → dmarc → spoof` (см. ниже).

---

## Вариант 2: Ansible

### Структура

```
ansible/
├── ansible.cfg              # inventory по умолчанию, become, таймауты
├── harden.yml               # playbook: vars_prompt + include_tasks + handlers
├── group_vars/all.yml       # значения по умолчанию всех параметров
├── inventory/
│   └── hosts.example.yml    # шаблон inventory (скопируйте в hosts.yml)
├── tasks/                   # 18 файлов задач (по одному на модуль)
└── templates/               # 22 Jinja2-шаблона конфигов
```

### Запуск

```bash
cd ansible
cp inventory/hosts.example.yml inventory/hosts.yml   # укажите свой сервер
ansible-playbook harden.yml                          # спросит все параметры
ansible-playbook harden.yml --tags ssh,firewall      # только выбранные модули
ansible-playbook harden.yml --check                  # dry-run
```

> `vars_prompt` в ansible-core **не поддерживает условные промпты** —
> playbook всегда задаёт все вопросы (значения по умолчанию корректны).
> Для полностью неинтерактивного запуска используйте `harden.sh --yes`.

### Переопределение дефолтов

Все «тихие» параметры (шифры, HSTS, fail2ban-тайминги, пути бэкапов и т.д.)
задаются в `group_vars/all.yml` или через `-e`:

```bash
ansible-playbook harden.yml -e hsts_max_age=31536000 -e fail2ban_bantime=86400
```

Ключевые переменные vars_prompt: `enable_*` (вкл/выкл модулей), `ssh_port`,
`ssh_password_auth`, `ssh_permit_root`, `fw_allow_web`, `fw_mail_ports`,
`ssl_domains`, `ssl_email`, `behind_cdn`, `cdn_trusted_ips`, `mail_domain`,
`enable_dkim`, `dkim_selector`, `spf_ip`, `spf_mode`, `dmarc_policy`,
`dmarc_rua`, `cve_auto_upgrade`, `backup_repo`, `backup_password`.

### Теги

`updates kernel pam ssh firewall fail2ban legacy ssl web realip mail dns cve
backups monitoring permissions verify`

---

## Список модулей

| Модуль | Описание | Ключевые действия |
|---|---|---|
| `updates` | Обновления и авто-безопасность | `apt dist-upgrade`; unattended-upgrades (`20auto-upgrades`, `51unattended-upgrades-local`: без авто-reboot, mail root) или dnf-automatic |
| `sysctl` | Ядро и сеть | `/etc/sysctl.d/99-hardening.conf`; core dumps = 0 |
| `pam` | Парольная политика | pwquality, faillock, login.defs, umask, sudoers.d, удаление `nullok` |
| `ssh` | OpenSSH | `/etc/ssh/sshd_config.d/99-harden.conf` (drop-in, не перезаписывает основной конфиг); баннер `/etc/issue.net`; валидация `sshd -t` перед restart |
| `firewall` | Межсетевой экран | ufw: `default deny incoming`, `limit SSH`, allow 80/443/25,465,587,993,995; firewalld-эквивалент |
| `fail2ban` | Баны | `/etc/fail2ban/jail.local` + проверка `fail2ban-client -t` |
| `legacy_auth` | Небезопасные протоколы | удаление telnet/rsh/ftp, `/etc/hosts.deny: ALL: ALL`, `hosts.equiv`, `openssl.cnf: MinProtocol=TLSv1.2` |
| `ssl` | ACME | `certbot certonly --webroot`, deploy-hook копирует сертификат в `/etc/ssl/harden/mail.*` и перезапускает MTA |
| `web_headers` | Заголовки + TLS | nginx `conf.d/00-security-headers.conf` или Apache `conf-available/harden-security.conf`; валидация `nginx -t` |
| `real_ip` | Периметр/CDN | Cloudflare CIDR (авто) или свои, nginx real_ip, ufw-правила per-IP |
| `mail` | SMTP/IMAP/POP3 | Exim split-config: `localmacros`, ACL (SPF, rate limit), AUTH только по TLS, DoS-лимиты, VRFY/EXPN off; Postfix submission 587/SASL; Dovecot `99-harden.conf` |
| `dkim` | DKIM | RSA-2048 в `/etc/exim4/dkim/`, нативная подпись Exim, DNS-запись в отчёт |
| `spf` | SPF | существующая запись читается, предлагается `~all` → `-all`, учитывается лимит 10 DNS-lookups |
| `dmarc` | DMARC | `_dmarc` TXT: p=none/quarantine/reject, rua, adkim/aspf, pct=100 |
| `spoof` | Проверка | SMTP-пробы: MAIL FROM с якобы своего домена, open-relay, VRFY/EXPN, STARTTLS |
| `cve` | Ubuntu CVE | API Canonical по source-пакетам (быстро) или все пакеты (`full`); OVAL-fallback; авто-обновление `released`-фиксов; отчёт `/root/harden-cve-*.txt` |
| `critical_updates` | Точечный апгрейд | apt: openssh/openssl/exim/dovecot/nginx/curl/git |
| `backups` | Резервные копии | restic: init, ежедневный backup+forget/prune через systemd-timer, пароль в `/etc/restic/password` (0600) |
| `monitoring` | Наблюдаемость | journald persistent, chrony, node_exporter (127.0.0.1:9100), AIDE + cron.weekly, health-check cron.daily |
| `ports` | Аудит портов | `ss -tulnp`, сравнение с ожидаемым списком |
| `permissions` | Права | world-writable → `o-w`, 0640 на shadow, auditd-правила + `augenrules --load` |
| `verify` | Проверка | sshd -T, ufw status, fail2ban status, ss, TLS-скан 443/465/587/993, curl-заголовки, dig SPF/DMARC/DKIM, PASS/WARN/FAIL-счётчик |

---

## Почтовые DNS-записи: порядок ввода

> **Важно:** не переводите SPF на `-all` и DMARC на `reject`, пока записи не
> опубликованы и письма не рассылаются через этот сервер — иначе они будут
> отклоняться получателями.

1. **Запустите** `harden.sh --module ssl,mail,dkim` (или через Ansible) —
   скрипт выпустит/подхватит сертификат, настроит MTA, сгенерирует DKIM-ключ
   и напечатает TXT-запись (также сохранит в `/root/harden-dns/`).
2. **Опубликуйте** в DNS-зоне домена:
   - `mail._domainkey` TXT с DKIM-ключом;
   - `@` TXT `v=spf1 mx a ip4:<IP> ~all` (политика soft);
   - `_dmarc` TXT `v=DMARC1; p=none; rua=mailto:...` (политика none).
3. **Дождитесь** делегирования/кэша (`dig +short TXT ...`), затем прогон
   `--module spoof,dmarc` — проверка SPF/DKIM-подписи и DMARC-оценки.
4. **Ужесточайте** постепенно: `~all` → `-all` (SPF), `p=none` →
   `p=quarantine` → `p=reject` (DMARC), наблюдая rua-отчёты 1–2 недели.

---

## Безопасность запуска

- **Всегда открывайте вторую SSH-сессию** перед запуском. Проверьте вход в
  ней, прежде чем закрывать первую: скрипт меняет конфиг sshd и правила
  файрвола.
- Перед каждым изменением конфиг-файла делается бэкап в
  `/root/harden-backup-<дата>/` (tar.gz).
- `--dry-run` печатает планируемые действия и не изменяет систему.
- Секреты (пароли бэкапов, ключи) не пишутся в лог; лог урежается по
  содержимому.

---

## Откат изменений

```bash
# 1. Найти бэкап
ls /root/harden-backup-*/

# 2. Распаковать (структура = дерево /etc, /root и т.д.)
cd / && tar -xzf /root/harden-backup-<дата>/etc-*.tar.gz   # и т.д.

# 3. Перезапустить затронутые сервисы
sudo systemctl restart sshd nginx fail2ban exim4 postfix dovecot

# 4. Убрать дроп-ин, если хотите полностью откатить SSH
sudo rm /etc/ssh/sshd_config.d/99-harden.conf && sudo systemctl restart sshd
```

Ansible-вариант хранит бэкапы конфигов перед шаблонизацией в тех же
каталогах (задачи `file`/`copy` с `backup: true` через `ANSIBLE_BACKUP`).

---

## Отчёты и логи

| Файл | Что |
|---|---|
| `/var/log/harden/harden-<дата>.log` | Полный лог выполнения (bash) |
| `/root/harden-report-<дата>.md` | Итоговый отчёт PASS/WARN/FAIL (bash, `verify`) |
| `/root/harden-dns/` | Скопированные/предложенные DNS-записи (bash) |
| `/root/harden-cve-<codename>.txt` | Результаты CVE-скана (Ubuntu) |
| `/root/harden-ansible/report.txt` | Верификационный отчёт (Ansible) |
| `/root/harden-ansible/dns-*.txt` | DKIM/SPF/DMARC-записи (Ansible) |
| `/var/log/harden-backup.log` | Лог restic-бэкапов |

---

## Структура проекта

```
harden/
├── harden.sh               # bash-скрипт (интерактивный, ~3400 строк)
├── README.md
└── ansible/                # Ansible-обёртка (зеркало модулей)
    ├── ansible.cfg
    ├── harden.yml
    ├── group_vars/all.yml
    ├── inventory/hosts.example.yml
    ├── tasks/              # updates.yml … verify.yml
    └── templates/          # sshd, sysctl, fail2ban, nginx, exim,
                            # dovecot, restic, audit, cve_scan.py …
```

---

## Совместимость ОС

| ОС | Статус |
|---|---|
| Ubuntu 20.04–24.04 | Полная поддержка (включая CVE-скан по API/OVAL) |
| Debian 11/12 | Полная поддержка (CVE-скан по Ubuntu-API не применяется, используется только apt) |
| RHEL/Rocky/AlmaLinux/Fedora | Базовые модули (firewalld вместо ufw, dnf-automatic, exim/postfix) |
| openSUSE Leap | Базовые модули (zypper, firewalld) |
| Alpine | Базовые модули (apk, без systemd — с оговорками) |

---

## Troubleshooting

**После запуска не пускает по SSH**
- Переключитесь на уже открытую сессию (или консоль провайдера);
- `sshd -t` покажет ошибку конфигурации;
- Восстановите бэкап `/root/harden-backup-*` или удалите
  `/etc/ssh/sshd_config.d/99-harden.conf` и перезапустите sshd.

**Certbot: `Connection refused` на :80**
- Убедитесь, что 80/tcp открыт во внешнем файрволе провайдера и в ufw,
  nginx/apache слушает и отдаёт `/.well-known/acme-challenge/`.

**Fail2ban пишет `Backend somehow failed`**
- Проверьте наличие jail.local и логов (`backend = systemd` на modern
  дистрибутивах); `fail2ban-client -t -d | less`.

**Exim: `TLS on connect` / AUTH не рекламируется**
- AUTH доступен только после STARTTLS — это ожидаемо; проверьте
  `exim -bP` и сертификат `/etc/ssl/harden/mail.crt`.

**CVE-скан молчит или падает**
- Скрипт требует Ubuntu + network до `ubuntu.com`; на Debian/CentOS модуль
  `cve` пропускается. Ручная проверка:
  `curl -s 'https://ubuntu.com/security/cves.json?package=openssh' | head`.

**DMARC отклоняет письма**
- Вернитесь к `p=none`, проверьте, что SPF-запись указывает на реальный
  исходящий IP и что DKIM-ключ опубликован (`dig +short TXT mail._domainkey`).

---

## Лицензия

MIT. Используйте на свой риск: всегда делайте снапшок перед первым запуском
на продакшене и проверяйте доступ по второй сессии.
