#!/bin/bash
# =============================================================================
# Поддержка Ubuntu 22.04 (чистая установка)
# Версия: 2.5.0
# =============================================================================

# Проверка прав root
if [ "$(id -u)" -ne 0 ]; then
  echo "Ошибка: Скрипт должен быть запущен от root. Завершение." >&2
  exit 1
fi

# Устанавливаем неинтерактивный режим для apt
export DEBIAN_FRONTEND=noninteractive

# ANSI-коды для цветов
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Глобальные переменные для логирования
STEP_LOG=()
SCRIPT_ERROR=0

# Функция для логирования успешных сообщений
log_info() {
    echo -e "${GREEN}[OK]${NC} $1 - УСПЕШНО"
    STEP_LOG+=("${GREEN}[OK]${NC} $1 - УСПЕШНО")
}

# Функция для логирования ошибок
log_error() {
    echo -e "${RED}[ERROR]${NC} $1 - ОШИБКА" >&2
    STEP_LOG+=("${RED}[ERROR]${NC} $1 - ОШИБКА")
}

# Функция завершения скрипта при ошибке с выводом хода выполнения
error_exit() {
    log_error "$1"
    SCRIPT_ERROR=1
    echo -e "\n${YELLOW}Ход выполнения:${NC}"
    for step in "${STEP_LOG[@]}"; do
         echo -e "$step"
    done
    echo -e "\n[Завершение скрипта]"
    exit 1
}

# Проверка прав root
check_root() {
    if [ "$EUID" -ne 0 ]; then
        error_exit "Скрипт должен быть запущен с правами root (через sudo или от root)"
    fi
}

# Функция переключения сетевого управления на systemd-networkd
configure_network_services() {
    log_info "Переключаю сетевое управление на systemd-networkd"
    # Останавливаем и отключаем NetworkManager
    systemctl stop NetworkManager.service 2>/dev/null || log_info "NetworkManager не установлен"
    systemctl disable NetworkManager.service 2>/dev/null || log_info "NetworkManager не установлен/отключение службы"

    # Включаем и запускаем systemd-networkd
    systemctl enable systemd-networkd.service || error_exit "Не удалось включить systemd-networkd"
    systemctl start systemd-networkd.service || error_exit "Не удалось запустить systemd-networkd"

    # Удаляем старые netplan-конфигурации с renderer NetworkManager 
    rm -f /etc/netplan/*.yml

    log_info "Сетевые службы переключены на systemd-networkd"
}

# Установщик пакетов
install_packages() {
    log_info "Инициализация запуска обновлений + установки программ"
    apt-get update || error_exit "Обновление репозиториев не выполнено"
    
    apt-get upgrade -y || error_exit "Обновление системы не выполнено"
    log_info "Обновление системы прошло"
    
    apt-get install -y htop net-tools mtr network-manager wireguard openvpn apache2 php git iptables-persistent openssh-server resolvconf speedtest-cli nload libapache2-mod-php isc-dhcp-server libapache2-mod-authnz-pam shellinabox dos2unix python3-venv python3.10-venv || error_exit "Установка необходимых пакетов не выполнена"
    log_info "Необходимые пакеты установлены"

    # Включаем необходимые модули Apache: proxy, proxy_http, authnz_pam, rewrite
    a2enmod proxy || error_exit "Не удалось включить модуль proxy"
    a2enmod proxy_http || error_exit "Не удалось включить модуль proxy_http"
    a2enmod rewrite || error_exit "Не удалось включить модуль rewrite"
    a2enmod authnz_pam || error_exit "Не удалось включить модуль authnz_pam"
    systemctl restart apache2 || error_exit "Не удалось перезапустить Apache после включения модулей"

    # Если установлен dnsmasq – удаляем его
    if dpkg -l | grep -qw dnsmasq; then
        log_info "Удаление dnsmasq"
        systemctl stop dnsmasq 2>/dev/null
        systemctl disable dnsmasq 2>/dev/null
        
        apt-get purge -y \
            -o Dpkg::Options::="--force-confdef" \
            -o Dpkg::Options::="--force-confold" \
            dnsmasq || error_exit "Не удалось удалить dnsmasq"
        
        log_info "dnsmasq удалён"
    fi

    # Если обнаружен openvswitch-switch – удаляем его
    if dpkg -l | grep -q openvswitch-switch; then
        log_info "Удаление openvswitch-switch"
        systemctl stop openvswitch-switch
        systemctl disable openvswitch-switch
        
        apt-get purge -y \
            -o Dpkg::Options::="--force-confdef" \
            -o Dpkg::Options::="--force-confold" \
            openvswitch-switch || error_exit "Не удалось удалить openvswitch-switch"
        
        log_info "openvswitch-switch удалён"
    fi
}

preselect_interfaces() {
    echo "Какое действие выполнить с NETPLAN?"
    echo "1. Полная настройка."
    echo "2. Настроить только NETPLAN и пропустить основную настройку."
    echo "3. Пропустить настройку NETPLAN и выполнить дальше основную настройку."
    read -r -p "Ваш выбор [1/2/3]: " netplan_choice

    case "$netplan_choice" in
        1)
            # Полная настройка
            select_interfaces
            configure_netplan
            ;;
        2)
            # Настроить только NETPLAN и пропустить основную настройку.
            select_interfaces
            configure_netplan
            echo -e "\n${GREEN}[OK]${NC} Настройка netplan выполнена. Дальнейшая настройка пропущена."
            exit 0
            ;;
        3)
            # Пропустить настройку NETPLAN и выполнить дальше основную настройку.
            netplan_file=$(find /etc/netplan -maxdepth 1 -type f -name "*.yaml" | head -n 1)
            if [ -z "$netplan_file" ]; then
                error_exit "Не найден netplan файл с расширением .yaml. Пожалуйста, настройте сетевые интерфейсы вручную."
            fi
            if ! grep -q "renderer: networkd" "$netplan_file"; then
                error_exit "Netplan файл ($netplan_file) не настроен для использования networkd."
            fi
            IN_IF=$(grep -E "^[[:space:]]+[a-zA-Z0-9_-]+:" "$netplan_file" | head -n 1 | awk '{print $1}' | tr -d ':')
            OUT_IF=$(grep -E "^[[:space:]]+[a-zA-Z0-9_-]+:" "$netplan_file" | sed -n '2p' | awk '{print $1}' | tr -d ':')
            LOCAL_IP=$(grep -A 5 -E "^[[:space:]]+$OUT_IF:" "$netplan_file" | grep "addresses:" | grep -oP '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | head -n 1)
            if [ -z "$IN_IF" ] || [ -z "$OUT_IF" ]; then
                error_exit "Не удалось определить сетевые интерфейсы из netplan файла."
            fi
            if [ -z "$LOCAL_IP" ]; then
                LOCAL_IP="192.168.1.1"
            fi
            log_info "Используются текущие настройки интерфейсов: ВХОДЯЩИЙ: $IN_IF, ВЫХОДЯЩИЙ: $OUT_IF, LOCAL_IP: $LOCAL_IP"
            ;;
        *)
            error_exit "Неверный выбор, пожалуйста выберите 1, 2 или 3."
            ;;
    esac
}

# Получение списка сетевых интерфейсов и выбор пользователем
select_interfaces() {
    echo -e "${GREEN}Получаю список сетевых интерфейсов...${NC}"
    all_interfaces=$(ip -o link show | awk '$2 != "lo:" {print $2}' | sed 's/://')
    full_list=""
    count=0
    for iface in $all_interfaces; do
        count=$((count+1))
        ip_addr=$(ip -o -4 addr show "$iface" 2>/dev/null | awk '{print $4}' | cut -d'/' -f1)
        if [ -z "$ip_addr" ]; then
            ip_addr="(нет IP)"
        fi
        full_list+="$count) $iface : $ip_addr\n"
        interfaces_array[$count]="$iface"
    done
    echo -e "Доступные сетевые интерфейсы:\n$full_list"
    echo ""

    read -r -p "Введите номер ВХОДЯЩЕГО интерфейса (подключен к интернету): " in_num
    IN_IF="${interfaces_array[$in_num]}"
    if [ -z "$IN_IF" ]; then
        error_exit "Некорректный выбор входящего интерфейса"
    fi

    read -r -p "Введите номер ВЫХОДЯЩЕГО интерфейса (локальная сеть): " out_num
    OUT_IF="${interfaces_array[$out_num]}"
    if [ -z "$OUT_IF" ]; then
        error_exit "Некорректный выбор выходящего интерфейса"
    fi

    log_info "Выбран входящий интерфейс: $IN_IF"
    log_info "Выбран выходящий интерфейс: $OUT_IF"

    read -r -p "Использовать стандартный локальный IP-адрес (192.168.69.1)? [y/n]: " use_default
    if [ "$use_default" == "n" ]; then
        read -r -p "Введите новый локальный IP-адрес в формате 192.168.X.1: " LOCAL_IP
        if [[ ! $LOCAL_IP =~ ^192\.168\.[0-9]{1,3}\.1$ ]]; then
            error_exit "Неверный формат локального IP"
        fi
    else
        LOCAL_IP="192.168.69.1"
    fi
    log_info "Локальный IP для локальной сети: $LOCAL_IP"
}

# Настройка netplan
configure_netplan() {
    log_info "Настраиваю сетевые подключения через netplan"
    rm -f /etc/netplan/*.yaml

    echo "Выберите вариант настройки входящего интерфейса:"
    echo "1) Получать IP по DHCP"
    echo "2) Статическая настройка (ввод параметров вручную)"
    read -r -p "Ваш выбор [1/2]: " net_choice

    if [ "$net_choice" == "1" ]; then
        cat <<EOF > /etc/netplan/01-network-manager-all.yaml
###################################################
# За помощью обращаться в телеграмм - @vpn_vendor
# Файл автоматически сгенерирован скриптом vpn.sh
network:
  version: 2
  renderer: networkd
  ethernets:
  # Входящий интерфейс (провайдер-dhcp/другой сервер):
    $IN_IF:
      dhcp4: true
  # Выходящий интерфейс (локальная сеть):
    $OUT_IF:
      dhcp4: false
      addresses: [$LOCAL_IP/24]
      nameservers:
        addresses: [8.8.8.8, 8.8.4.4]
      optional: true
###################################################
EOF
    elif [ "$net_choice" == "2" ]; then
        read -r -p "Введите статический IP для входящего интерфейса: " STATIC_IP
        read -r -p "Введите маску (например, 24): " SUBNET_MASK
        read -r -p "Введите шлюз: " GATEWAY
        read -r -p "Введите DNS1: " DNS1
        read -r -p "Введите DNS2: " DNS2
        cat <<EOF > /etc/netplan/01-network-manager-all.yaml
###################################################
# За помощью обращаться в телеграмм - @vpn_vendor
# Файл автоматически сгенерирован скриптом vpn.sh
network:
  version: 2
  renderer: networkd
  ethernets:
  # Входящий интерфейс (провайдер-статика/другой сервер):
    $IN_IF:
      dhcp4: false
      addresses: [$STATIC_IP/$SUBNET_MASK]
      gateway4: $GATEWAY
      nameservers:
        addresses: [$DNS1, $DNS2]
  # Выходящий интерфейс (локальная сеть):
    $OUT_IF:
      dhcp4: false
      addresses: [$LOCAL_IP/24]
      nameservers:
        addresses: [8.8.8.8, 8.8.4.4]
      optional: true
###################################################
EOF
    else
        error_exit "Неверный выбор варианта настройки сети"
    fi

    chmod 600 /etc/netplan/01-network-manager-all.yaml
    netplan apply || error_exit "Netplan не был применен"
    log_info "Настройки netplan применены"
    log_info "Запуск проверки интернет соединения"
    echo "Ожидаю 20 секунд для стабилизации соединения..."
    sleep 20
    response=$(curl -s -o /dev/null -w "%{http_code}" http://www.google.com)
    if [ "$response" -ne 200 ]; then
        error_exit "Нет доступа в интернет"
    fi
    log_info "Интернет-соединение успешно установлено"
}

# Настройка DNS
configure_dns() {
    log_info "Настраиваю DNS через systemd-resolved"
    RESOLVED_CONF="/etc/systemd/resolved.conf"

    # Поиск [Resolve] и удаление старых DNS= и добавление строк
    if grep -q "^\[Resolve\]" "$RESOLVED_CONF"; then
        # Удаляем строки, начинающиеся с DNS= в блоке [Resolve]
        sed -i '/^\[Resolve\]/,/^\[/ s/^DNS=.*//g' "$RESOLVED_CONF"
        # Добавляем нужную строку сразу после [Resolve]
        sed -i '/^\[Resolve\]/a DNS=8.8.8.8 8.8.4.4' "$RESOLVED_CONF"
    else
        # Если секция отсутствует, добавляем её в конец файла
        echo -e "\n[Resolve]\nDNS=8.8.8.8 8.8.4.4" >> "$RESOLVED_CONF"
    fi

    # Перезапускаем systemd-resolved
    systemctl restart systemd-resolved || error_exit "Не удалось перезапустить systemd-resolved"
    log_info "DNS настроены через systemd-resolved"
}

# Настройка DHCP-сервера (isc-dhcp-server)
configure_dhcp() {
    log_info "Настраиваю DHCP-сервер (isc-dhcp-server)"
    DHCP_CONF="/etc/dhcp/dhcpd.conf"
    DHCP_DEFAULT="/etc/default/isc-dhcp-server"

    [ -f "$DHCP_CONF" ] && cp "$DHCP_CONF" "${DHCP_CONF}.bak"

    cat <<EOF > "$DHCP_CONF"
default-lease-time 600;
max-lease-time 7200;
authoritative;
subnet ${LOCAL_IP%.*}.0 netmask 255.255.255.0 {
    range ${LOCAL_IP%.*}.2 ${LOCAL_IP%.*}.254;
    option routers $LOCAL_IP;
    option subnet-mask 255.255.255.0;
    option domain-name "local.lan";
    option domain-name-servers 8.8.8.8, 8.8.4.4;
}
EOF

    if grep -q "^INTERFACESv4=" "$DHCP_DEFAULT"; then
        sed -i "s/^INTERFACESv4=.*/INTERFACESv4=\"$OUT_IF\"/" "$DHCP_DEFAULT"
    else
        echo "INTERFACESv4=\"$OUT_IF\"" >> "$DHCP_DEFAULT"
    fi

    chown root:dhcpd /var/lib/dhcp/dhcpd.leases || error_exit "chown root:dhcpd /var/lib/dhcp/dhcpd.leases не был применен"
    chmod 664 /var/lib/dhcp/dhcpd.leases || error_exit "chmod 664 /var/lib/dhcp/dhcpd.leases не был применен"
    systemctl restart isc-dhcp-server || error_exit "isc-dhcp-server не был перезапущен"
    systemctl enable isc-dhcp-server || error_exit "isc-dhcp-server не был включён для автозапуска"
    log_info "DHCP-сервер настроен"
}

# Настройка iptables и NAT
configure_iptables() {
    log_info "Настраиваю iptables (MASQUERADE)"
    sed -i '/^#.*net.ipv4.ip_forward/s/^#//' /etc/sysctl.conf
    sysctl -p || error_exit "Ошибка применения sysctl"
    iptables -t nat -A POSTROUTING -o tun0 -s "${LOCAL_IP%.*}.0/24" -j MASQUERADE || error_exit "Не удалось настроить iptables"
    iptables-save > /etc/iptables/rules.v4 || error_exit "Не удалось сохранить правила iptables"
    log_info "iptables настроены"
}

# Настройка VPN (OpenVPN)
configure_vpn() {
    log_info "Настраиваю VPN (OpenVPN)"
    sed -i '/^#\s*AUTOSTART="all"/s/^#\s*//' /etc/default/openvpn
    log_info "VPN настроен"
}

# Настройка веб-интерфейса
configure_web_interface() {
    log_info "Настраиваю веб-интерфейс для управления VPN"
    # Устанавливаем корректные права на директории конфигурации
    chmod -R 755 /etc/openvpn /etc/wireguard
    chown -R www-data:www-data /etc/openvpn /etc/wireguard

    # Для sudo-пользователей (при необходимости)
    echo "www-data ALL=(root) NOPASSWD: /usr/bin/id" | tee -a /etc/sudoers
    echo "www-data ALL=(ALL) NOPASSWD: ALL" | tee -a /etc/sudoers
    echo "www-data ALL=(ALL) NOPASSWD: /bin/systemctl" | tee -a /etc/sudoers

    # Клонируем обновлённый сайт (репозиторий web-cabinet)
    rm -rf /var/www/html
    git clone https://github.com/Rostarc/web-cabinet.git /var/www/html || error_exit "Не удалось клонировать репозиторий веб-сайта"
    chown -R www-data:www-data /var/www/html
    chmod -R 755 /var/www/html
    log_info "Веб-сайт склонирован в /var/www/html"
}

# Функция настройки виртуального хоста Apache и базовой аутентификации
configure_apache() {
    log_info "Настраиваю виртуальный хост Apache и базовую аутентификацию"

    # Формируем новый конфиг виртуального хоста
    cat <<EOF > /etc/apache2/sites-available/000-default.conf
<VirtualHost *:80>
    ServerAdmin webmaster@localhost
    DocumentRoot /var/www/html
    ErrorLog \${APACHE_LOG_DIR}/error.log
    CustomLog \${APACHE_LOG_DIR}/access.log combined

    # Прокси для Shell In A Box
    ProxyPass /shell/ http://127.0.0.1:4200/
    ProxyPassReverse /shell/ http://127.0.0.1:4200/

    <Directory "/var/www/html">
        AuthType Basic
        AuthName "Restricted Content"
        AuthUserFile /etc/apache2/.htpasswd
        Require valid-user
    </Directory>
</VirtualHost>
EOF
    log_info "Конфигурация виртуального хоста Apache записана в /etc/apache2/sites-available/000-default.conf"

    # Настраиваем .htaccess в /var/www/html
    cat <<'EOF' > /var/www/html/.htaccess
<RequireAll>
    Require ip 192.168
</RequireAll>

RewriteEngine On
RewriteBase /

# Исключаем каталог elfinder из перенаправлений
RewriteCond %{REQUEST_URI} ^/elfinder/ [NC]
RewriteRule .* - [L]

# Если запрошен существующий файл или каталог — не перенаправляем
RewriteCond %{REQUEST_FILENAME} -f [OR]
RewriteCond %{REQUEST_FILENAME} -d
RewriteRule ^ - [L]

# Перенаправляем все остальные запросы на index.php с параметром page
RewriteRule ^(.*)$ index.php?page=$1 [QSA,L]
EOF
    log_info ".htaccess создан и настроен в /var/www/html"

    # Изменяем в /etc/apache2/apache2.conf блок для /var/www/ (AllowOverride)
    sed -i '/<Directory \/var\/www\/>/,/<\/Directory>/ s/AllowOverride None/AllowOverride All/' /etc/apache2/apache2.conf || error_exit "Не удалось изменить AllowOverride в apache2.conf"
    log_info "Обновлён /etc/apache2/apache2.conf: AllowOverride для /var/www/ теперь All"

    systemctl restart apache2 || error_exit "Не удалось перезапустить Apache после внесения изменений"
    log_info "Apache перезапущен"
}

# Функция настройки Shell In A Box (для SSH консоли)
configure_shellinabox() {
    log_info "Настраиваю Shell In A Box"
    # Устанавливаем shellinabox (если ещё не установлен)
    apt-get install -y shellinabox || error_exit "Не удалось установить shellinabox"
    systemctl enable shellinabox
    systemctl start shellinabox

    # Переопределяем конфигурацию в /etc/default/shellinabox для рабочего варианта
    cat <<EOF > /etc/default/shellinabox
# Should shellinaboxd start automatically
SHELLINABOX_DAEMON_START=1

# TCP port that shellinaboxd's webserver listens on
SHELLINABOX_PORT=4200

# Параметры: отключаем SSL, отключаем звуковой сигнал
SHELLINABOX_ARGS="--no-beep --disable-ssl"
EOF
    systemctl restart shellinabox || error_exit "Не удалось перезапустить shellinabox"
    log_info "Shell In A Box настроен и перезапущен"
}

# Функция настройки демона пинга и сбора системных показателей
configure_ping_daemon() {
    log_info "Настраиваю демон пинга и сбора системных показателей"

    # Создаём скрипт демона
    cat <<'EOF' > /usr/local/bin/ping_daemon.sh
#!/bin/bash
# Расширенный демон для сбора пинга и системных показателей

# Пути к лог-файлам
PING_LOG="/var/log/ping_history.log"
SYS_STATS_LOG="/var/log/sys_stats.log"
HOST="google.com"
MAX_ENTRIES=86400  # Максимальное количество записей в каждом логе

# Если лог-файлы не существуют, создаём их
[ ! -f "$PING_LOG" ] && touch "$PING_LOG"
[ ! -f "$SYS_STATS_LOG" ] && touch "$SYS_STATS_LOG"

while true; do
  # --- Сбор данных пинга ---
  ping_output=$(ping -c 1 -w 5 "$HOST" 2>&1)
  ping_time=-1
  if [[ "$ping_output" =~ time=([0-9]+\.[0-9]+) ]]; then
    ping_time="${BASH_REMATCH[1]}"
  fi
  ts=$(date +%s)
  echo "$ts $ping_time" >> "$PING_LOG"
  # Если в логе слишком много строк, удаляем первую (FIFO)
  if [ $(wc -l < "$PING_LOG") -gt "$MAX_ENTRIES" ]; then
    sed -i '1d' "$PING_LOG"
  fi

  # --- Сбор системных показателей ---
  # CPU: Получаем значение user CPU (например, "15.3 us")
  cpu_line=$(top -b -n1 | grep "Cpu(s)")
  cpu_usage=0
  if [[ "$cpu_line" =~ ([0-9]+\.[0-9]+)[[:space:]]*us ]]; then
    cpu_usage="${BASH_REMATCH[1]}"
  fi

  # RAM: Используем free -m (вторая строка с "Mem:")
  free_output=$(free -m)
  ram_total=$(echo "$free_output" | awk '/Mem:/ {print $2}')
  ram_used=$(echo "$free_output" | awk '/Mem:/ {print $3}')
  ram_usage=0
  if [ "$ram_total" -gt 0 ]; then
    ram_usage=$(echo "scale=1; $ram_used*100/$ram_total" | bc)
  fi

  # Disk: Используем df -h /, получаем процент использования (обычно в 5-м столбце)
  df_line=$(df -h / | tail -1)
  disk_perc=$(echo "$df_line" | awk '{print $5}' | sed 's/%//')

  # Записываем системные показатели в лог в формате:
  # timestamp cpu_usage ram_usage disk_percentage
  echo "$ts $cpu_usage $ram_usage $disk_perc" >> "$SYS_STATS_LOG"
  if [ $(wc -l < "$SYS_STATS_LOG") -gt "$MAX_ENTRIES" ]; then
    sed -i '1d' "$SYS_STATS_LOG"
  fi

  sleep 2
done
EOF

    chmod +x /usr/local/bin/ping_daemon.sh || error_exit "Не удалось сделать ping_daemon.sh исполняемым"

    # Создаём systemd unit для демона
    cat <<EOF > /etc/systemd/system/ping_daemon.service
[Unit]
Description=Ping Daemon (сбор ping каждые 2 секунды)
After=network.target

[Service]
ExecStart=/usr/local/bin/ping_daemon.sh
Restart=always
RestartSec=2
User=root
Group=root

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload || error_exit "Не удалось перезагрузить демоны systemd"
    systemctl enable ping_daemon.service || error_exit "Не удалось включить ping_daemon.service"
    systemctl start ping_daemon.service || error_exit "Не удалось запустить ping_daemon.service"
    log_info "Демон пинга и системных показателей настроен и запущен"
}

# Функция настройки метрик и мониторинга
configure_metrics_services() {
    log_info "Настраиваю сервисы метрик и мониторинга"

    # --- update_metrics.service ---
    cat <<EOF > /etc/systemd/system/update_metrics.service
[Unit]
Description=Update System Metrics Daemon
After=network.target

[Service]
ExecStart=/usr/bin/python3 /var/www/html/api/update_metrics_daemon.py
Restart=always
RestartSec=10
User=www-data
Group=www-data
StandardOutput=syslog
StandardError=syslog
SyslogIdentifier=update-metrics

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload || error_exit "Ошибка перезагрузки systemd после update_metrics.service"
    systemctl start update_metrics.service || error_exit "Не удалось запустить update_metrics.service"
    systemctl enable update_metrics.service || error_exit "Не удалось включить update_metrics.service"
    log_info "update_metrics.service настроен"

    # --- Установка arp-scan ---
    apt-get install -y arp-scan || error_exit "Не удалось установить arp-scan"

    # --- scan_local_network.py ---
    mkdir -p /var/www/html/api
    cat <<'EOF' > /var/www/html/api/scan_local_network.py
#!/usr/bin/env python3
import subprocess
import json
import re
import os

def scan_network(interface):
    try:
        # Запускаем arp-scan для указанного интерфейса
        result = subprocess.run(['sudo', 'arp-scan', '--interface=' + interface, '--localnet'],
                                capture_output=True, text=True, timeout=30)
        output = result.stdout
    except Exception as e:
        return {"error": str(e)}
    
    devices = []
    # Пример строки: "192.168.1.10    00:11:22:33:44:55    Some Vendor Inc."
    pattern = re.compile(r'(\d+\.\d+\.\d+\.\d+)\s+([0-9a-f:]+)\s+(.*)')
    for line in output.splitlines():
        m = pattern.match(line)
        if m:
            ip = m.group(1)
            mac = m.group(2)
            vendor = m.group(3).strip()
            devices.append({"ip": ip, "mac": mac, "vendor": vendor})
    return {"devices": devices}

if __name__ == '__main__':
    # Используем переменную окружения OUT_IF, если она не задана, по умолчанию "enp0s8"
    interface = os.environ.get("OUT_IF", "enp0s8")
    data = scan_network(interface)
    output_file = "/var/www/html/data/local_network.json"
    with open(output_file, "w") as f:
        json.dump(data, f)
EOF
    chmod +x /var/www/html/api/scan_local_network.py || error_exit "Не удалось сделать scan_local_network.py исполняемым"

    # --- Добавляем cron задачи для update_network_metrics и scan_local_network ---
    # Добавляем задачу для update_network_metrics.py (если требуется)
    (crontab -u www-data -l 2>/dev/null; echo "* * * * * /usr/bin/python3 /var/www/html/api/update_network_metrics.py") | crontab -u www-data -
    # Добавляем задачу для scan_local_network.py с передачей переменной OUT_IF
    (crontab -u www-data -l 2>/dev/null; echo "0 */6 * * * OUT_IF=${OUT_IF} /usr/bin/python3 /var/www/html/api/scan_local_network.py") | crontab -u www-data -

    # --- network_load.service ---
    cat <<EOF > /etc/systemd/system/network_load.service
[Unit]
Description=Network Load Monitor using psutil
After=network.target

[Service]
ExecStart=/usr/bin/python3 /var/www/html/api/update_network_load.py
WorkingDirectory=/var/www/html/api
User=www-data
Group=www-data
Restart=always
RestartSec=10
StandardOutput=syslog
StandardError=syslog
SyslogIdentifier=network-load

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload || error_exit "Ошибка перезагрузки systemd после network_load.service"
    systemctl start network_load.service || error_exit "Не удалось запустить network_load.service"
    systemctl enable network_load.service || error_exit "Не удалось включить network_load.service"
    log_info "network_load.service настроен"

    # --- Установка необходимых пакетов для метрик ---
    apt-get install -y python3-psutil python3-pip vnstat || error_exit "Не удалось установить пакеты для метрик"
    pip3 install psutil || error_exit "Не удалось установить psutil через pip3"
    log_info "Пакеты для метрик и мониторинга установлены"
}

# Функция для настройки и запуска Telegram Bot Service.
telegram_bot() {
    echo "Настройка Telegram Bot Service..."

    # Создание файла службы /etc/systemd/system/telegram_bot.service
    sudo tee /etc/systemd/system/telegram_bot.service > /dev/null << 'EOF'
[Unit]
Description=Telegram Bot Service
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/var/www/html/bot_source
ExecStart=/var/www/html/bot_source/venv/bin/python /var/www/html/bot_source/bot.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

    # Создание лог-файла и установка прав
    sudo touch /var/log/telegram_bot.log
    sudo chown www-data:www-data /var/log/telegram_bot.log
    sudo chmod 664 /var/log/telegram_bot.log

    # Обновление конфигурации systemd и активация службы
    sudo systemctl daemon-reload
    sudo systemctl enable telegram_bot.service
    sudo systemctl stop telegram_bot.service

    # Создание виртуального окружения для Telegram Bot
    sudo python3 -m venv /var/www/html/bot_source/venv
    sudo chown -R "$USER":"$USER" /var/www/html/bot_source/venv
    source /var/www/html/bot_source/venv/bin/activate

    # Обновление pip и установка необходимых библиотек
    pip install --upgrade pip
    pip install python-telegram-bot psutil requests "python-telegram-bot[job-queue]"

    # Добавление прав для пользователя www-data для управления службой
    echo "www-data ALL=NOPASSWD: /bin/systemctl is-active telegram_bot.service, /bin/systemctl start telegram_bot.service, /bin/systemctl stop telegram_bot.service, /bin/systemctl enable telegram_bot.service, /bin/systemctl disable telegram_bot.service" | sudo tee /etc/sudoers.d/telegram_bot

    # Установка исполняемых прав для bot.py
    sudo chmod +x /var/www/html/bot_source/bot.py

    # Настройка прав для файла конфигурации telegram_bot_config.json
    sudo chown www-data:www-data /var/www/html/data/telegram_bot_config.json
    sudo chmod 664 /var/www/html/data/telegram_bot_config.json

    echo "Telegram Bot Service успешно настроен и запущен."
}

# Функция настройки Home Metrics Daemon
configure_home_metrics_daemon() {
    log_info "Настраиваю Home Metrics Daemon"

    # Создаем/перезаписываем unit-файл для home_metrics_daemon.service
    cat <<'EOF' > /etc/systemd/system/home_metrics_daemon.service
[Unit]
Description=Home Metrics Daemon (Collect CPU/RAM/Disk history)
After=network.target

[Service]
# Запуск вашего скрипта
ExecStart=/usr/bin/python3 /var/www/html/api/home_metrics_daemon.py

# Перезапускать при сбоях
Restart=always
RestartSec=2

# Кто будет исполнять (можно root или www-data, в зависимости от ваших нужд)
User=www-data
Group=www-data

# Логи будут попадать в syslog (journalctl -u home_metrics_daemon)
StandardOutput=syslog
StandardError=syslog
SyslogIdentifier=home-metrics-daemon

[Install]
WantedBy=multi-user.target
EOF

    log_info "Файл home_metrics_daemon.service создан"

    # Перезагружаем демон systemd и запускаем сервис
    systemctl daemon-reload || error_exit "Не удалось перезагрузить systemd после создания home_metrics_daemon.service"
    log_info "systemd daemon перезагружен"

    systemctl start home_metrics_daemon.service || error_exit "Не удалось запустить home_metrics_daemon.service"
    systemctl enable home_metrics_daemon.service || error_exit "Не удалось включить home_metrics_daemon.service"
    log_info "home_metrics_daemon.service запущен и включен"

    # Рекомендуется перезапустить сервис, если это необходимо
    systemctl restart home_metrics_daemon.service || error_exit "Не удалось перезапустить home_metrics_daemon.service"
    log_info "home_metrics_daemon.service перезапущен"

    # Если файла нет – создаем пустой
    if [ ! -f /var/www/html/data/home_metrics_daemon.json ]; then
        touch /var/www/html/data/home_metrics_daemon.json || error_exit "Не удалось создать файл /var/www/html/data/home_metrics_daemon.json"
    fi

    chmod 644 /var/www/html/data/home_metrics_daemon.json || error_exit "Не удалось установить права 644 на /var/www/html/data/home_metrics_daemon.json"
    chown www-data:www-data /var/www/html/data/home_metrics_daemon.json || error_exit "Не удалось изменить владельца файла /var/www/html/data/home_metrics_daemon.json"
    log_info "Права для /var/www/html/data/home_metrics_daemon.json установлены"
}

# Функция финальных доработок (права на папки, создание файла заметок)
finalize_setup() {
    log_info "Выполняю финальные доработки"
    chmod -R 777 /var/www/html || log_error "Не удалось изменить права на /var/www/html"
    mkdir -p /home/files/.trash/.tmb/
    mkdir -p /home/files/.trash/
    mkdir -p /home/files
    chmod +x /var/www/html/scripts/update.sh
    chmod +x /usr/local/bin/ping_daemon.sh
    chmod +x /var/www/html/api/scan_local_network.py
    chmod +x /var/www/html/api/update_network_load.py
    chown -R www-data:www-data /home/files
    chown -R www-data:www-data /home/files/.trash/
    chown -R www-data:www-data /home/files/.trash/.tmb/
    chown -R www-data:www-data /var/www/html/data
    chown www-data:www-data /var/log/vpn-web.log
    chmod -R 755 /home/files
    chmod -R 755 /home/files/.trash/
    chmod -R 755 /home/files/.trash/.tmb/
    chmod -R 755 /var/www/html/data
    chmod 660 /var/log/vpn-web.log
    usermod -a -G adm www-data
    systemctl restart apache2
    log_info "Финальные настройки прав и директорий выполнены"
}

# Удаление и откат изменений
remove_configuration() {

    log_info "Запуск удаления зависимостей и программ"
    # Определяем список сервисов для остановки и отключения
    services=(
        "openvpn@client1.service"
        "wg-quick@tun0.service"
        "isc-dhcp-server"
        "apache2"
        "shellinabox"
        "ping_daemon.service"
        "dnsmasq"
    )
    for service in "${services[@]}"; do
        systemctl stop "$service" 2>/dev/null
        systemctl disable "$service" 2>/dev/null
    done
    log_info "Остановка служб прошла"

    # Если установлен dnsmasq, дополнительно удаляем его
    if dpkg -l | grep -qw dnsmasq; then
        log_info "Начато удаление dnsmasq"
        apt-get purge -y dnsmasq || log_error "Не удалось удалить dnsmasq"
        log_info "dnsmasq удалён"
    fi

    # Удаляем конфигурационные файлы и директории, связанные с настройкой
    rm -rf /etc/openvpn /etc/wireguard /var/www/html
    rm -f /etc/dhcp/dhcpd.conf /etc/default/isc-dhcp-server /var/lib/dhcp/dhcpd.leases
    rm -f /etc/systemd/system/vpn-update.service /etc/systemd/system/vpn-update.timer || log_error "Не удалось удалить остатки конфигураций служб"
    log_info "Удалены остатки конфигураций служб"

    # Удаляем установленные пакеты
    apt-get purge -y \
        htop net-tools mtr network-manager wireguard openvpn apache2 php git iptables-persistent \
        openssh-server resolvconf speedtest-cli nload libapache2-mod-php isc-dhcp-server \
        libapache2-mod-authnz-pam shellinabox dos2unix || log_error "Не удалось удалить пакеты OpenVPN, WireGuard, isc-dhcp-server или shellinabox"
    apt-get autoremove -y
    log_info "Приложения и программы удалены"

    # Удаляем правило NAT, если оно было добавлено
    iptables -t nat -D POSTROUTING -o tun0 -s "${LOCAL_IP%.*}.0/24" -j MASQUERADE 2>/dev/null
    iptables-save > /etc/iptables/rules.v4
    log_info "Удалены правила iptables"

    # Перезагружаем systemd, чтобы изменения в unit-файлах вступили в силу
    systemctl daemon-reload

    # Удаление настроек Телеграм бота
    echo "Начало удаления конфигурации Telegram Bot Service..."

    # Остановка и отключение сервиса, если он запущен или включён
    if systemctl is-active --quiet telegram_bot.service; then
        echo "Останавливаем сервис telegram_bot..."
        sudo systemctl stop telegram_bot.service
    else
        echo "Сервис telegram_bot уже не запущен."
    fi

    if systemctl is-enabled --quiet telegram_bot.service; then
        echo "Отключаем сервис telegram_bot..."
        sudo systemctl disable telegram_bot.service
    else
        echo "Сервис telegram_bot уже отключён."
    fi
    log_info "Сервис telegram_bot отключен"

    # Удаление файла службы systemd
    if [ -f /etc/systemd/system/telegram_bot.service ]; then
        echo "Удаляем файл службы /etc/systemd/system/telegram_bot.service..."
        sudo rm -f /etc/systemd/system/telegram_bot.service
    else
        echo "Файл службы /etc/systemd/system/telegram_bot.service не найден."
    fi

    # Обновляем конфигурацию systemd
    sudo systemctl daemon-reload

    # 4. Удаление лог-файла
    if [ -f /var/log/telegram_bot.log ]; then
        echo "Удаляем лог-файл /var/log/telegram_bot.log..."
        sudo rm -f /var/log/telegram_bot.log
    else
        echo "Лог-файл /var/log/telegram_bot.log не найден."
    fi
    log_info "Лог-файл telegram_bot удален"

    # Удаление виртуального окружения
    if [ -d /var/www/html/bot_source/venv ]; then
        echo "Удаляем виртуальное окружение /var/www/html/bot_source/venv..."
        sudo rm -rf /var/www/html/bot_source/venv
    else
        echo "Виртуальное окружение /var/www/html/bot_source/venv не найдено."
    fi
    log_info "Виртуальное окружение отключено"

    # Удаление файла sudoers для управления службой telegram_bot
    if [ -f /etc/sudoers.d/telegram_bot ]; then
        echo "Удаляем файл sudoers /etc/sudoers.d/telegram_bot..."
        sudo rm -f /etc/sudoers.d/telegram_bot
    else
        echo "Файл sudoers /etc/sudoers.d/telegram_bot не найден."
    fi
    
    log_info "Все настройки удалены"
}

# Функция финальной проверки с анимацией
check_execution() {
    echo -e "\n${YELLOW}[Проверка выполнения] Начинается проверка...${NC}"
    for i in $(seq 1 100); do
        printf "\r[Проверка выполнения] %d%%" "$i"
        sleep 0.03
    done
    echo -e "\n"
    # Проверка работы isc-dhcp-server
    if systemctl is-active --quiet isc-dhcp-server; then
        log_info "ISC-DHCP-SERVER запущен"
    else
        error_exit "ISC-DHCP-SERVER не запущен"
    fi
    # Проверка работы Apache2
    if systemctl is-active --quiet apache2; then
        log_info "Apache2 запущен"
    else
        error_exit "Apache2 не запущен"
    fi
    # Проверка работы shellinabox
    if systemctl is-active --quiet shellinabox; then
        log_info "Shell In A Box запущен"
    else
        error_exit "Shell In A Box не запущен"
    fi
    # Проверка наличия выбранных интерфейсов
    if ip link show "$IN_IF" >/dev/null 2>&1; then
        log_info "Интерфейс $IN_IF обнаружен"
    else
        error_exit "Интерфейс $IN_IF не обнаружен"
    fi
    if ip link show "$OUT_IF" >/dev/null 2>&1; then
        log_info "Интерфейс $OUT_IF обнаружен"
    else
        error_exit "Интерфейс $OUT_IF не обнаружен"
    fi
    log_info "Проверка выполнения завершена"
}

# --- Основная часть скрипта ---
check_root

echo ""
echo -e "${BLUE}        .^~!!!~.                                                             .J:                    ${NC}"
echo -e "${BLUE}       ?5777~!?P7 ..    .    ::    . ::           .    .   ::.   . .:.    .:.:@~   :::    . :.      ${NC}"
echo -e "${BLUE}      Y5.JY7YG ~&.:B!  7G 7BJ?JG~ ~#J?JG~        :B7  7B.~5?7YY. PP??PY  7G??5@~ ~PJ?JP~ ~#YJ7      ${NC}"
echo -e "${BLUE}     ^&.?#  P5 7B. ?#.:&~ J#   YB !&:  G5         7&::#! &5!7?#^ BY  ~@:.@!  :&~ &?   Y# ~@^        ${NC}"
echo -e "${BLUE}     ^&:~P??Y5?5^   5GGJ  ?&~.:G5 !&.  PP          YGGY  GP^:^^  #J  ^@: #Y.:?@~ GP:.^GY !@.        ${NC}"
echo -e "${BLUE}      JP7~~^^~.     .J?   J#7?J7  ^J.  7!          .JJ   .7???!  ?~  :J. :?J?!?: .7J??!  :J.        ${NC}"
echo -e "${BLUE}       :~!77!~            7P             :??????J^                                                  ${NC}"
echo ""
echo -e "${YELLOW}==============================================${NC}"
echo -e "${YELLOW}  Установка VPN-сервера с веб-интерфейсом (v2.5.0)${NC}"
echo -e "${YELLOW}==============================================${NC}"
echo ""
echo "Выберите действие:"
echo "1) Установить и настроить сервер"
echo "2) Удалить все настройки сервера"
echo ""
read -r -p "Ваш выбор [1/2]: " action_choice

if [ "$action_choice" == "2" ]; then
    remove_configuration
    echo -e "${YELLOW}[Завершение скрипта]${NC}"
    exit 0
elif [ "$action_choice" != "1" ]; then
    error_exit "Неверный выбор. Выберите 1 или 2"
fi

# Выполнение установки и настройки
configure_network_services
install_packages
preselect_interfaces
configure_dns
configure_dhcp
configure_iptables
configure_vpn
configure_web_interface
configure_apache
configure_shellinabox
configure_ping_daemon
configure_metrics_services
telegram_bot
configure_home_metrics_daemon
finalize_setup

# Финальная проверка с анимацией
check_execution

echo -e "\n${GREEN}[OK]${NC} Установка завершена успешно!"
echo ""
echo "После перезагрузки сервера все настройки будут применены."
echo "Веб-интерфейс настроен. Доступен по http://$LOCAL_IP/"
echo "Логин и пароль от веб-сайта такой же как и от сервера"
echo "Удачи!"

exit 0
