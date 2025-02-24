#!/bin/bash
# =============================================================================
# Поддержка Ubuntu 20.04 и 22.04 (чистая установка)
# Версия: 2.1
# =============================================================================

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

# Установщик пакетов
install_packages() {
    log_info "Обновление репозиториев"
    apt-get update || error_exit "Обновление репозиториев не выполнено"
    
    apt-get upgrade -y -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold" || error_exit "Обновление системы не выполнено"
    log_info "Обновление системы прошло"
    
    apt-get install -y -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold" \
        htop net-tools mtr network-manager wireguard openvpn apache2 php git iptables-persistent \
        openssh-server resolvconf speedtest-cli nload libapache2-mod-php wget ufw isc-dhcp-server \
        libapache2-mod-authnz-pam shellinabox dos2unix || error_exit "Установка необходимых пакетов не выполнена"
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

    read -p "Введите номер ВХОДЯЩЕГО интерфейса (подключен к интернету): " in_num
    IN_IF="${interfaces_array[$in_num]}"
    if [ -z "$IN_IF" ]; then
        error_exit "Некорректный выбор входящего интерфейса"
    fi

    read -p "Введите номер ВЫХОДЯЩЕГО интерфейса (локальная сеть): " out_num
    OUT_IF="${interfaces_array[$out_num]}"
    if [ -z "$OUT_IF" ]; then
        error_exit "Некорректный выбор выходящего интерфейса"
    fi

    log_info "Выбран входящий интерфейс: $IN_IF"
    log_info "Выбран выходящий интерфейс: $OUT_IF"

    read -p "Использовать стандартный локальный IP-адрес (192.168.1.1)? [y/n]: " use_default
    if [ "$use_default" == "n" ]; then
        read -p "Введите новый локальный IP-адрес в формате 192.168.X.1: " LOCAL_IP
        if [[ ! $LOCAL_IP =~ ^192\.168\.[0-9]{1,3}\.1$ ]]; then
            error_exit "Неверный формат локального IP"
        fi
    else
        LOCAL_IP="192.168.1.1"
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
    read -p "Ваш выбор [1/2]: " net_choice

    if [ "$net_choice" == "1" ]; then
        cat <<EOF > /etc/netplan/01-network-manager-all.yaml
network:
  version: 2
  renderer: networkd
  ethernets:
    $IN_IF:
      dhcp4: true
    $OUT_IF:
      dhcp4: false
      addresses: [$LOCAL_IP/24]
      nameservers:
        addresses: [8.8.8.8, 8.8.4.4]
      optional: true
EOF
    elif [ "$net_choice" == "2" ]; then
        read -p "Введите статический IP для входящего интерфейса: " STATIC_IP
        read -p "Введите маску (например, 24): " SUBNET_MASK
        read -p "Введите шлюз: " GATEWAY
        read -p "Введите DNS1: " DNS1
        read -p "Введите DNS2: " DNS2
        cat <<EOF > /etc/netplan/01-network-manager-all.yaml
network:
  version: 2
  renderer: networkd
  ethernets:
    $IN_IF:
      dhcp4: false
      addresses: [$STATIC_IP/$SUBNET_MASK]
      gateway4: $GATEWAY
      nameservers:
        addresses: [$DNS1, $DNS2]
    $OUT_IF:
      dhcp4: false
      addresses: [$LOCAL_IP/24]
      nameservers:
        addresses: [8.8.8.8, 8.8.4.4]
      optional: true
EOF
    else
        error_exit "Неверный выбор варианта настройки сети"
    fi

    netplan apply || error_exit "Netplan не был применен"
    log_info "Настройки netplan применены"
    log_info "Проверка доступа в интернет"
    sleep 20
    response=$(curl -s -o /dev/null -w "%{http_code}" http://www.google.com)
    if [ "$response" -ne 200 ]; then
        error_exit "Нет доступа в интернет"
    fi
    log_info "Интернет-соединение успешно установлено"
}

# Настройка DNS
configure_dns() {
    log_info "Настраиваю DNS"
    RESOLV_BASE="/etc/resolvconf/resolv.conf.d/base"
    RESOLV="/etc/resolv.conf"
    for dns in "nameserver 8.8.8.8" "nameserver 8.8.4.4"; do
        grep -qxF "$dns" "$RESOLV_BASE" || echo "$dns" >> "$RESOLV_BASE"
        grep -qxF "$dns" "$RESOLV" || echo "$dns" >> "$RESOLV"
    done
    resolvconf -u || error_exit "Ошибка обновления resolvconf"
    systemctl restart systemd-resolved || error_exit "Не удалось перезапустить systemd-resolved"
    log_info "DNS настроены"
}

# Настройка SSH (разрешение root-доступа)
configure_ssh() {
    log_info "Настраиваю SSH (разрешаю root-доступ)"
    sed -i 's/#\?PermitRootLogin .*/PermitRootLogin yes/' /etc/ssh/sshd_config
    systemctl restart ssh || systemctl restart sshd || error_exit "Не удалось перезапустить SSH"
    ufw allow OpenSSH || error_exit "Не удалось разрешить OpenSSH через ufw"
    log_info "SSH настроен"
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

    systemctl restart isc-dhcp-server || error_exit "isc-dhcp-server не был перезапущен"
    systemctl enable isc-dhcp-server || error_exit "isc-dhcp-server не был включён для автозапуска"
    log_info "DHCP-сервер настроен"
}

# Настройка iptables и NAT
configure_iptables() {
    log_info "Настраиваю iptables (MASQUERADE)"
    sed -i '/^#.*net.ipv4.ip_forward/s/^#//' /etc/sysctl.conf
    sysctl -p || error_exit "Ошибка применения sysctl"
    iptables -t nat -A POSTROUTING -o tun0 -s ${LOCAL_IP%.*}.0/24 -j MASQUERADE || error_exit "Не удалось настроить iptables"
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

#############################################
# Новые функции для дополнительных настроек #
#############################################

# Функция настройки виртуального хоста Apache и базовой аутентификации
configure_apache() {
    log_info "Настраиваю виртуальный хост Apache и базовую аутентификацию"

    # Запрашиваем у пользователя логин и пароль для доступа к сайту
    read -p "Введите логин для доступа к сайту: " BASIC_AUTH_USER
    read -s -p "Введите пароль для доступа к сайту: " BASIC_AUTH_PASS
    echo ""
    htpasswd -cb /etc/apache2/.htpasswd "$BASIC_AUTH_USER" "$BASIC_AUTH_PASS" || error_exit "Не удалось создать файл .htpasswd"
    log_info "Файл .htpasswd создан"

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
AuthType Basic
AuthName "Restricted Area"
AuthUserFile /etc/apache2/.htpasswd
Require valid-user

<RequireAll>
    Require ip 192.168
</RequireAll>

RewriteEngine On
# Не трогаем URL начинающиеся с /shell/
RewriteCond %{REQUEST_URI} !^/shell/
RewriteCond %{REQUEST_FILENAME} !-f
RewriteCond %{REQUEST_FILENAME} !-d
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
MAX_ENTRIES=2000  # Максимальное количество записей в каждом логе

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

  sleep 10
done
EOF

    chmod +x /usr/local/bin/ping_daemon.sh || error_exit "Не удалось сделать ping_daemon.sh исполняемым"

    # Создаём systemd unit для демона
    cat <<EOF > /etc/systemd/system/ping_daemon.service
[Unit]
Description=Ping Daemon
After=network.target

[Service]
ExecStart=/usr/local/bin/ping_daemon.sh
Restart=always

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload || error_exit "Не удалось перезагрузить демоны systemd"
    systemctl enable ping_daemon.service || error_exit "Не удалось включить ping_daemon.service"
    systemctl start ping_daemon.service || error_exit "Не удалось запустить ping_daemon.service"
    log_info "Демон пинга и системных показателей настроен и запущен"
}

# Функция финальных доработок (права на папки, создание файла заметок)
finalize_setup() {
    log_info "Выполняю финальные доработки"
    chmod -R 777 /var/www/html || log_error "Не удалось изменить права на /var/www/html"
    touch /var/www/html/interface_notes.txt || log_error "Не удалось создать /var/www/html/interface_notes.txt"
    chmod 777 /var/www/html/interface_notes.txt || log_error "Не удалось установить права для /var/www/html/interface_notes.txt"
    sudo chmod +x /var/www/html/scripts/update.sh
    sudo chmod +x /usr/local/bin/ping_daemon.sh
    log_info "Веб-интерфейс настроен. Доступен по http://$LOCAL_IP/"
}

# Функция удаления настроек (откат) – можно расширить для удаления новых компонентов
remove_configuration() {
    log_info "Удаляю ранее настроенные компоненты"
    systemctl stop openvpn@client1.service wg-quick@tun0.service isc-dhcp-server apache2 shellinabox ping_daemon.service 2>/dev/null
    systemctl disable openvpn@client1.service wg-quick@tun0.service ping_daemon.service
    if dpkg -l | grep -qw dnsmasq; then
        log_info "Удаление dnsmasq"
        systemctl stop dnsmasq 2>/dev/null
        systemctl disable dnsmasq 2>/dev/null
        apt-get purge -y dnsmasq || log_error "Не удалось удалить dnsmasq"
        log_info "dnsmasq удалён"
    fi
    rm -rf /etc/openvpn /etc/wireguard /var/www/html /etc/dhcp/dhcpd.conf
    rm -f /etc/netplan/01-network-manager-all.yaml
    rm -f /etc/systemd/system/vpn-update.service /etc/systemd/system/vpn-update.timer
    apt-get purge -y openvpn wireguard isc-dhcp-server shellinabox || log_error "Не удалось удалить пакеты OpenVPN, WireGuard, isc-dhcp-server или shellinabox"
    apt-get autoremove -y
    iptables -t nat -D POSTROUTING -o tun0 -s ${LOCAL_IP%.*}.0/24 -j MASQUERADE 2>/dev/null
    iptables-save > /etc/iptables/rules.v4
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
echo -e "${YELLOW}  Установка VPN-сервера с веб-интерфейсом (v1.5)${NC}"
echo -e "${YELLOW}==============================================${NC}"
echo ""
echo "Выберите действие:"
echo "1) Установить и настроить сервер"
echo "2) Удалить все настройки сервера"
echo ""
read -p "Ваш выбор [1/2]: " action_choice

if [ "$action_choice" == "2" ]; then
    remove_configuration
    echo -e "${YELLOW}[Завершение скрипта]${NC}"
    exit 0
elif [ "$action_choice" != "1" ]; then
    error_exit "Неверный выбор. Выберите 1 или 2"
fi

# Выполнение установки и настройки
install_packages
select_interfaces
configure_netplan
configure_dns
configure_ssh
configure_dhcp
configure_iptables
configure_vpn
configure_web_interface
configure_apache
configure_shellinabox
configure_ping_daemon
finalize_setup

# Финальная проверка с анимацией
check_execution

echo -e "\n${GREEN}[OK]${NC} Установка завершена успешно!"
echo ""
echo "После перезагрузки сервера все настройки будут применены."
echo "Веб-интерфейс настроен. Доступен по http://$LOCAL_IP/"
echo "Удачи!"

exit 0
