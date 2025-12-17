#!/bin/bash
# ==============================================================================
#
#   Скрипт автоматической настройки VPN-сервера
#   Поддерживаемая ОС: ТОЛЬКО Ubuntu 22.04 LTS (чистая установка с флешки) !!!
#
# ==============================================================================
#
#   Версия: 2.5.4
#
#   [~] Полностью переписана логика проверки правил iptables (configure_mtu_daemon).
#         - Устранена проблема "iptables -C -A", вызывавшая дублирование.
#         - Добавлен механизм самоисцеления.
#
# ==============================================================================

# Неинтерактивный режим для apt
export DEBIAN_FRONTEND=noninteractive

# Цветовые коды ANSI
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Глобальные переменные
STEP_LOG=()
SCRIPT_ERROR=0
net_choice=""

# Логирование успеха
log_info() {
    echo -e "${GREEN}[OK]${NC} $1 - УСПЕШНО"
    STEP_LOG+=("${GREEN}[OK]${NC} $1 - УСПЕШНО")
}

# Логирование ошибки
log_error() {
    echo -e "${RED}[ERROR]${NC} $1 - ОШИБКА" >&2
    STEP_LOG+=("${RED}[ERROR]${NC} $1 - ОШИБКА")
}

# Аварийный выход
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

# Проверка системных требований (root права и версия ОС)
check_system_requirements() {
    # 1. Проверка прав root
    if [ "$EUID" -ne 0 ]; then
        error_exit "Скрипт должен быть запущен с правами root (через sudo или от root)"
    fi

    # 2. Проверка версии операционной системы
    if [ -f /etc/os-release ]; then
        # Загружаем переменные из файла (ID, VERSION_ID и т.д.) в текущую сессию
        . /etc/os-release
        
        # Проверяем, что ID дистрибутива - "ubuntu" (без учета регистра) и версия - "22.04"
        if [[ "${ID,,}" == "ubuntu" ]] && [[ "$VERSION_ID" == "22.04" ]]; then
            log_info "Система опознана: Ubuntu 22.04. Проверка требований пройдена."
        else
            error_exit "[ОШИБКА!] - Неподдерживаемая ОС. Скрипт предназначен ТОЛЬКО для Ubuntu 22.04. Обнаружено: $PRETTY_NAME"
        fi
    else
        error_exit "Не удалось определить версию ОС. Файл /etc/os-release не найден. Возможно установлена другая ОС, а не Ubuntu 22.04"
    fi
}

# Переключение на systemd-networkd
configure_network_services() {
    log_info "Переключаю сетевое управление на systemd-networkd"
    # Отключение NetworkManager
    systemctl stop NetworkManager.service 2>/dev/null || log_info "NetworkManager не установлен"
    systemctl disable NetworkManager.service 2>/dev/null || log_info "NetworkManager не установлен/отключение службы"

    # Включение systemd-networkd
    systemctl enable systemd-networkd.service || error_exit "Не удалось включить systemd-networkd"
    systemctl start systemd-networkd.service || error_exit "Не удалось запустить systemd-networkd"

    # Очистка старых конфигураций netplan
    rm -f /etc/netplan/*.yml

    log_info "Сетевые службы переключены на systemd-networkd"
}

# Установщик пакетов
install_packages() {
    log_info "Инициализация запуска обновлений + установки программ"
    # Обновление списка пакетов
    apt-get update || error_exit "Обновление репозиториев не выполнено"
    
    # Обновление системы
    log_info "Запускаю полное обновление системы в автоматическом режиме..."
    apt-get -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold" upgrade -y || error_exit "Обновление системы не выполнено"
    log_info "Обновление системы прошло"
    
    # Установка пакетов
    log_info "Устанавливаю необходимые пакеты в автоматическом режиме..."
    apt-get -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold" install -y ppp net-tools mtr wireguard openvpn apache2 php git iptables-persistent openssh-server resolvconf speedtest-cli nload libapache2-mod-php isc-dhcp-server iperf3 libapache2-mod-authnz-pam shellinabox dos2unix python3-venv python3.10-venv || error_exit "Установка необходимых пакетов не выполнена"
    log_info "Необходимые пакеты установлены"

    # Включение модулей Apache
    a2enmod proxy || error_exit "Не удалось включить модуль proxy"
    a2enmod proxy_http || error_exit "Не удалось включить модуль proxy_http"
    a2enmod rewrite || error_exit "Не удалось включить модуль rewrite"
    a2enmod authnz_pam || error_exit "Не удалось включить модуль authnz_pam"
    systemctl restart apache2 || error_exit "Не удалось перезапустить Apache после включения модулей"

    # Удаление dnsmasq (если установлен)
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

    # Удаление openvswitch-switch (если установлен)
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

# Меню выбора режима настройки Netplan
preselect_interfaces() {
    echo "Какое действие выполнить с NETPLAN?"
    echo "1. Полная настройка."
    echo "2. Настроить только NETPLAN и пропустить основную настройку."
    echo "3. Пропустить настройку NETPLAN и выполнить ТОЛЬКО основную настройку."
    read -r -p "Ваш выбор [1/2/3]: " netplan_choice

    case "$netplan_choice" in
        1)
            # 1) Полная настройка
            select_interfaces
            configure_netplan
            ;;
        2)
            # 2) Только настройка Netplan
            configure_network_services
            select_interfaces
            configure_netplan
            echo -e "\n${GREEN}[OK]${NC} Настройка netplan выполнена. Дальнейшая настройка пропущена."
            exit 0
            ;;
        3)
            # 3) Пропуск настройки (использование существующей)
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
                LOCAL_IP="192.168.69.1"
            fi
            log_info "Используются текущие настройки интерфейсов: ВХОДЯЩИЙ: $IN_IF, ВЫХОДЯЩИЙ: $OUT_IF, LOCAL_IP: $LOCAL_IP"
            ;;
        *)
            error_exit "Неверный выбор, пожалуйста выберите 1, 2 или 3."
            ;;
    esac
}

# Выбор сетевых интерфейсов
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
    # Отключение cloud-init
    log_info "Проверка статуса управления сетью cloud-init..."
    local cloud_config_file="/etc/cloud/cloud.cfg.d/99-disable-network-config.cfg"
    if [ ! -f "$cloud_config_file" ]; then
        echo "network: {config: disabled}" > "$cloud_config_file"
        log_info "Управление сетью в cloud-init было отключено."
    else
        log_info "Управление сетью в cloud-init уже отключено."
    fi

    # Резервное копирование и очистка старых конфигов netplan
    log_info "Поиск сторонних конфигурационных файлов Netplan..."
    local netplan_dir="/etc/netplan"
    local main_config_file="99-vpn-script.yaml"
    local has_other_configs=false
    
    for file in "$netplan_dir"/*.yaml; do
        [ -f "$file" ] || continue
        if [ "$(basename "$file")" != "$main_config_file" ]; then
            has_other_configs=true
            break
        fi
    done

    if [ "$has_other_configs" = true ]; then
        local backup_dir="$netplan_dir/backup_$(date +%F_%H%M%S)"
        echo -e "${YELLOW}[WARNING]${NC} Обнаружены сторонние файлы конфигурации. Создаю резервную копию."
        mkdir -p "$backup_dir"
        
        for file in "$netplan_dir"/*.yaml; do
            [ -f "$file" ] || continue
            if [ "$(basename "$file")" != "$main_config_file" ]; then
                log_info "Архивирую файл: $(basename "$file")"
                mv "$file" "$backup_dir/"
            fi
        done
        rm -f "$netplan_dir/$main_config_file"
    else
        log_info "Сторонние файлы конфигурации не найдены. Очищаю предыдущие настройки."
        rm -f "$netplan_dir"/*.yaml
    fi
    
    # Сбор данных
    echo "Выберите вариант настройки входящего интерфейса:"
    echo "1) Получать IP по DHCP от провайдера/сервера"
    echo "2) Статическая настройка (ввод параметров вручную)"
    echo "3) PPPoE-соединение от провайдера (логин/пароль)"
    read -r -p "Ваш выбор [1/2/3]: " net_choice

    local netplan_config_path="/etc/netplan/99-vpn-script.yaml"

    if [ "$net_choice" == "1" ]; then
cat <<EOF > "$netplan_config_path"
###################################################
# Файл автоматически сгенерирован скриптом vpn.sh
network:
  version: 2
  renderer: networkd
  ethernets:
    # Входящий интерфейс (белый интернет):
    $IN_IF:
      dhcp4: true
    # Выходящий интерфейс (локальная сеть):
    $OUT_IF:
      dhcp4: false
      addresses: [$LOCAL_IP/24]
      optional: true
EOF
    elif [ "$net_choice" == "2" ]; then
        read -r -p "Введите статический IP для входящего интерфейса: " STATIC_IP
        read -r -p "Введите префикс (если провайдер например выдал 255.255.255.224, введите 27): " SUBNET_MASK
        read -r -p "Введите шлюз: " GATEWAY
        read -r -p "Введите DNS1: " DNS1
        read -r -p "Введите DNS2: " DNS2
cat <<EOF > "$netplan_config_path"
###################################################
# Файл автоматически сгенерирован скриптом vpn.sh
network:
  version: 2
  renderer: networkd
  ethernets:
    # Входящий интерфейс (белый интернет):
    $IN_IF:
      dhcp4: false
      addresses: [$STATIC_IP/$SUBNET_MASK]
      routes:
        - to: default
          via: $GATEWAY
      nameservers:
        addresses: [$DNS1, $DNS2]
    # Выходящий интерфейс (локальная сеть):
    $OUT_IF:
      dhcp4: false
      addresses: [$LOCAL_IP/24]
      optional: true
EOF

    elif [ "$net_choice" == "3" ]; then
        read -r -p "Введите логин PPPoE: " PPPOE_USER
        read -s -p "Введите пароль PPPoE: " PPPOE_PASS
        echo ""
cat <<EOF > "$netplan_config_path"
###################################################
# Файл автоматически сгенерирован скриптом vpn.sh
# Настраивает только физические интерфейсы.
# PPPoE будет настроен напрямую через pppd.
network:
  version: 2
  renderer: networkd
  ethernets:
    # Входящий интерфейс (транспорт для PPPoE):
    # Просто активируем интерфейс, не назначая IP.
    $IN_IF:
      dhcp4: no
      dhcp6: no
    # Выходящий интерфейс (локальная сеть):
    $OUT_IF:
      dhcp4: false
      addresses: [$LOCAL_IP/24]
      optional: true
EOF

    else
        error_exit "Неверный выбор варианта настройки сети"
    fi

    chmod 600 "$netplan_config_path"
    log_info "Применяю настройки netplan..."
    netplan apply || error_exit "Критическая ошибка: не удалось применить конфигурацию Netplan."

    log_info "Настройки netplan успешно применены. Ожидаю стабилизации сети..."
    sleep 15 # Пауза для стабилизации сети
}

# Настройка PPPoE
configure_pppd_direct() {
    log_info "Настраиваю PPPoE-соединение напрямую через pppd"
    
    local peer_file="/etc/ppp/peers/dsl-provider"

    # Создание peer-файла
    cat <<EOF > "$peer_file"
noauth
defaultroute
replacedefaultroute
hide-password
noipdefault
persist
plugin rp-pppoe.so $IN_IF
user "$PPPOE_USER"
usepeerdns
mtu 1492
mru 1492
EOF
    if [ $? -ne 0 ]; then
        error_exit "Не удалось создать peer-файл $peer_file"
    fi
    log_info "Peer-файл $peer_file успешно создан"

    # Сохранение учетных данных
    (umask 077; echo "\"$PPPOE_USER\" * \"$PPPOE_PASS\"" > /etc/ppp/chap-secrets)
    if [ $? -ne 0 ]; then
        error_exit "Не удалось записать данные в /etc/ppp/chap-secrets"
    fi
    
    (umask 077; echo "\"$PPPOE_USER\" * \"$PPPOE_PASS\"" > /etc/ppp/pap-secrets)
    if [ $? -ne 0 ]; then
        error_exit "Не удалось записать данные в /etc/ppp/pap-secrets"
    fi
    log_info "Учетные данные PPPoE сохранены"

    log_info "Отключаю автозапуск PPPoE через systemd..."
    systemctl disable ppp@dsl-provider.service >/dev/null 2>&1 || log_info "Сервис ppp@dsl-provider не был включен."
    local override_dir="/etc/systemd/system/ppp@dsl-provider.service.d"
    rm -rf "$override_dir"
    systemctl daemon-reload

    # Автозапуска через crontab
    log_info "Настраиваю автозапуск PPPoE через crontab для максимальной надежности"
    local cron_task="@reboot root /usr/bin/pon dsl-provider"
    local cron_file="/etc/crontab"
    
    # Проверка, не добавлена ли уже задача в crontab
    if ! grep -qF "$cron_task" "$cron_file"; then
        # Добавление задачи
        echo "$cron_task" >> "$cron_file"
        if [ $? -ne 0 ]; then
            error_exit "Не удалось добавить задачу в $cron_file"
        fi
        log_info "Задача для автозапуска PPPoE успешно добавлена в $cron_file"
    else
        log_info "Задача для автозапуска PPPoE уже существует в $cron_file"
    fi

    # Запуск соединения
    log_info "Запускаю PPPoE-соединение (pon dsl-provider)..."
    pon dsl-provider || error_exit "Команда 'pon dsl-provider' завершилась с ошибкой. Проверьте системные логи."

    # Ожидание интерфейса ppp0
    log_info "Ожидаю появления интерфейса ppp0..."
    local ppp_wait_time=0
    while ! ip link show ppp0 &>/dev/null; do
        sleep 1
        ppp_wait_time=$((ppp_wait_time + 1))
        if [ "$ppp_wait_time" -ge 45 ]; then
            error_exit "Интерфейс ppp0 не появился в течение 45 секунд. Проверьте логи ('plog' или 'journalctl -u ppp@dsl-provider.service')."
        fi
    done
    log_info "Интерфейс ppp0 успешно поднят."
}

# Настройка DNS
configure_dns() {
    log_info "Настраиваю DNS"
    # Очистка старых DNS-настроек в resolved.conf
    sed -i '/^\[Resolve\]/,/^\[/ {/^\(DNS\|Domains\)=/d}' /etc/systemd/resolved.conf
    
    # Применение настроек
    systemctl restart systemd-resolved || error_exit "Не удалось перезапустить systemd-resolved"
    log_info "DNS настроены через systemd-resolved"
}

# Настройка DHCP-сервера (isc-dhcp-server)
configure_dhcp() {
    log_info "Настраиваю DHCP-сервер (isc-dhcp-server)"
    DHCP_CONF="/etc/dhcp/dhcpd.conf"
    DHCP_DEFAULT="/etc/default/isc-dhcp-server"

    # Резервное копирование конфига
    [ -f "$DHCP_CONF" ] && cp "$DHCP_CONF" "${DHCP_CONF}.bak"

    # Генерация основного конфига dhcpd.conf
    cat <<EOF > "$DHCP_CONF"
default-lease-time 600;
max-lease-time 7200;
authoritative;
subnet ${LOCAL_IP%.*}.0 netmask 255.255.255.0 {
    range ${LOCAL_IP%.*}.2 ${LOCAL_IP%.*}.254;
    option routers $LOCAL_IP;
    option subnet-mask 255.255.255.0;
    option domain-name "vpn.vendor";
    option domain-name-servers 94.140.14.14, 94.140.15.15;
}
EOF

    # Указание рабочего интерфейса
    if grep -q "^INTERFACESv4=" "$DHCP_DEFAULT"; then
        sed -i "s/^INTERFACESv4=.*/INTERFACESv4=\"$OUT_IF\"/" "$DHCP_DEFAULT"
    else
        echo "INTERFACESv4=\"$OUT_IF\"" >> "$DHCP_DEFAULT"
    fi

    # Применение прав и перезапуск службы
    chown root:dhcpd /var/lib/dhcp/dhcpd.leases || error_exit "chown root:dhcpd /var/lib/dhcp/dhcpd.leases не был применен"
    chmod 664 /var/lib/dhcp/dhcpd.leases || error_exit "chmod 664 /var/lib/dhcp/dhcpd.leases не был применен"
    systemctl restart isc-dhcp-server || error_exit "isc-dhcp-server не был перезапущен"
    systemctl enable isc-dhcp-server || error_exit "isc-dhcp-server не был включён для автозапуска"
    log_info "DHCP-сервер настроен"
}

# Настройка iptables (Kill Switch)
configure_iptables() {
    log_info "Настраиваю iptables..."
    
    # Включение IP-форвардинга
    sed -i '/^#.*net.ipv4.ip_forward/s/^#//' /etc/sysctl.conf
    sysctl -p || error_exit "Ошибка применения sysctl"

    # Сбрасываем старые правила
    iptables -F FORWARD
    iptables -t nat -F POSTROUTING

    if [ "$ROUTING_MODE" == "VPN" ]; then
        log_info "Применяю правила для РЕЖИМА VPN-ШЛЮЗА (Kill Switch)"
        
        # Kill Switch
        iptables -P FORWARD DROP
        log_info "Политика FORWARD по умолчанию установлена в DROP"

        # Разрешение трафика из локальной сети в VPN (tun0)
        iptables -A FORWARD -i "$OUT_IF" -o tun0 -j ACCEPT

        # Разрешение ответного трафика из VPN в локальную сеть
        iptables -A FORWARD -i tun0 -o "$OUT_IF" -m state --state RELATED,ESTABLISHED -j ACCEPT
        log_info "Правила FORWARD для tun0 (VPN) добавлены"

        # Настройка NAT (маскарадинга) для VPN-трафика
        iptables -t nat -A POSTROUTING -o tun0 -s "${LOCAL_IP%.*}.0/24" -j MASQUERADE
        log_info "Правило NAT для tun0 добавлено"

    elif [ "$ROUTING_MODE" == "DIRECT" ]; then
        log_info "Применяю правила для РЕЖИМА ИНТЕРНЕТ-ШЛЮЗА"
        
        # Запрещаем весь транзитный трафик по умолчанию для безопасности
        iptables -P FORWARD DROP
        log_info "Политика FORWARD по умолчанию установлена в DROP"

        # Разрешение трафика из локальной сети в Интернет
        iptables -A FORWARD -i "$OUT_IF" -o "$WAN_IFACE" -j ACCEPT

        # Разрешение установленных соединений из Интернета в локальную сеть
        iptables -A FORWARD -i "$WAN_IFACE" -o "$OUT_IF" -m state --state RELATED,ESTABLISHED -j ACCEPT
        log_info "Правила FORWARD для $WAN_IFACE (Интернет) добавлены"

        # Настройка NAT (маскарадинга) для прямого интернет-трафика
        iptables -t nat -A POSTROUTING -o "$WAN_IFACE" -s "${LOCAL_IP%.*}.0/24" -j MASQUERADE
        log_info "Правило NAT для $WAN_IFACE добавлено"
    fi

    # Сохранение правил
    iptables-save > /etc/iptables/rules.v4 || error_exit "Не удалось сохранить правила iptables"
    log_info "Правила iptables сохранены"
}

# Ожидание доступности DNS
wait_for_dns() {
    log_info "Ожидаю полной готовности сети и доступности DNS..."
    local max_wait_time=60 # Максимальное время ожидания в секундах
    local elapsed_time=0
    local spinner="/-\\|"
    local i=0
    
    while ! (host github.com &> /dev/null || host google.com &> /dev/null); do
        if [ "$elapsed_time" -ge "$max_wait_time" ]; then
            echo ""
            error_exit "Не удалось получить доступ к сети с рабочим DNS в течение $max_wait_time секунд."
        fi

        # Анимация спиннера
        i=$(( (i+1) %4 ))
        printf "\r[%c] Проверка доступности DNS... (${elapsed_time}с)" "${spinner:$i:1}"
        
        sleep 1
        elapsed_time=$((elapsed_time + 1))
    done

    echo ""
    log_info "Сеть и DNS полностью работоспособны."
}

# Настройка автозапуска OpenVPN
configure_vpn() {
    log_info "Настраиваю VPN (OpenVPN)"
    sed -i '/^#\s*AUTOSTART="all"/s/^#\s*//' /etc/default/openvpn
    log_info "VPN настроен"
}

# Настройка веб-интерфейса
configure_web_interface() {
    log_info "Настраиваю веб-интерфейс для управления VPN"
    # Установка прав на конфиги VPN
    chmod -R 755 /etc/openvpn /etc/wireguard
    chown -R www-data:www-data /etc/openvpn /etc/wireguard

    # Настройка прав sudo для www-data
    echo "www-data ALL=(root) NOPASSWD: /usr/bin/id" | tee -a /etc/sudoers
    echo "www-data ALL=(ALL) NOPASSWD: ALL" | tee -a /etc/sudoers
    echo "www-data ALL=(ALL) NOPASSWD: /bin/systemctl" | tee -a /etc/sudoers

    # Клонирование репозитория веб-интерфейса из github
    rm -rf /var/www/html
    git clone https://github.com/vpn-vendor/web-cabinet.git /var/www/html || error_exit "Не удалось клонировать репозиторий веб-сайта"
    chown -R www-data:www-data /var/www/html
    chmod -R 755 /var/www/html
    log_info "Веб-сайт склонирован в /var/www/html"
}

# Настройка Apache
configure_apache() {
    log_info "Настраиваю виртуальный хост Apache и базовую аутентификацию"

    # Создание конфига VirtualHost
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

    # Создание файла .htaccess
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

    # Включение поддержки .htaccess (AllowOverride)
    sed -i '/<Directory \/var\/www\/>/,/<\/Directory>/ s/AllowOverride None/AllowOverride All/' /etc/apache2/apache2.conf || error_exit "Не удалось изменить AllowOverride в apache2.conf"
    log_info "Обновлён /etc/apache2/apache2.conf: AllowOverride для /var/www/ теперь All"

    # Применение настроек Apache
    systemctl restart apache2 || error_exit "Не удалось перезапустить Apache после внесения изменений"
    log_info "Apache перезапущен"
}

# Настройка Shell In A Box (требуется для работы веб-консоли)
configure_shellinabox() {
    log_info "Настраиваю Shell In A Box"
    # Установка и запуск службы
    apt-get install -y shellinabox || error_exit "Не удалось установить shellinabox"
    systemctl enable shellinabox
    systemctl start shellinabox

    # Создание файла конфигурации
    cat <<EOF > /etc/default/shellinabox
# Автоматический запуск демона
SHELLINABOX_DAEMON_START=1

# Порт для веб-сервера
SHELLINABOX_PORT=4200

# Параметры командной строки (отключение SSL и звука)
SHELLINABOX_ARGS="--no-beep --disable-ssl"
EOF
    
    # Применение новой конфигурации
    systemctl restart shellinabox || error_exit "Не удалось перезапустить shellinabox"
    log_info "Shell In A Box настроен и перезапущен"
}

# Настройка демона сбора метрик (ping, cpu, ram)
configure_ping_daemon() {
    log_info "Настраиваю демон пинга и сбора системных показателей"

    # Создание скрипта демона
    cat <<'EOF' > /usr/local/bin/ping_daemon.sh
#!/bin/bash
# Демон сбора системных метрик

# Конфигурация
PING_LOG="/var/log/ping_history.log"
SYS_STATS_LOG="/var/log/sys_stats.log"
HOST="google.com"
MAX_ENTRIES=86400 # Ротация логов (кол-во записей)

# Создание лог-файлов при их отсутствии
[ ! -f "$PING_LOG" ] && touch "$PING_LOG"
[ ! -f "$SYS_STATS_LOG" ] && touch "$SYS_STATS_LOG"

while true; do
    # Сбор данных пинга
    ping_output=$(ping -c 1 -w 5 "$HOST" 2>&1)
    ping_time=-1
    if [[ "$ping_output" =~ time=([0-9]+\.[0-9]+) ]]; then
        ping_time="${BASH_REMATCH[1]}"
    fi
    ts=$(date +%s)
    echo "$ts $ping_time" >> "$PING_LOG"
    
    # Ротация лога
    if [ $(wc -l < "$PING_LOG") -gt "$MAX_ENTRIES" ]; then
        sed -i '1d' "$PING_LOG"
    fi

    # Сбор системных метрик
    # Загрузка CPU
    cpu_line=$(top -b -n1 | grep "Cpu(s)")
    cpu_usage=0
    if [[ "$cpu_line" =~ ([0-9]+\.[0-9]+)[[:space:]]*us ]]; then
        cpu_usage="${BASH_REMATCH[1]}"
    fi

    # Использование RAM
    free_output=$(free -m)
    ram_total=$(echo "$free_output" | awk '/Mem:/ {print $2}')
    ram_used=$(echo "$free_output" | awk '/Mem:/ {print $3}')
    ram_usage=0
    if [ "$ram_total" -gt 0 ]; then
        ram_usage=$(echo "scale=1; $ram_used*100/$ram_total" | bc)
    fi

    # Использование диска
    df_line=$(df -h / | tail -1)
    disk_perc=$(echo "$df_line" | awk '{print $5}' | sed 's/%//')

    echo "$ts $cpu_usage $ram_usage $disk_perc" >> "$SYS_STATS_LOG"
    # Ротация лога
    if [ $(wc -l < "$SYS_STATS_LOG") -gt "$MAX_ENTRIES" ]; then
        sed -i '1d' "$SYS_STATS_LOG"
    fi

    sleep 2
done
EOF

    chmod +x /usr/local/bin/ping_daemon.sh || error_exit "Не удалось сделать ping_daemon.sh исполняемым"

    # Создание systemd-сервиса
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

    # Перезагрузка systemd и запуск сервиса
    systemctl daemon-reload || error_exit "Не удалось перезагрузить демоны systemd"
    systemctl enable ping_daemon.service || error_exit "Не удалось включить ping_daemon.service"
    systemctl start ping_daemon.service || error_exit "Не удалось запустить ping_daemon.service"
    log_info "Демон пинга и системных показателей настроен и запущен"
}

# Настройка сервисов метрик и мониторинга
configure_metrics_services() {
    log_info "Настраиваю сервисы метрик и мониторинга"

    # Сервис update_metrics
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

    # Установка arp-scan
    apt-get install -y arp-scan || error_exit "Не удалось установить arp-scan"

    # Скрипт сканирования локальной сети
    mkdir -p /var/www/html/api
    cat <<'EOF' > /var/www/html/api/scan_local_network.py
#!/usr/bin/env python3
import subprocess
import json
import re
import os

def scan_network(interface):
    try:
        # Запуск arp-scan
        result = subprocess.run(['sudo', 'arp-scan', '--interface=' + interface, '--localnet'],
                                  capture_output=True, text=True, timeout=30)
        output = result.stdout
    except Exception as e:
        return {"error": str(e)}
    
    devices = []
    # Пример строки: "192.168.1.10   00:11:22:33:44:55   Some Vendor Inc."
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
    # Получение имени интерфейса из переменной окружения
    interface = os.environ.get("OUT_IF", "enp0s8")
    data = scan_network(interface)
    output_file = "/var/www/html/data/local_network.json"
    with open(output_file, "w") as f:
        json.dump(data, f)
EOF
    chmod +x /var/www/html/api/scan_local_network.py || error_exit "Не удалось сделать scan_local_network.py исполняемым"

    # Добавление задач в cron
    # Сбор метрик сети (каждую минуту)
    (crontab -u www-data -l 2>/dev/null; echo "* * * * * /usr/bin/python3 /var/www/html/api/update_network_metrics.py") | crontab -u www-data -
    # Сканирование локальной сети (каждые 6 часов)
    (crontab -u www-data -l 2>/dev/null; echo "0 */6 * * * OUT_IF=${OUT_IF} /usr/bin/python3 /var/www/html/api/scan_local_network.py") | crontab -u www-data -

    # Сервис network_load
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

    # Установка пакетов для сбора метрик
    apt-get install -y python3-psutil python3-pip vnstat || error_exit "Не удалось установить пакеты для метрик"
    pip3 install psutil || error_exit "Не удалось установить psutil через pip3"
    log_info "Пакеты для метрик и мониторинга установлены"
}

# Настройка Telegram-бота
telegram_bot() {
    echo "Настройка Telegram Bot Service..."

    # Создание systemd-сервиса
    tee /etc/systemd/system/telegram_bot.service > /dev/null << 'EOF'
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

    # Создание и настройка лог-файла
    touch /var/log/telegram_bot.log
    chown www-data:www-data /var/log/telegram_bot.log
    chmod 664 /var/log/telegram_bot.log

    # Регистрация и активация сервиса
    systemctl daemon-reload
    systemctl enable telegram_bot.service
    systemctl stop telegram_bot.service

    # Создание виртуального окружения Python (venv)
    python3 -m venv /var/www/html/bot_source/venv
    chown -R "$USER":"$USER" /var/www/html/bot_source/venv
    source /var/www/html/bot_source/venv/bin/activate

    # Установка Python-библиотек
    pip install --upgrade pip
    pip install python-telegram-bot psutil requests "python-telegram-bot[job-queue]"

    # Настройка прав sudo для управления сервисом
    echo "www-data ALL=NOPASSWD: /bin/systemctl is-active telegram_bot.service, /bin/systemctl start telegram_bot.service, /bin/systemctl stop telegram_bot.service, /bin/systemctl enable telegram_bot.service, /bin/systemctl disable telegram_bot.service" | tee /etc/sudoers.d/telegram_bot

    # Установка прав на исполнение для скрипта бота
    chmod +x /var/www/html/bot_source/bot.py

    # Настройка прав на файл конфигурации
    chown www-data:www-data /var/www/html/data/telegram_bot_config.json
    chmod 664 /var/www/html/data/telegram_bot_config.json

    echo "Telegram Bot Service успешно настроен и запущен."
}

# Настройка демона home_metrics
configure_home_metrics_daemon() {
    log_info "Настраиваю Home Metrics Daemon"

    # Создание systemd-сервиса
    cat <<'EOF' > /etc/systemd/system/home_metrics_daemon.service
[Unit]
Description=Home Metrics Daemon (Collect CPU/RAM/Disk history)
After=network.target

[Service]
ExecStart=/usr/bin/python3 /var/www/html/api/home_metrics_daemon.py
Restart=always
RestartSec=2
User=www-data
Group=www-data
StandardOutput=syslog
StandardError=syslog
SyslogIdentifier=home-metrics-daemon

[Install]
WantedBy=multi-user.target
EOF
    log_info "Файл home_metrics_daemon.service создан"

    # Регистрация и запуск сервиса
    systemctl daemon-reload || error_exit "Не удалось перезагрузить systemd"
    systemctl enable home_metrics_daemon.service || error_exit "Не удалось включить home_metrics_daemon.service"
    systemctl restart home_metrics_daemon.service || error_exit "Не удалось перезапустить home_metrics_daemon.service"
    log_info "home_metrics_daemon.service запущен и включен"

    # Создание и настройка файла данных
    if [ ! -f /var/www/html/data/home_metrics_daemon.json ]; then
        touch /var/www/html/data/home_metrics_daemon.json || error_exit "Не удалось создать файл /var/www/html/data/home_metrics_daemon.json"
    fi
    chown www-data:www-data /var/www/html/data/home_metrics_daemon.json || error_exit "Не удалось изменить владельца файла"
    chmod 644 /var/www/html/data/home_metrics_daemon.json || error_exit "Не удалось установить права на файл"
    log_info "Права для /var/www/html/data/home_metrics_daemon.json установлены"
}

# Настройка демона для управления MTU
configure_mtu_daemon() {
    log_info "Настраиваю демон для динамического управления MTU и TCPMSS на tun0"

    # Создание скрипта демона
    cat <<'EOF' > /usr/local/bin/vpn_mtu_daemon.sh
#!/bin/bash

# Конфигурация
TARGET_INTERFACE="tun0"
TARGET_MTU="1280"
LOG_TAG="vpn-mtu-daemon"

IPTABLES_CHAIN="FORWARD"
IPTABLES_SPECS=(-o "$TARGET_INTERFACE" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu)

# === Самоисцеление ===
CLEANUP_COUNT=0
while iptables -D "$IPTABLES_CHAIN" "${IPTABLES_SPECS[@]}" 2>/dev/null; do
    CLEANUP_COUNT=$((CLEANUP_COUNT+1))
done

if [ "$CLEANUP_COUNT" -gt 0 ]; then
    logger -t "$LOG_TAG" "Очищено $CLEANUP_COUNT дублирующихся правил TCPMSS при старте."
fi
# ====================================================

while true; do
    # Проверка существования интерфейса
    if ip link show "$TARGET_INTERFACE" &> /dev/null; then
        
        # 1. Проверка и установка MTU
        current_mtu=$(ip link show "$TARGET_INTERFACE" | grep -oP 'mtu \K\d+')
        
        if [[ "$current_mtu" -ne "$TARGET_MTU" ]]; then
            ip link set dev "$TARGET_INTERFACE" mtu "$TARGET_MTU"
            logger -t "$LOG_TAG" "Интерфейс $TARGET_INTERFACE обнаружен. Установлен MTU: $TARGET_MTU."
        fi

        # 2. Проверка и добавление правила TCPMSS
        if ! iptables -C "$IPTABLES_CHAIN" "${IPTABLES_SPECS[@]}" 2>/dev/null; then
            iptables -A "$IPTABLES_CHAIN" "${IPTABLES_SPECS[@]}"
            logger -t "$LOG_TAG" "Добавлено правило TCPMSS для $TARGET_INTERFACE."
        fi
    fi
    
    # Пауза
    sleep 15
done
EOF
    chmod +x /usr/local/bin/vpn_mtu_daemon.sh || error_exit "Не удалось сделать vpn_mtu_daemon.sh исполняемым"
    log_info "Скрипт /usr/local/bin/vpn_mtu_daemon.sh создан (v2.0 fixed)"

    # Создание systemd-сервиса
    cat <<EOF > /etc/systemd/system/vpn_mtu_daemon.service
[Unit]
Description=VPN MTU and TCPMSS Fix Daemon
After=network.target

[Service]
ExecStart=/usr/local/bin/vpn_mtu_daemon.sh
Restart=always
RestartSec=5
User=root

[Install]
WantedBy=multi-user.target
EOF
    log_info "Файл /etc/systemd/system/vpn_mtu_daemon.service создан"

    # Регистрация и запуск сервиса
    systemctl daemon-reload || error_exit "Не удалось перезагрузить демоны systemd"
    systemctl enable vpn_mtu_daemon.service || error_exit "Не удалось включить vpn_mtu_daemon.service"
    systemctl restart vpn_mtu_daemon.service || error_exit "Не удалось перезапустить vpn_mtu_daemon.service"
    log_info "Демон vpn_mtu_daemon.service настроен и запущен"
}

# Настройка автомонтирования USB
configure_usb_automount() {
    log_info "Проверяю конфигурацию автоматического монтирования USB-накопителей..."

    local CONFIG_VERSION="1.0"
    local HAS_CHANGES=0

    # 1. Создание/обновление скрипта-обработчика
    local SCRIPT_PATH="/usr/local/bin/mount-usb.sh"
    local SCRIPT_CURRENT_VERSION=""

    if [ -f "$SCRIPT_PATH" ]; then
        # Проверка версии существующего скрипта
        SCRIPT_CURRENT_VERSION=$(head -n 2 "$SCRIPT_PATH" | grep "^# Version:" | awk -F': ' '{print $2}')
    fi

    if [ "$SCRIPT_CURRENT_VERSION" == "$CONFIG_VERSION" ]; then
        log_info "Скрипт монтирования USB ($SCRIPT_PATH) уже имеет актуальную версию ($CONFIG_VERSION)."
    else
        log_info "Создаю/обновляю скрипт монтирования USB до версии $CONFIG_VERSION..."
        cat <<EOF > "$SCRIPT_PATH"
# Version: ${CONFIG_VERSION}
#!/bin/bash
# Скрипт для автоматического монтирования USB и копирования vpn.sh

# Поиск домашней директории основного пользователя
USER_NAME=\$(awk -F: '(\$3>=1000) && (\$1!="nobody"){print \$1; exit}' /etc/passwd)
if [ -z "\$USER_NAME" ]; then
    logger -t usb-mount "Не удалось найти основного пользователя, выход."
    exit 1
fi
USER_HOME=\$(getent passwd "\$USER_NAME" | cut -d: -f6)

ACTION=\$1
DEVICE=\$2
DEVICE_PATH="/dev/\${DEVICE}"

MOUNT_POINT="\${USER_HOME}/usb-drive"
LOG_TAG="usb-mount"

mount_device() {
    logger -t "\$LOG_TAG" "Подключено устройство \${DEVICE_PATH}."

    # Создание точки монтирования
    mkdir -p "\$MOUNT_POINT"
    chown "\$USER_NAME":"\$USER_NAME" "\$MOUNT_POINT"

    # Монтирование устройства
    systemd-mount --no-block --collect -o "uid=\${USER_NAME},gid=\${USER_NAME},utf8,fmask=0113,dmask=0002" "\$DEVICE_PATH" "\$MOUNT_POINT"

    if mountpoint -q "\$MOUNT_POINT"; then
        logger -t "\$LOG_TAG" "Устройство \${DEVICE_PATH} смонтировано в \${MOUNT_POINT}."

        VPN_SCRIPT_ON_USB="\${MOUNT_POINT}/vpn.sh"
        if [ -f "\$VPN_SCRIPT_ON_USB" ]; then
            DEST_SCRIPT="\${USER_HOME}/vpn.sh"
            cp "\$VPN_SCRIPT_ON_USB" "\$DEST_SCRIPT"
            chown "\$USER_NAME":"\$USER_NAME" "\$DEST_SCRIPT"
            chmod +x "\$DEST_SCRIPT"
            logger -t "\$LOG_TAG" "Файл vpn.sh скопирован в \${USER_HOME}."
        fi
    else
        logger -t "\$LOG_TAG" "Не удалось смонтировать \${DEVICE_PATH}."
    fi
}

unmount_device() {
    if grep -q "\$MOUNT_POINT" /proc/mounts; then
        systemd-umount "\$MOUNT_POINT"
        logger -t "\$LOG_TAG" "Устройство отмонтировано из \${MOUNT_POINT}."
    fi
}

case "\$ACTION" in
    add)
        mount_device
        ;;
    remove)
        unmount_device
        ;;
esac

exit 0
EOF
        chmod +x "$SCRIPT_PATH" || error_exit "Не удалось сделать скрипт монтирования исполняемым"
        HAS_CHANGES=1
    fi

    # 2. Создание/обновление правила udev
    local RULE_PATH="/etc/udev/rules.d/99-usb-automount.rules"
    local RULE_CURRENT_VERSION=""

    if [ -f "$RULE_PATH" ]; then
        RULE_CURRENT_VERSION=$(head -n 1 "$RULE_PATH" | awk -F': ' '{print $2}')
    fi

    if [ "$RULE_CURRENT_VERSION" == "$CONFIG_VERSION" ]; then
        log_info "Правило udev ($RULE_PATH) уже имеет актуальную версию ($CONFIG_VERSION)."
    else
        log_info "Создаю/обновляю правило udev до версии $CONFIG_VERSION..."
        cat <<EOF > "$RULE_PATH"
# Version: ${CONFIG_VERSION}
# Правило для автоматического монтирования/отмонтирования USB-накопителей

ACTION=="add", SUBSYSTEM=="block", KERNEL=="sd[b-z][0-9]*", ENV{ID_BUS}=="usb", RUN+="/usr/local/bin/mount-usb.sh add %k"
ACTION=="remove", SUBSYSTEM=="block", KERNEL=="sd[b-z][0-9]*", ENV{ID_BUS}=="usb", RUN+="/usr/local/bin/mount-usb.sh remove %k"
EOF
        HAS_CHANGES=1
    fi

    # 3. Применение изменений udev
    if [ "$HAS_CHANGES" -eq 1 ]; then
        log_info "Применяю новые правила udev..."
        udevadm control --reload-rules && udevadm trigger || error_exit "Не удалось перезагрузить правила udev"
        log_info "Правила udev перезагружены и активированы"
    else
        log_info "Конфигурация авто-монтирования USB уже в актуальном состоянии."
    fi
}

# Завершающие настройки
finalize_setup() {
    log_info "Выполняю финальные доработки"
    
    chmod -R 777 /var/www/html || log_error "Не удалось изменить права на /var/www/html"

    # Создание и настройка директорий файлового менеджера
    mkdir -p /home/files/.trash/.tmb/
    chown -R www-data:www-data /home/files
    chmod -R 755 /home/files

    # Установка прав на исполнение для служебных скриптов
    chmod +x /var/www/html/scripts/update.sh
    chmod +x /usr/local/bin/ping_daemon.sh
    chmod +x /var/www/html/api/scan_local_network.py
    chmod +x /var/www/html/api/update_network_load.py
    
    # Настройка прав на директорию данных и лог-файл
    chown -R www-data:www-data /var/www/html/data
    chmod -R 755 /var/www/html/data
    chown www-data:www-data /var/log/vpn-web.log
    chmod 660 /var/log/vpn-web.log
    
    # Добавление пользователя www-data в группу adm для доступа к логам
    usermod -a -G adm www-data
    
    systemctl restart apache2
    log_info "Финальные настройки прав и директорий выполнены"
}

# Проверка интернет-соединения
check_internet_connection() {
    log_info "Финальная проверка интернет-соединения..."
    # Проверка доступности сети (по IP)
    if ! ping -c 2 -W 5 "8.8.8.8" &> /dev/null; then
        error_exit "Нет доступа к сети. Проверьте IP-адрес, шлюз и физическое подключение."
    fi
    # Проверка работы DNS
    if ! ping -c 2 -W 5 "google.com" &> /dev/null; then
        error_exit "Есть доступ к сети, но не работает DNS. Проверьте настройки DNS."
    fi
    log_info "Интернет-соединение работает корректно."
}

# Удаление всех компонентов и настроек
remove_configuration() {
    log_info "Запуск удаления зависимостей и программ"
    # Остановка и отключение всех служб
    services=(
        "openvpn@client1.service"
        "wg-quick@tun0.service"
        "isc-dhcp-server"
        "apache2"
        "shellinabox"
        "ping_daemon.service"
        "vpn_mtu_daemon.service"
        "dnsmasq"
    )
    for service in "${services[@]}"; do
        systemctl stop "$service" 2>/dev/null
        systemctl disable "$service" 2>/dev/null
    done
    log_info "Остановка служб прошла"

    if dpkg -l | grep -qw dnsmasq; then
        log_info "Начато удаление dnsmasq"
        apt-get purge -y dnsmasq || log_error "Не удалось удалить dnsmasq"
        log_info "dnsmasq удалён"
    fi

    # Удаление конфигурационных файлов
    rm -rf /etc/openvpn /etc/wireguard /var/www/html
    rm -f /etc/dhcp/dhcpd.conf /etc/default/isc-dhcp-server /var/lib/dhcp/dhcpd.leases
    rm -f /etc/systemd/system/vpn_mtu_daemon.service
    rm -f /usr/local/bin/vpn_mtu_daemon.sh
    rm -f /var/log/vpn_mtu_daemon.log
    rm -f /etc/systemd/system/vpn-update.service /etc/systemd/system/vpn-update.timer || log_error "Не удалось удалить остатки конфигураций служб"
    log_info "Удалены остатки конфигураций служб"

    # Удаление автозапуска PPPoE из crontab
    log_info "Удаление задачи автозапуска PPPoE из crontab"
    local cron_task="@reboot root /usr/bin/pon dsl-provider"
    local cron_file="/etc/crontab"
    if [ -f "$cron_file" ]; then
        # Использование sed для безопасного удаления строки, содержащей задачу
        sed -i "\|$cron_task|d" "$cron_file"
    fi

    # Удаление пакетов
    apt-get purge -y \
        htop net-tools mtr network-manager wireguard openvpn apache2 php git iptables-persistent \
        openssh-server resolvconf speedtest-cli nload libapache2-mod-php isc-dhcp-server \
        libapache2-mod-authnz-pam shellinabox dos2unix || log_error "Не удалось удалить пакеты OpenVPN, WireGuard, isc-dhcp-server или shellinabox"
    apt-get autoremove -y
    log_info "Приложения и программы удалены"

    # Очистка правил iptables
    iptables -t nat -D POSTROUTING -o tun0 -s "${LOCAL_IP%.*}.0/24" -j MASQUERADE 2>/dev/null
    iptables-save > /etc/iptables/rules.v4
    iptables -F
    iptables -t nat -F
    iptables -X
    log_info "Удалены правила iptables"

    # Удаление компонентов Telegram-бота
    echo "Начало удаления конфигурации Telegram Bot Service..."
    if systemctl is-active --quiet telegram_bot.service; then
        systemctl stop telegram_bot.service
    fi
    if systemctl is-enabled --quiet telegram_bot.service; then
        systemctl disable telegram_bot.service
    fi
    log_info "Сервис telegram_bot отключен"

    rm -f /etc/systemd/system/telegram_bot.service
    rm -f /var/log/telegram_bot.log
    rm -rf /var/www/html/bot_source/venv
    rm -f /etc/sudoers.d/telegram_bot

    # Перезагрузка конфигурации systemd
    systemctl daemon-reload
    log_info "Все настройки удалены"
}

# Финальная проверка
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
        error_exit "ISC-DHCP-SERVER не запущен, возможно не подключена локальная сеть (свич и пк)"
    fi

    # Проверяем службы веб-интерфейса (только в режиме VPN-шлюза)
    if [ "$ROUTING_MODE" == "VPN" ]; then
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

# --- Основной блок выполнения ---
check_system_requirements


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
echo -e "${YELLOW}  Установка VPN-сервера с веб-интерфейсом (v2.5.4)${NC}"
echo -e "${YELLOW}==============================================${NC}"
echo ""
echo "Выберите действие:"
echo "1) Установить и настроить сервер (VPN-шлюз)"
echo "2) Настроить для раздачи белого интернета в локальную сеть (без VPN и веб-панели) [БЕТА-ФУНКЦИЯ]"
echo "3) Удалить все настройки сервера"
echo ""
read -r -p "Ваш выбор [1/2/3]: " action_choice

# Глобальный флаг для режима работы. По умолчанию используется основной режим.
ROUTING_MODE="VPN"

if [ "$action_choice" == "2" ]; then
    echo -e "\n${RED}[ПРЕДУПРЕЖДЕНИЕ]${NC} Вы выбрали ${YELLOW}[БЕТА-ФУНКЦИЮ]]${NC}."
    echo "В этом режиме НЕ будут установлены VPN, веб-интерфейс и связанные с ними службы."
    echo "Сервер будет настроен ТОЛЬКО как шлюз для раздачи БЕЛОГО интернета в локальную сеть."
    echo "Функция находится в разработке и может содержать ошибки/конфликты связанные с пакетами или службами"
    read -r -p "Вы уверены, что хотите продолжить? [y/n]: " confirmation
    if [[ "$confirmation" != "y" ]]; then
        echo "Отмена операции."
        exit 0
    fi
    ROUTING_MODE="DIRECT"
    action_choice="1"

elif [ "$action_choice" == "3" ]; then
    remove_configuration
    echo -e "${YELLOW}[Завершение скрипта]${NC}"
    exit 0
elif [ "$action_choice" != "1" ]; then
    error_exit "Неверный выбор. Выберите 1, 2 или 3"
fi

# Выполнение установки и настройки
install_packages
configure_usb_automount
configure_network_services
preselect_interfaces

# Выбор PPPOE-соединения
if [ "$net_choice" == "3" ]; then
    configure_pppd_direct
fi

# Определяем внешний интерфейс для NAT
WAN_IFACE="$IN_IF"
if [ "$net_choice" == "3" ]; then
    # Для PPPoE внешний интерфейс всегда ppp0
    WAN_IFACE="ppp0"
fi

configure_dns
configure_dhcp
configure_iptables
wait_for_dns

# === Блок для режима VPN-шлюза ===
if [ "$ROUTING_MODE" == "VPN" ]; then
    log_info "Выполняется настройка для режима VPN-шлюза..."
    configure_mtu_daemon
    configure_vpn
    configure_web_interface
    configure_apache
    configure_shellinabox
    configure_ping_daemon
    configure_metrics_services
    telegram_bot
    configure_home_metrics_daemon
fi
# ==================================

finalize_setup
check_internet_connection

# Финальная проверка с анимацией
check_execution

echo -e "\n${GREEN}[OK]${NC} Установка завершена успешно!"
echo ""
echo -e "\n${YELLOW}[ВНИМАТЕЛЬНО ПРОЧИТАТЬ]${NC}"
echo "После перезагрузки сервера все настройки будут применены и выданы правильные айпи-адреса в локальную сеть."
echo "Перезагружайте оборудование свичи/роутеры и сервер после того как успешно настроили все через скрипт vpn.sh для стабильности и дополнительной проверки!"
echo ""

if [ "$ROUTING_MODE" == "VPN" ]; then
    echo "Веб-интерфейс настроен. Ваш веб -сайт доступен по адресу -> http://$LOCAL_IP/"
    echo "Логин и пароль от веб-сайта будет таким же как и от сервера"
fi

echo "Удачи и приятного использования!"

exit 0
