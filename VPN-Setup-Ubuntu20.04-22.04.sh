#!/bin/bash
# =============================================================================
# Поддержка Ubuntu 20.04 и 22.04 (чистая установка)
# Версия: 1.0 
# =============================================================================

# Логи вывод
log_info() {
    echo -e "[INFO] $1"
}

# логи ошибок
log_error() {
    echo -e "[ERROR] $1" >&2
}

# Проверка рут
check_root() {
    if [ "$EUID" -ne 0 ]; then
        log_error "Скрипт должен быть запущен с правами root (через sudo или от root)."
        exit 1
    fi
}

# Установщик
install_packages() {
    log_info "Обновление репозиториев и установка необходимых пакетов..."
    apt-get update
    apt-get upgrade -y
    apt-get install -y htop net-tools mtr dnsmasq network-manager wireguard openvpn apache2 php git iptables-persistent openssh-server resolvconf speedtest-cli nload libapache2-mod-php wget ufw
    if [ $? -ne 0 ]; then
        log_error "Ошибка установки пакетов. Проверьте доступ к интернету и повторите попытку."
        exit 1
    fi

    # обнаружение openvswitch-switch и удаление
    if dpkg -l | grep -q openvswitch-switch; then
        log_info "Обнаружен пакет openvswitch-switch, выполняю его удаление..."
        systemctl stop openvswitch-switch
        systemctl disable openvswitch-switch
        apt-get purge -y openvswitch-switch
    fi
}


# Получение списка интерфейсов
select_interfaces() {
    log_info "Получаю список сетевых интерфейсов..."
    # Вывод списка с айпи адресами
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
        log_error "Некорректный выбор входящего интерфейса."
        exit 1
    fi

    read -p "Введите номер ВЫХОДЯЩЕГО интерфейса (локальная сеть): " out_num
    OUT_IF="${interfaces_array[$out_num]}"
    if [ -z "$OUT_IF" ]; then
        log_error "Некорректный выбор выходящего интерфейса."
        exit 1
    fi

    log_info "Выбран входящий интерфейс: $IN_IF"
    log_info "Выбран выходящий интерфейс: $OUT_IF"

    # Запрос локального IP для локальной сети (по умолчанию 192.168.1.1)
    read -p "Использовать стандартный локальный IP-адрес (192.168.1.1)? [y/n]: " use_default
    if [ "$use_default" == "n" ]; then
        read -p "Введите новый локальный IP-адрес в формате 192.168.X.1: " LOCAL_IP
        if [[ ! $LOCAL_IP =~ ^192\.168\.[0-9]{1,3}\.1$ ]]; then
            log_error "Неверный формат локального IP. Должен быть вида 192.168.X.1"
            exit 1
        fi
    else
        LOCAL_IP="192.168.1.1"
    fi
    log_info "Локальный IP для локальной сети: $LOCAL_IP"
}

# Настройки netplan
configure_netplan() {
    log_info "Настраиваю сетевые подключения через netplan..."
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
        log_error "Неверный выбор варианта настройки сети."
        exit 1
    fi

    # Применяем настройку netplan
    netplan apply
    log_info "Настройки netplan применены. Жду 10 секунд для стабилизации..."
    sleep 10

    # Проверка интернет-соединения
    log_info "Проверяю доступ в интернет..."
    response=$(curl -s -o /dev/null -w "%{http_code}" http://www.google.com)
    if [ "$response" -ne 200 ]; then
        log_error "Ошибка: нет доступа в интернет. Проверьте подключение."
        exit 1
    fi
    log_info "Интернет-соединение успешно установлено."
}

# Функция настройки DNS
configure_dns() {
    log_info "Настраиваю DNS..."
    RESOLV_BASE="/etc/resolvconf/resolv.conf.d/base"
    RESOLV="/etc/resolv.conf"
    # Добавляем записи (можно изменить при необходимости)
    for dns in "nameserver 8.8.8.8" "nameserver 8.8.4.4"; do
        grep -qxF "$dns" "$RESOLV_BASE" || echo "$dns" >> "$RESOLV_BASE"
        grep -qxF "$dns" "$RESOLV" || echo "$dns" >> "$RESOLV"
    done
    resolvconf -u
    systemctl restart systemd-resolved
    log_info "DNS настроены."
}

# Функция настройки SSH (разрешение root)
configure_ssh() {
    log_info "Настраиваю SSH (разрешаю root-доступ)..."
    sed -i 's/#\?PermitRootLogin .*/PermitRootLogin yes/' /etc/ssh/sshd_config
    systemctl restart ssh || systemctl restart sshd
    ufw allow OpenSSH
    log_info "SSH настроен."
}

# Функция настройки DHCP-сервера (dnsmasq)
configure_dhcp() {
    log_info "Настраиваю DHCP-сервер (dnsmasq)..."
    CONFIG_FILE="/etc/dnsmasq.conf"
    # Резервное копирование исходного файла (если существует)
    [ -f "$CONFIG_FILE" ] && cp "$CONFIG_FILE" "${CONFIG_FILE}.bak"

    cat <<EOF > "$CONFIG_FILE"
dhcp-authoritative
domain=local.lan
listen-address=127.0.0.1,$LOCAL_IP
dhcp-range=${LOCAL_IP%.*}.2,${LOCAL_IP%.*}.254,255.255.255.0,12h
server=8.8.8.8
server=8.8.4.4
cache-size=10000
EOF

    systemctl stop systemd-resolved
    systemctl disable systemd-resolved
    systemctl restart dnsmasq
    systemctl enable dnsmasq
    log_info "DHCP-сервер настроен."
}

# Функция настройки iptables и NAT
configure_iptables() {
    log_info "Настраиваю iptables (MASQUERADE)..."
    # Разрешаем пересылку пакетов
    sed -i '/^#.*net.ipv4.ip_forward/s/^#//' /etc/sysctl.conf
    sysctl -p

    # Добавляем правило NAT для интерфейса (предполагается, что VPN-интерфейс будет называться tun0)
    iptables -t nat -A POSTROUTING -o tun0 -s ${LOCAL_IP%.*}.0/24 -j MASQUERADE
    iptables-save > /etc/iptables/rules.v4
    log_info "iptables настроены."
}

# Функция настройки VPN (открываем автозапуск OpenVPN)
configure_vpn() {
    log_info "Настраиваю VPN (OpenVPN)..."
    sed -i '/^#\s*AUTOSTART="all"/s/^#\s*//' /etc/default/openvpn
    log_info "VPN настроен."
}

# Функция настройки веб-интерфейса
configure_web_interface() {
    log_info "Настраиваю веб-интерфейс для управления VPN..."

    # Изменяем права доступа к конфигурационным каталогам
    chmod -R 755 /etc/openvpn /etc/wireguard
    chown -R www-data:www-data /etc/openvpn /etc/wireguard

    # Добавляем разрешения для пользователя www-data (запись sudoers)
    cat <<EOF >> /etc/sudoers
www-data ALL=(ALL) NOPASSWD: /bin/systemctl stop openvpn*, /bin/systemctl start openvpn*
www-data ALL=(ALL) NOPASSWD: /bin/systemctl stop wg-quick*, /bin/systemctl start wg-quick*
EOF

    # Открываем порт 80 в iptables и сохраняем правила
    iptables -A INPUT -p tcp --dport 80 -j ACCEPT
    iptables-save > /etc/iptables/rules.v4

    # Удаляем старый сайт (если есть) и клонируем репозиторий веб-интерфейса
    rm -rf /var/www/html
    git clone https://github.com/Rostarc/VPN-Web-Installer.git /var/www/html

    # Настраиваем права для Apache
    chown -R www-data:www-data /var/www/html
    chmod -R 755 /var/www/html

    # Создаём .htaccess для ограничения доступа (разрешён доступ только с локальной сети)
    cat <<EOF > /var/www/html/.htaccess
<RequireAll>
    Require ip 192.168
</RequireAll>
EOF

    # Включаем модуль rewrite для Apache и перезапускаем его
    a2enmod rewrite
    systemctl restart apache2
    log_info "Веб-интерфейс настроен. Доступен по http://$LOCAL_IP/"
}

# Функция удаления настроек (откат)
remove_configuration() {
    log_info "Удаляю ранее настроенные компоненты..."

    # Остановка служб
    systemctl stop openvpn@client1.service wg-quick@tun0.service dnsmasq apache2 2>/dev/null
    systemctl disable openvpn@client1.service wg-quick@tun0.service

    # Удаление конфигурационных каталогов и файлов
    rm -rf /etc/openvpn /etc/wireguard /var/www/html /etc/dnsmasq.conf
    rm -f /etc/netplan/01-network-manager-all.yaml
    rm -f /etc/systemd/system/vpn-update.service /etc/systemd/system/vpn-update.timer

    # Удаление пакетов OpenVPN и WireGuard (опционально)
    apt-get purge -y openvpn wireguard
    apt-get autoremove -y

    # Очистка iptables
    iptables -t nat -D POSTROUTING -o tun0 -s ${LOCAL_IP%.*}.0/24 -j MASQUERADE 2>/dev/null
    iptables-save > /etc/iptables/rules.v4

    log_info "Все настройки удалены. Вы можете запустить установку заново."
}

# --- Основная часть скрипта ---
check_root

# МЕНЮ
echo ""
echo "        .^~!!!~.                                                             .J:                    "
echo "       ?5777~!?P7 ..    .    ::    . ::           .    .   ::.   . .:.    .:.:@~   :::    . :.      "
echo "      Y5.JY7YG ~&.:B!  7G 7BJ?JG~ ~#J?JG~        :B7  7B.~5?7YY. PP??PY  7G??5@~ ~PJ?JP~ ~#YJ7      "
echo "     ^&.?#  P5 7B. ?#.:&~ J#   YB !&:  G5         7&::#! &5!7?#^ BY  ~@:.@!  :&~ &?   Y# ~@^        "
echo "     ^&:~P??Y5?5^   5GGJ  ?&~.:G5 !&.  PP          YGGY  GP^:^^  #J  ^@: #Y.:?@~ GP:.^GY !@.        "
echo "      JP7~~^^~.     .J?   J#7?J7  ^J.  7!          .JJ   .7???!  ?~  :J. :?J?!?: .7J??!  :J.        "
echo "       :~!77!~            7P             :??????J^                                                  "
echo ""
echo "=============================================="
echo "  Установка VPN-сервера с веб-интерфейсом (v1.0)"
echo "=============================================="
echo ""
echo "Выберите действие:"
echo "1) Установить и настроить сервер"
echo "2) Удалить все настройки сервера"
echo ""
read -p "Ваш выбор [1/2]: " action_choice

if [ "$action_choice" == "2" ]; then
    remove_configuration
    exit 0
elif [ "$action_choice" != "1" ]; then
    log_error "Неверный выбор. Выберите 1 или 2."
    exit 1
fi

# Выполнение установки
install_packages
select_interfaces
configure_netplan
configure_dns
configure_ssh
configure_dhcp
configure_iptables
configure_vpn
configure_web_interface

log_info "Установка завершена успешно!"
echo ""
echo "После перезагрузки сервера все настройки будут применены."
echo "Удачи!"

exit 0
