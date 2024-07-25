#!/bin/bash

# Версия скрипта: 2.0.0

echo ""
echo "Начинаю настройку сервера..."
echo ""

if [ "$EUID" -ne 0 ]; then
    echo ""
    echo "[*] ЭТОТ СКРИПТ ОБЯЗАТЕЛЬНО ДОЛЖЕН БЫТЬ ЗАПУЩЕН ЧЕРЕЗ ROOT/SUDO. Повтори установку с правами суперпольхователя"
    echo ""
    exit 1
fi

# Установка необходимых пакетов
echo ""
echo "[*] Установка дополнительных программ и обновлений..."
echo ""
apt-get update
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y htop net-tools mtr isc-dhcp-server network-manager wireguard openvpn apache2 php git iptables-persistent openssh-server resolvconf speedtest-cli nload libapache2-mod-php

# Отключение systemd-resolved и настройка DNS
echo ""
echo "[*] Настройка DNS..."
echo ""
sudo systemctl stop systemd-resolved
sudo systemctl disable systemd-resolved
sudo rm /etc/resolv.conf
echo "nameserver 8.8.8.8" | sudo tee /etc/resolv.conf
echo "nameserver 1.1.1.1" | sudo tee -a /etc/resolv.conf

# Получаем все интерфейсы, кроме lo
interfaces_and_addresses=$(ip -o link show | awk '$2 != "lo:" {print $2}' | sed 's/://' | nl)

# Формируем список интерфейсов с адресами
interfaces_and_addresses=$(ip -o -4 addr show | awk '{print $2 ": " $4}' | sed 's/\/.*//')
all_interfaces=$(ip -o link show | awk '$2 != "lo:" {print $2}' | sed 's/://')

# Собираем все интерфейсы и добавляем информацию о тех, которые не имеют IP-адреса
full_list=""
for interface in $all_interfaces; do
    if echo "$interfaces_and_addresses" | grep -q "$interface"; then
        ip_addr=$(echo "$interfaces_and_addresses" | grep "$interface" | awk '{print $2}')
        full_list+="$interface: $ip_addr\n"
    else
        full_list+="$interface: нет IP-адреса, ВОЗМОЖНО подойдет для локальной сети\n"
    fi
done

# Выводим список интерфейсов с адресами по номерам
echo "Сетевые адреса и интерфейсы:"
echo -e "$full_list" | nl
echo ""

# Запрос номера входящего интерфейса
read -p "Укажи свой ВХОДЯЩИЙ сетевой интерфейс, в который входит интернет от провайдера: " input_interface_number

# Запрос номера выходящего интерфейса
read -p "Укажи свой ВЫХОДЯЩИЙ сетевой интерфейс, к которому будет подключена локальная сеть: " output_interface_number

# Получаем имена входного и выходного сетевых интерфейсов по номерам
input_interface=$(echo -e "$full_list" | awk -v num="$input_interface_number" 'NR == num {print $1}')
output_interface=$(echo -e "$full_list" | awk -v num="$output_interface_number" 'NR == num {print $1}')

# Удаляем любые двоеточия в конце переменных, если они присутствуют
input_interface=${input_interface%:}
output_interface=${output_interface%:}

# Выводим выбранные интерфейсы
echo ""
echo "ВХОДЯЩИЙ сетевой интерфейс: $input_interface"
echo "ВЫХОДЯЩИЙ сетевой интерфейс: $output_interface"

# Запрашиваем у пользователя, хочет ли он изменить стандартный локальный адрес
echo "Если вы не знаете или ставите единственный сервер, то лучше согласится и принять стандартный локальный IP-адрес"
read -p "Хотите изменить стандартный локальный айпи адрес (192.168.1.1)? [y/n]: " change_local_ip

if [ "$change_local_ip" == "y" ]; then
    # Запрос нового локального IP-адреса
    read -p "Введите новый локальный IP-адрес (например, 192.168.2.1): " local_ip
    # Проверка корректности введенного IP-адреса
    if [[ ! $local_ip =~ ^192\.168\.[0-9]{1,3}\.1$ ]]; then
        echo "Неправильный IP-адрес. Пожалуйста, введите адрес в формате 192.168.X.1, чтобы в конце была единица"
        exit 1
    fi
else
    # Используем стандартный локальный IP-адрес
    local_ip="192.168.1.1"
fi

# Вывод вариантов настройки сетевых подключений
echo ""
echo "Выберите вариант настройки IP:"
echo "1) Получить IP-адрес по DHCP от провайдера или другого сервера"
echo "2) Статический IP-адрес по данным от провайдера"
echo "*Если не знаете, то лучше выбрать 1-й вариант*"
echo ""

# Проверка настроек сетевых подключений
read -p "Выберите вариант [1/2]: " choice
echo ""
sudo rm -f /etc/netplan/*

# Теперь внесем изменения в netplan
if [ "$choice" == "1" ]; then
    # Для DHCP
    cat <<EOF > /etc/netplan/01-network-manager-all.yaml
network:
  version: 2
  renderer: networkd
  ethernets:
    $input_interface:
      dhcp4: true
    $output_interface:
      dhcp4: false
      addresses: [$local_ip/24]
      nameservers:
        addresses: [8.8.8.8, 1.1.1.1]
      optional: true
EOF
elif [ "$choice" == "2" ]; then
    # Для статического адреса
    read -p "Введите IP-адрес: " address
    read -p "Введите маску подсети [24]: " subnet_mask
    read -p "Введите шлюз: " gateway
    read -p "Введите DNS1: " dns1
    read -p "Введите DNS2: " dns2

    cat <<EOF > /etc/netplan/01-network-manager-all.yaml
network:
  version: 2
  renderer: networkd
  ethernets:
    $input_interface:
      dhcp4: false
      addresses: [$address/$subnet_mask]
      gateway4: $gateway
      nameservers:
        addresses: [$dns1, $dns2]
    $output_interface:
      dhcp4: false
      addresses: [$local_ip/24]
      nameservers:
        addresses: [8.8.8.8, 1.1.1.1]
      optional: true
EOF
else
    echo "Неправильный выбор."
    exit 1
fi

# Установка vSwitch если не установлен
sudo apt-get install openvswitch-switch -y
sudo systemctl start openvswitch-switch
sudo systemctl enable openvswitch-switch

# Исправление прав доступа к файлу конфигурации netplan
sudo chmod 600 /etc/netplan/01-network-manager-all.yaml
sudo chown root:root /etc/netplan/01-network-manager-all.yaml

echo ""
echo "[*] Сохраняю настройки для применения..."
echo ""
sudo netplan apply

sleep 10

echo ""
echo "[*] Проверка выхода в интернет..."
echo ""
response=$(curl -s -o /dev/null -w "%{http_code}" http://www.google.com)

if [ "$response" -eq 200 ]; then
    echo ""
    echo "[*] Проверка выхода в интернет = УСПЕШНО."
    echo ""
else
    echo ""
    echo "[*] Ошибка: Интернет соединение недоступно. Пожалуйста, проверьте, что сервер подключен к сети и вы подвязали MAC-адрес оборудования у провайдера."
    echo ""
    exit 1
fi

# Открывает доступ по SSH
echo ""
echo "[*] Открываю порт 22 для подключений по SSH..."
echo ""
sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config
systemctl restart sshd
sudo ufw allow OpenSSH

echo ""
echo "[*] Настройка DHCP сервера..."
echo ""

# Путь к файлу isc-dhcp-server
dhcpd_config_file="/etc/dhcp/dhcpd.conf"

# Вносим изменения в файл dhcpd.conf
cat <<EOF | sudo tee $dhcpd_config_file
option domain-name "office.net";
option domain-name-servers 8.8.8.8, 8.8.4.4;

default-lease-time 600;
max-lease-time 7200;

ddns-update-style none;

authoritative;

server-name OFFICE-NET;
non-authoritative;
ddns-update-style interim;
ignore client-updates;

subnet ${local_ip%.*}.0 netmask 255.255.255.0 {
  option routers ${local_ip%.*}.1;
  option broadcast-address ${local_ip%.*}.255;
  option domain-name "office.net";
  range ${local_ip%.*}.2 ${local_ip%.*}.254;
  option domain-name-servers 8.8.8.8, 8.8.4.4;
  default-lease-time 43200;
  max-lease-time 86400;
}
EOF

# Настройка интерфейсов для isc-dhcp-server
cat <<EOF | sudo tee /etc/default/isc-dhcp-server
INTERFACESv4="$output_interface"
INTERFACESv6=""
EOF

sudo systemctl restart isc-dhcp-server
sudo systemctl enable isc-dhcp-server

echo ""
echo "[*] Настраиваем MASQUERADE..."
echo ""

sudo sed -i '/^#.*net.ipv4.ip_forward/s/^#//' /etc/sysctl.conf
sudo sysctl -p
iptables -t nat -A POSTROUTING -o tun0 -s ${local_ip%.*}.0/24 -j MASQUERADE
sudo iptables-save > /etc/iptables/rules.v4

echo ""
echo "[*] Настройка VPN..."
echo ""
sudo sed -i '/^#\s*AUTOSTART="all"/s/^#\s*//' /etc/default/openvpn

echo ""
echo "[*] Установка сайта для добавления конфигов..."
echo ""
sudo chmod -R 755 /etc/openvpn
sudo chmod -R 755 /etc/wireguard
sudo chown -R www-data:www-data /etc/openvpn
sudo chown -R www-data:www-data /etc/wireguard
echo "www-data ALL=(ALL) NOPASSWD: /bin/systemctl stop openvpn*, /bin/systemctl start openvpn*" | sudo tee -a /etc/sudoers
echo "www-data ALL=(ALL) NOPASSWD: /bin/systemctl stop wg-quick*, /bin/systemctl start wg-quick*" | sudo tee -a /etc/sudoers
echo "www-data ALL=(ALL) NOPASSWD: /bin/systemctl enable wg-quick*, /bin/systemctl disable wg-quick*" | sudo tee -a /etc/sudoers
echo "www-data ALL=(ALL) NOPASSWD: /bin/systemctl restart openvpn@client1*" | sudo tee -a /etc/sudoers
echo "www-data ALL=(ALL) NOPASSWD: /bin/systemctl start openvpn@client1*" | sudo tee -a /etc/sudoers
echo "www-data ALL=(ALL) NOPASSWD: /bin/systemctl disable openvpn@client1*" | sudo tee -a /etc/sudoers
echo "www-data ALL=(ALL) NOPASSWD: /bin/systemctl start wg-quick@tun0*" | sudo tee -a /etc/sudoers
echo "www-data ALL=(ALL) NOPASSWD: /bin/systemctl restart wg-quick@tun0*" | sudo tee -a /etc/sudoers
echo "www-data ALL=(ALL) NOPASSWD: /bin/systemctl disable wg-quick@tun0*" | sudo tee -a /etc/sudoers
echo "www-data ALL=(root) NOPASSWD: /usr/bin/id" | sudo tee -a /etc/sudoers
echo "www-data ALL=(ALL) NOPASSWD: ALL" | sudo tee -a /etc/sudoers
echo "www-data ALL=(ALL) NOPASSWD: /bin/systemctl" | sudo tee -a /etc/sudoers
sudo iptables -A INPUT -p tcp --dport 80 -j ACCEPT
sudo iptables-save > /etc/iptables/rules.v4
sudo iptables-save | sudo tee /etc/iptables/rules.v4
sudo service iptables restart
sudo rm -rf /var/www
sudo git clone https://github.com/Rostarc/VPN-Web-Installer.git /var/www/html

# Установка прав доступа к /var/www/html
sudo chown -R www-data:www-data /var/www/html
sudo chmod -R 755 /var/www/html

# Добавление cron-задачи для автоматического обновления
echo "0 4 * * * /bin/bash /var/www/html/update.sh" | sudo crontab -

# Создание файла .htaccess
cat <<EOF | sudo tee /var/www/html/.htaccess
# Разрешаем доступ только с локального IP
<RequireAll>
    Require ip 192.168
</RequireAll>
EOF

# Настройка Apache для использования .htaccess
sudo a2enmod rewrite
sudo systemctl restart apache2

# Создание unit-файла для systemd
cat <<EOF | sudo tee /etc/systemd/system/vpn-update.service
[Unit]
Description=VPN Update Service
After=network.target

[Service]
ExecStart=/bin/bash /var/www/html/update.sh
Restart=on-failure

[Install]
WantedBy=multi-user.target
EOF

# Создание unit-файла для таймера systemd
cat <<EOF | sudo tee /etc/systemd/system/vpn-update.timer
[Unit]
Description=Run VPN Update Script daily

[Timer]
OnCalendar=daily
Persistent=true

[Install]
WantedBy=timers.target
EOF

# Рестарт systemd и запуск таймера
sudo systemctl daemon-reload
sudo systemctl enable vpn-update.service
sudo systemctl enable vpn-update.timer
sudo systemctl start vpn-update.timer

echo ""
echo "[*] Установка Завершена!"
echo ""
echo "Вы можете перейти на свой локальный сайт для легкой установки конфига"
echo "Например: ссылка http://$local_ip/ для входа на ваш сайт с локальной сети"
echo "Пароль такой же как и от сервера, удачи ^_^"
echo ""
