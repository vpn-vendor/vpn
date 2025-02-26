# VPN-Setup-Script v2.1.0

Этот скрипт помогает вам выполнить автоматическую настройку сервера для использования VPN конфигураций, а также легкую замену VPN через ваш собственный локальный веб-сайт. 

Скрипт тестировался и работает на:
- Ubuntu 20.04
- Ubuntu 22.04
- Ubuntu 24.04
- Linux Mint


# Установка
Скопируйте эту команду и следуйте инструкциям чтобы выполнить скрипт на своем оборудовании:
```bash
cd ~
```
Скачиваем и запускаем скрипт
```bash
wget https://raw.githubusercontent.com/Rostarc/vpn/main/vpn.sh -O vpn.sh && sudo bash vpn.sh
```
Еще бывает такая проблема -
"Will not apply HSTS... HSTS database must be a regular and non-world-writable file"
Исправляется она вот так
```bash
rm -f ~/.wget-hsts
```


# Программы
Скрипт выполняет автоматическое обновление системы и установка таких программ:
- htop
- net-tools
- isc-dhcp-server
- network-manager
- speedtest-cli
- nload
- mtr
- wireguard
- openvpn
- apache2
- git
- iptables-persistent
- openssh-server
- resolvconf

Скрипт так же выполняет удаление таких программ в случае обнаружения:
- dnsmasq
- openvswitch-switch

# Контакты и сотрудничество
Всегда готов обсудить условия для работы с вами и вашими решениями.

Есть VPN-конфигурации для ваших linux серверов, а также Windows/MacOs и Android/Ios.

Обращайтесь за помощью/вопросами в телеграмм - https://t.me/vpn_vendor
