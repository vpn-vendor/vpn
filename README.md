# VPN-Setup-Script

Этот скрипт помогает вам выполнить автоматическую настройку сервера для использования VPN конфигураций, а также легкую замену VPN через ваш собственный локальный веб-сайт. 

Скрипт тестировался и работает на:
- Ubuntu 20.04
- Ubuntu 22.04


# Установка
Скопируйте эту комнду и следуйте инструкциям чтобы выполнить скрипт на своем оборудовании:
```bash
cd ~
```
```bash
wget https://raw.githubusercontent.com/Rostarc/VPN-Setup-Script/main/VPN-Setup-Ubuntu20.04-22.04.sh -O VPN-Setup-Ubuntu20.04-22.04.sh && sudo bash VPN-Setup-Ubuntu20.04-22.04.sh
```

Есть более укороченная команда
```bash
wget https://raw.githubusercontent.com/Rostarc/VPN-Setup-Script/main/VPN.sh -O VPN.sh && sudo bash VPN.sh
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
- ufw

# Контакты и сотрудничество
Всегда готов обсудить условия для работы с вами и вашими решениями.

Есть VPN-конфигурации для ваших linux серверов, а также Windows/MacOs и Android/Ios.

Обращайтесь за помощью/вопросами в телеграмм - https://t.me/vpn_vendor
