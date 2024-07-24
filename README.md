# VPN-Setup-Script

Этот скрипт помогает вам выполнить автоматическую настройку сервера для использования VPN конфигураций, а также легкую замену VPN через ваш собственный локальный веб-сайт. 

Скрипт тестировался на:
- Ubuntu 20.04
- Ubuntu 22.04


# Устновка
Скопируйте эту комнду и следуйте инструкциям чтобы выполнить скрипт на своем оборудовании:
```bash
curl -O https://raw.githubusercontent.com/Rostarc/VPN-Setup-Script/main/VPN-Setup-Ubuntu20.04-22.04.sh && sudo bash VPN-Setup-Ubuntu20.04-22.04.sh
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
