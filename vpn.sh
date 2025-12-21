#!/bin/bash
# ==============================================================================
#
#   Скрипт автоматической настройки VPN-сервера
#   Поддерживаемая ОС: ТОЛЬКО Ubuntu 22.04 LTS (чистая установка с флешки) !!!
#
# ==============================================================================
#
#   Версия: 2.5.5
#
#   [~] Апгрейд configure_dhcp:
#         - Полная оптимизация под VoIP.
#         - Добавлен авто-рестарт службы.
#         - Используются прямые внешние DNS запросы уменьшающие задежку (mc) важную для VoIP.
#   [~] Улучшение configure_iptables:
#         - Ядро перенастроено полностью под VoIP.
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
    log_info "Запуск предварительной проверки системы..."

    # 1. Проверка прав root
    if [ "$EUID" -ne 0 ]; then
        error_exit "Скрипт НУЖНО запустить с правами root (через sudo или от root)!!!"
    fi

    # 2. Изолированная проверка ОС
    if [ -f /etc/os-release ]; then
        local os_name=$(grep -E "^ID=" /etc/os-release | cut -d= -f2 | tr -d '"')
        local os_version=$(grep -E "^VERSION_ID=" /etc/os-release | cut -d= -f2 | tr -d '"')

        if [[ "${os_name,,}" == "ubuntu" ]] && [[ "$os_version" == "22.04"* ]]; then
            log_info "Система подтверждена: Ubuntu $os_version."
        else
            error_exit "Неподдерживаемая ОС ($os_name $os_version). Требуется Ubuntu 22.04."
        fi
    else
        error_exit "Файл /etc/os-release не найден. Невозможно определить ОС."
    fi

    # 3. Dependency Check
    local required_tools=("curl" "grep" "awk" "sed" "ip" "systemctl")
    local missing_tools=()

    for tool in "${required_tools[@]}"; do
        if ! command -v "$tool" &> /dev/null; then
            missing_tools+=("$tool")
        fi
    done

    if [ ${#missing_tools[@]} -ne 0 ]; then
        log_error "Отсутствуют необходимые системные утилиты: ${missing_tools[*]}"
        log_info "Пытаюсь установить базовые утилиты..."
        apt-get update -qq && apt-get install -y -qq "${missing_tools[@]}" || error_exit "Не удалось установить базовые зависимости."
    fi

    # 4. Anti-Lock Mechanism
    if fuser /var/lib/dpkg/lock-frontend >/dev/null 2>&1 || fuser /var/lib/dpkg/lock >/dev/null 2>&1; then
        log_info "Обнаружена блокировка APT (фоновые обновления). Ожидание освобождения..."
        local wait_counter=0
        while fuser /var/lib/dpkg/lock-frontend >/dev/null 2>&1 || fuser /var/lib/dpkg/lock >/dev/null 2>&1; do
            sleep 5
            wait_counter=$((wait_counter+5))
            if [ "$wait_counter" -ge 300 ]; then
                error_exit "APT заблокирован слишком долго (>5 минут). Попробуйте перезагрузить сервер."
            fi
            printf "\rОжидание завершения системных процессов... %ds" "$wait_counter"
        done
        echo "" # Перенос строки после счетчика
        log_info "Блокировка APT снята. Продолжаем."
    fi

    log_info "Предварительная проверка системы пройдена успешно."
}

# Переключение на systemd-networkd
configure_network_services() {
    log_info "Инициализация перехода на systemd-networkd..."

    # 1. Мягкая остановка и полная блокировка NetworkManager
    if systemctl is-active --quiet NetworkManager; then
        log_info "Останавливаю NetworkManager..."
        systemctl stop NetworkManager.service 2>/dev/null
    fi
    
    if systemctl is-enabled --quiet NetworkManager; then
        systemctl disable NetworkManager.service 2>/dev/null
        systemctl mask NetworkManager.service 2>/dev/null || log_info "Не удалось замаскировать NetworkManager (не критичная ошибка)"
        log_info "NetworkManager отключен и замаскирован."
    else
        log_info "NetworkManager уже отключен или отсутствует."
    fi

    # 2. Включение systemd-networkd
    if ! systemctl is-active --quiet systemd-networkd; then
        systemctl enable systemd-networkd.service || error_exit "Не удалось включить systemd-networkd"
        systemctl start systemd-networkd.service || error_exit "Не удалось запустить systemd-networkd"
        log_info "Служба systemd-networkd запущена."
    else
        log_info "systemd-networkd уже работает."
    fi

    # 3. Включение systemd-resolved
    if ! systemctl is-active --quiet systemd-resolved; then
        systemctl enable systemd-resolved.service
        systemctl start systemd-resolved.service
        log_info "Служба systemd-resolved (DNS) запущена."
    fi

    # 4. Исправление симлинка resolv.conf
    if [ -L /etc/resolv.conf ] && [ "$(readlink /etc/resolv.conf)" != "/run/systemd/resolve/stub-resolv.conf" ]; then
        log_info "Корректировка симлинка /etc/resolv.conf..."
        ln -sf /run/systemd/resolve/stub-resolv.conf /etc/resolv.conf
    fi

    log_info "Службы сетевого управления подготовлены."
}

# Установщик пакетов
install_packages() {
    log_info "Инициализация системы пакетов..."

    # 1. Очистка конфликтующего ПО
    local conflict_packages=("dnsmasq" "openvswitch-switch" "netplan.io") 
    
    for pkg in "dnsmasq" "openvswitch-switch"; do
        if dpkg -l | grep -qw "$pkg"; then
            log_info "Обнаружен конфликтующий пакет: $pkg. Удаляю..."
            systemctl stop "$pkg" 2>/dev/null
            systemctl disable "$pkg" 2>/dev/null
            apt-get purge -y -qq "$pkg" || log_error "Ошибка при удалении $pkg (возможно уже удален)"
        fi
    done

    # 2. Обновление списка пакетов
    log_info "Обновление репозиториев..."
    local update_success=0
    for i in {1..3}; do
        if apt-get update -qq; then
            update_success=1
            break
        fi
        log_info "Попытка обновления $i не удалась. Жду 5 секунд..."
        sleep 5
    done

    if [ $update_success -eq 0 ]; then
        error_exit "Критическая ошибка: Не удалось обновить список пакетов (проверьте интернет/DNS)."
    fi

    # 3. Автоматизация ответов
    echo iptables-persistent iptables-persistent/autosave_v4 boolean true | debconf-set-selections
    echo iptables-persistent iptables-persistent/autosave_v6 boolean true | debconf-set-selections

    # 4. Обновление системы (Silent Upgrade)
    log_info "Запуск полного обновления системы (может занять время)..."
    apt-get -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold" upgrade -y -qq || error_exit "Ошибка обновления системы"

    # 5. Установка пакетов
    log_info "Установка необходимых пакетов..."
    local packages=(
        "ppp" "net-tools" "mtr" "wireguard" "openvpn" "apache2" "php" "git"
        "iptables-persistent" "openssh-server" "resolvconf" "speedtest-cli"
        "nload" "libapache2-mod-php" "isc-dhcp-server" "iperf3"
        "libapache2-mod-authnz-pam" "shellinabox" "dos2unix"
        "python3-venv" "python3.10-venv" "debconf-utils"
    )

    apt-get -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold" install -y -qq "${packages[@]}" || error_exit "Ошибка установки пакетов."
    log_info "Пакеты успешно установлены."

    # 6. Настройка модулей Apache
    if command -v a2enmod &> /dev/null; then
        a2enmod proxy proxy_http rewrite authnz_pam headers > /dev/null 2>&1
        systemctl restart apache2 || log_error "Apache перезапустится позже (сейчас не критично)"
    else
        error_exit "Apache не установлен корректно (нет a2enmod)."
    fi

    log_info "Установка и первичная настройка ПО завершена."
}

# Меню выбора режима настройки Netplan
preselect_interfaces() {
    log_info "Выбор режима настройки сети..."
    
    echo "------------------------------------------------"
    echo "Какое действие выполнить с настройками сети (NETPLAN)?"
    echo "1. [ПО УМОЛЧАНИЮ] Полная настройка с нуля (выбор интерфейсов, IP)."
    echo "2. Настроить ТОЛЬКО Netplan и выйти (без установки VPN)."
    echo "3. Пропустить настройку Netplan (использовать текущую конфигурацию)."
    echo "------------------------------------------------"

    # 1. Цикл валидации
    while true; do
        read -r -p "Ваш выбор [1/2/3]: " netplan_choice
        case "$netplan_choice" in
            1|2|3) break ;; # Корректный ввод, выход из цикла
            *) echo -e "${YELLOW}Пожалуйста, введите 1, 2 или 3.${NC}" ;;
        esac
    done

    case "$netplan_choice" in
        1)
            # Полная настройка
            select_interfaces
            configure_netplan
            ;;
        2)
            # Только настройка Netplan (Режим утилиты)
            configure_network_services
            select_interfaces
            configure_netplan
            echo -e "\n${GREEN}[OK]${NC} Настройка netplan выполнена. Перезагрузите сервер для применения."
            exit 0
            ;;
        3)
            # Пропуск настройки (Advanced Mode)
            log_info "Анализ текущей конфигурации сети..."
            
            # Попытка найти активный файл
            netplan_file=$(find /etc/netplan -maxdepth 1 -type f -name "*.yaml" ! -name "00-installer-config.yaml" | head -n 1)
            [ -z "$netplan_file" ] && netplan_file=$(find /etc/netplan -maxdepth 1 -type f -name "*.yaml" | head -n 1)

            if [ -z "$netplan_file" ]; then
                error_exit "Не найдены файлы конфигурации Netplan (.yaml). Выберите вариант 1."
            fi
            
            log_info "Используется файл конфигурации: $netplan_file"

            # 2. Парсинг
            # Извлекаем имена интерфейсов (убираем пробелы и двоеточия)
            local found_ifaces=$(grep -E "^[[:space:]]{2,4}[a-zA-Z0-9_-]+:$" "$netplan_file" | tr -d ': ')
            
            # Превращаем в массив
            readarray -t iface_array <<< "$found_ifaces"
            
            if [ ${#iface_array[@]} -lt 2 ]; then
                 error_exit "В файле $netplan_file найдено менее 2 интерфейсов. Скрипту нужен 1 WAN и 1 LAN. Настройте вручную (Вариант 1)."
            fi
            
            IN_IF="${iface_array[0]}"
            OUT_IF="${iface_array[1]}"
            
            # Попытка извлечь IP для LAN
            LOCAL_IP=$(grep -A 5 "$OUT_IF" "$netplan_file" | grep -oP 'addresses: \[\K[0-9.]+' || echo "")
            
            # 3. Валидация полученных данных
            if [ -z "$IN_IF" ] || [ -z "$OUT_IF" ]; then
                 error_exit "Не удалось определить интерфейсы автоматически. Используйте Вариант 1."
            fi
            
            if [ -z "$LOCAL_IP" ]; then
                log_info "Не удалось определить локальный IP из файла. Использую значение по умолчанию."
                LOCAL_IP="192.168.69.1"
            fi

            log_info "Определена конфигурация: WAN=$IN_IF, LAN=$OUT_IF, IP=$LOCAL_IP"
            ;;
    esac
}

# Выбор сетевых интерфейсов
select_interfaces() {
    log_info "Сканирование сетевых интерфейсов..."

    # 1. Сбор и отображение интерфейсов
    echo -e "${GREEN}Обнаруженные интерфейсы:${NC}"
    
    unset interfaces_array
    declare -A interfaces_array
    local count=0
    local full_list=""
    
    # Получаем список интерфейсов. Исключая lo, tun/wg и другие.
    local all_interfaces=$(ip -o link show | awk -F': ' '$2 !~ /^lo|^tun|^wg|^docker|^br/ {print $2}')

    if [ -z "$all_interfaces" ]; then
        error_exit "Не найдено физических сетевых интерфейсов!"
    fi

    for iface in $all_interfaces; do
        count=$((count+1))
        local ip_addr=$(ip -o -4 addr show "$iface" 2>/dev/null | awk '{print $4}' | cut -d'/' -f1)
        [ -z "$ip_addr" ] && ip_addr="(нет IP)"
        
        full_list+="$count) $iface : $ip_addr\n"
        interfaces_array[$count]="$iface"
    done
    
    echo -e "$full_list"
    echo ""

    # 2. Выбор ВХОДЯЩЕГО интерфейса (WAN)
    while true; do
        read -r -p "Введите номер ВХОДЯЩЕГО интерфейса (Интернет): " in_num
        if [[ "$in_num" =~ ^[0-9]+$ ]] && [ -n "${interfaces_array[$in_num]}" ]; then
            IN_IF="${interfaces_array[$in_num]}"
            break
        else
            echo -e "${YELLOW}Ошибка: Введите корректный номер из списка (1-$count).${NC}"
        fi
    done
    log_info "Выбран WAN интерфейс: $IN_IF"

    # 3. Выбор ВЫХОДЯЩЕГО интерфейса (LAN)
    while true; do
        read -r -p "Введите номер ВЫХОДЯЩЕГО интерфейса (Локальная сеть): " out_num
        
        if [[ "$out_num" =~ ^[0-9]+$ ]] && [ -n "${interfaces_array[$out_num]}" ]; then
            local selected_out="${interfaces_array[$out_num]}"
            
            # Проверка на конфликт
            if [ "$selected_out" == "$IN_IF" ]; then
                echo -e "${RED}Ошибка: Выходящий интерфейс не может совпадать с входящим ($IN_IF).${NC}"
                echo "Выберите другой порт для локальной сети."
            else
                OUT_IF="$selected_out"
                break
            fi
        else
            echo -e "${YELLOW}Ошибка: Введите корректный номер из списка.${NC}"
        fi
    done
    log_info "Выбран LAN интерфейс: $OUT_IF"

    # 4. Настройка локалки
    while true; do
        read -r -p "Использовать стандартный IP шлюза (192.168.69.1)? [y/n]: " use_default
        case "${use_default,,}" in
            y|yes|"") # Пустой ввод = да
                LOCAL_IP="192.168.69.1"
                break
                ;;
            n|no)
                # Ввод кастомного IP
                while true; do
                    read -r -p "Введите IP шлюза (строго формат 192.168.X.1): " user_ip
                    # Валидность
                    if [[ "$user_ip" =~ ^192\.168\.([0-9]{1,3})\.1$ ]]; then
                        octet="${BASH_REMATCH[1]}"
                        if [ "$octet" -ge 0 ] && [ "$octet" -le 255 ]; then
                            LOCAL_IP="$user_ip"
                            break 2
                        else
                            echo -e "${YELLOW}Ошибка: Октет $octet выходит за пределы 0-255.${NC}"
                        fi
                    else
                        echo -e "${YELLOW}Ошибка: Неверный формат. Требуется 192.168.X.1 (где X - число 0-255, например 192.168.101.1).${NC}"
                    fi
                done
                ;;
            *)
                echo -e "${YELLOW}Пожалуйста, введите буквой 'y' (да) или 'n' (нет).${NC}"
                ;;
        esac
    done

    log_info "Настройки сети приняты: WAN=$IN_IF, LAN=$OUT_IF, GW=$LOCAL_IP"
}

# Валидатор IP
validate_ip_format() {
    local ip=$1
    local stat=1
    if [[ $ip =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        OIFS=$IFS
        IFS='.'
        ip_arr=($ip)
        IFS=$OIFS
        [[ ${ip_arr[0]} -le 255 && ${ip_arr[1]} -le 255 && ${ip_arr[2]} -le 255 && ${ip_arr[3]} -le 255 ]]
        stat=$?
    fi
    return $stat
}

# Конвертатор
mask_to_cidr() {
    local mask=$1
    if [[ "$mask" =~ ^/?([0-9]{1,2})$ ]]; then
        echo "${BASH_REMATCH[1]}"
        return 0
    fi

    # Маски
    case $mask in
        "255.255.255.255") echo "32" ;;
        "255.255.255.252") echo "30" ;;
        "255.255.255.248") echo "29" ;;
        "255.255.255.240") echo "28" ;;
        "255.255.255.224") echo "27" ;;
        "255.255.255.192") echo "26" ;;
        "255.255.255.128") echo "25" ;;
        "255.255.255.0")   echo "24" ;;
        "255.255.254.0")   echo "23" ;;
        "255.255.252.0")   echo "22" ;;
        "255.255.248.0")   echo "21" ;;
        "255.255.240.0")   echo "20" ;;
        "255.255.192.0")   echo "18" ;;
        "255.255.128.0")   echo "17" ;;
        "255.255.0.0")     echo "16" ;;
        "255.0.0.0")       echo "8"  ;;
        *) echo "error" ;;
    esac
}

# Настройки netplan
configure_netplan() {
    log_info "Настройка конфигурации сети (Netplan)..."

    # 1. Отключение cloud-init (чтобы не перезаписывал настройки)
    local cloud_config_file="/etc/cloud/cloud.cfg.d/99-disable-network-config.cfg"
    if [ ! -f "$cloud_config_file" ]; then
        mkdir -p "$(dirname "$cloud_config_file")"
        echo "network: {config: disabled}" > "$cloud_config_file"
        log_info "Управление сетью cloud-init отключено."
    fi

    # 2. Резервное копирование старых конфигов
    local netplan_dir="/etc/netplan"
    local main_config_file="99-vpn-script.yaml"
    mkdir -p "$netplan_dir"
    
    # Если есть конфиги, бэкапим их
    if ls "$netplan_dir"/*.yaml 1> /dev/null 2>&1; then
        local backup_dir="$netplan_dir/backup_$(date +%F_%H%M%S)"
        mkdir -p "$backup_dir"
        log_info "Создаю резервную копию текущих настроек в $backup_dir"
        mv "$netplan_dir"/*.yaml "$backup_dir/" 2>/dev/null
    fi

    # 3. Выбор режима настройки
    echo "------------------------------------------------"
    echo "Выберите тип подключения для Входящего интерфейса ($IN_IF):"
    echo "1) DHCP (Автоматический IP от провайдера) [Рекомендуется]"
    echo "2) Статический IP (Ручной ввод IP, Маски, Шлюза)"
    echo "3) PPPoE (Логин и пароль)"
    echo "------------------------------------------------"
    
    local net_choice
    while true; do
        read -r -p "Ваш выбор [1/2/3]: " net_choice
        case "$net_choice" in
            1|2|3) break ;;
            *) echo -e "${YELLOW}Пожалуйста, введите 1, 2 или 3.${NC}" ;;
        esac
    done

    local yaml_content=""

    if [ "$net_choice" == "1" ]; then
        # === DHCP ===
        log_info "Выбран режим DHCP."
        yaml_content=$(cat <<EOF
network:
  version: 2
  renderer: networkd
  ethernets:
    $IN_IF:
      dhcp4: true
    $OUT_IF:
      dhcp4: false
      addresses: [$LOCAL_IP/24]
      optional: true
EOF
)
    elif [ "$net_choice" == "2" ]; then
        # === STATIC IP ===
        log_info "Выбран режим Статического IP. Следуйте подсказкам."

        # A. Ввод IP
        local STATIC_IP
        while true; do
            read -r -p "Введите Ваш статический IP (напр. 45.10.20.30): " STATIC_IP
            if validate_ip_format "$STATIC_IP"; then break; else echo -e "${RED}Неверный формат IP.${NC}"; fi
        done

        # B. Ввод Маски
        local INPUT_MASK
        local CIDR_MASK
        while true; do
            echo -e "Введите маску подсети."
            echo -e "Поддерживаются форматы: ${GREEN}24${NC}, ${GREEN}/24${NC} или ${GREEN}255.255.255.0${NC}"
            read -r -p "Маска: " INPUT_MASK
            
            CIDR_MASK=$(mask_to_cidr "$INPUT_MASK")
            
            if [ "$CIDR_MASK" == "error" ] || [ -z "$CIDR_MASK" ]; then
                echo -e "${RED}Не удалось распознать маску. Попробуйте формат 255.255.255.0 или 24.${NC}"
            else
                echo -e "Принята маска: /${CIDR_MASK}"
                break
            fi
        done

        # C. Ввод Шлюза
        local GATEWAY
        while true; do
            read -r -p "Введите основной шлюз (Gateway): " GATEWAY
            if validate_ip_format "$GATEWAY"; then break; else echo -e "${RED}Неверный формат IP шлюза.${NC}"; fi
        done

        # D. Ввод DNS
        local DNS1 DNS2
        while true; do
            read -r -p "Введите DNS сервер (по умолчанию 8.8.8.8): " DNS1
            [ -z "$DNS1" ] && DNS1="8.8.8.8"
            if validate_ip_format "$DNS1"; then break; else echo -e "${RED}Неверный формат IP DNS.${NC}"; fi
        done
        read -r -p "Введите второй DNS (не обязательно): " DNS2
        [ -n "$DNS2" ] && ! validate_ip_format "$DNS2" && DNS2="" # Сброс если кривой

        local dns_block="addresses: [$DNS1]"
        if [ -n "$DNS2" ]; then dns_block="addresses: [$DNS1, $DNS2]"; fi

        yaml_content=$(cat <<EOF
network:
  version: 2
  renderer: networkd
  ethernets:
    $IN_IF:
      dhcp4: false
      addresses: [$STATIC_IP/$CIDR_MASK]
      routes:
        - to: default
          via: $GATEWAY
      nameservers:
        $dns_block
    $OUT_IF:
      dhcp4: false
      addresses: [$LOCAL_IP/24]
      optional: true
EOF
)

    elif [ "$net_choice" == "3" ]; then
        # === PPPoE ===
        log_info "Выбран режим PPPoE."
        yaml_content=$(cat <<EOF
network:
  version: 2
  renderer: networkd
  ethernets:
    $IN_IF:
      dhcp4: no
      dhcp6: no
    $OUT_IF:
      dhcp4: false
      addresses: [$LOCAL_IP/24]
      optional: true
EOF
)
    fi

    # 4. Запись и Применение
    local config_path="$netplan_dir/$main_config_file"
    echo "$yaml_content" > "$config_path"
    chmod 600 "$config_path"

    log_info "Проверка синтаксиса конфигурации..."
    
    if netplan generate; then
        log_info "Синтаксис корректен. Применяю настройки..."
        netplan apply
        if [ $? -eq 0 ]; then
            log_info "Настройки сети успешно применены."
            echo -e "${YELLOW}Ожидание инициализации сети (10 сек)...${NC}"
            sleep 10
        else
            error_exit "Ошибка при выполнении 'netplan apply'. Проверьте настройки."
        fi
    else
        log_error "Сгенерирован некорректный файл Netplan! Откат изменений."
        rm -f "$config_path"
        if ls "$backup_dir"/*.yaml 1> /dev/null 2>&1; then
             mv "$backup_dir"/*.yaml "$netplan_dir/"
             netplan apply
        fi
        error_exit "Настройка сети прервана из-за внутренней ошибки валидации."
    fi
}

# Настройка PPPoE
configure_pppd_direct() {
    log_info "Настройка PPPoE-соединения..."
    
    if ! command -v pppd >/dev/null; then
        apt-get install -y ppp || error_exit "Не удалось установить ppp."
    fi

    local peer_file="/etc/ppp/peers/dsl-provider"

    # 1. Конфигурация
    cat <<EOF > "$peer_file"
plugin rp-pppoe.so $IN_IF
user "$PPPOE_USER"
noauth
hide-password
defaultroute
replacedefaultroute
noipdefault
persist
maxfail 0
holdoff 10
lcp-echo-interval 30
lcp-echo-failure 4
mtu 1492
mru 1492
usepeerdns
EOF
    
    if [ $? -ne 0 ]; then
        error_exit "Не удалось создать файл настроек $peer_file"
    fi
    log_info "Конфигурация провайдера создана"

    # 2. Сохранение паролей
    local secrets_entry="\"$PPPOE_USER\" * \"$PPPOE_PASS\" *"
    
    # Очистка старый записей
    sed -i "/^\"$PPPOE_USER\"/d" /etc/ppp/chap-secrets
    sed -i "/^\"$PPPOE_USER\"/d" /etc/ppp/pap-secrets

    (umask 077; echo "$secrets_entry" >> /etc/ppp/chap-secrets)
    (umask 077; echo "$secrets_entry" >> /etc/ppp/pap-secrets)
    
    log_info "Учетные данные PPPoE обновлены."

    # 3. Отключение Systemd
    if systemctl is-enabled --quiet ppp@dsl-provider.service; then
        systemctl disable ppp@dsl-provider.service >/dev/null 2>&1
        systemctl stop ppp@dsl-provider.service >/dev/null 2>&1
    fi

    rm -rf "/etc/systemd/system/ppp@dsl-provider.service.d"
    
    # 4. Cron
    local cron_file="/etc/crontab"
    
    # A. Задача на старт
    local boot_task="@reboot root sleep 20 && /usr/bin/pon dsl-provider"
    
    # B. Watchdog
    local watch_task="* * * * * root pgrep -f 'pppd call dsl-provider' > /dev/null || /usr/bin/pon dsl-provider"

    # Очистка старых задач
    sed -i '/dsl-provider/d' "$cron_file"
    
    # Добавление новых задач
    echo "$boot_task" >> "$cron_file"
    echo "$watch_task" >> "$cron_file"
    
    log_info "В Crontab добавлены задачи автозапуска (Delay 20s) и восстановления (Watchdog)."

    # 5. Первый запуск
    log_info "Инициализация соединения..."
    poff dsl-provider >/dev/null 2>&1
    sleep 2
    pon dsl-provider
    
    # 6. Ожидание интерфейса
    log_info "Ожидаю поднятия интерфейса ppp0..."
    local ppp_wait_time=0
    local max_wait=45
    
    while ! ip link show ppp0 &>/dev/null; do
        sleep 1
        ppp_wait_time=$((ppp_wait_time + 1))
        
        # Индикатор прогресса
        if (( ppp_wait_time % 5 == 0 )); then
            echo -n "."
        fi
        
        if [ "$ppp_wait_time" -ge "$max_wait" ]; then
            echo ""
            log_error "Таймаут ожидания ppp0 ($max_wait сек)."
            log_error "Возможные причины: неверный логин/пароль или нет линка на $IN_IF."
            log_error "Скрипт продолжит работу, но проверьте 'journalctl -xe' или 'plog'."
            return 0
        fi
    done
    
    echo ""
    log_info "Интерфейс ppp0 успешно поднят! IP: $(ip -4 addr show ppp0 | grep -oP '(?<=inet\s)\d+(\.\d+){3}')"
}

# Настройка DNS
configure_dns() {
    log_info "Настройка DNS (systemd-resolved)..."

    # 1. Сим-линк
    local target_resolv="/run/systemd/resolve/stub-resolv.conf"
    
    if [ "$(readlink /etc/resolv.conf)" != "$target_resolv" ]; then
        log_info "Обнаружен некорректный сим-линк /etc/resolv.conf. Исправляю..."
        # Бэкап
        if [ ! -L /etc/resolv.conf ] && [ -f /etc/resolv.conf ]; then
            mv /etc/resolv.conf /etc/resolv.conf.bak
        else
            rm -f /etc/resolv.conf
        fi
        ln -sf "$target_resolv" /etc/resolv.conf
    fi

    # 2. Конфиг
    cat <<EOF > /etc/systemd/resolved.conf
# Файл автоматически сгенериван скриптом vpn.sh
[Resolve]
FallbackDNS=8.8.8.8 1.1.1.1 2001:4860:4860::8888
# Локальный кеш - yes
Cache=yes
DNSStubListener=yes
MulticastDNS=no
EOF
    log_info "Конфигурация /etc/systemd/resolved.conf обновлена."

    # 3. Финал
    systemctl daemon-reload
    systemctl restart systemd-resolved || error_exit "Не удалось перезапустить systemd-resolved"

    if ! systemctl is-active --quiet systemd-resolved; then
         error_exit "Критическая ошибка: служба DNS не запустилась."
    fi

    log_info "DNS успешно настроен и проверен."
}

# Настройка DHCP-сервера (isc-dhcp-server)
configure_dhcp() {
    log_info "Настройка DHCP-сервера (isc-dhcp-server) с оптимизацией под VoIP..."

    local DHCP_CONF="/etc/dhcp/dhcpd.conf"
    local DHCP_DEFAULT="/etc/default/isc-dhcp-server"

    # 1. Авто-рестарт
    local override_dir="/etc/systemd/system/isc-dhcp-server.service.d"
    mkdir -p "$override_dir"
    cat <<EOF > "$override_dir/override.conf"
[Service]
Restart=always
RestartSec=10
EOF
    systemctl daemon-reload
    log_info "Внедрен авто-рестар DHCP ТОЛЬКО на случай падений."

    # 2. Бэкап
    [ -f "$DHCP_CONF" ] && cp "$DHCP_CONF" "${DHCP_CONF}.bak_$(date +%F_%H%M%S)"

    # 3. Конфиг под VoIP    
    cat <<EOF > "$DHCP_CONF"
# Оптимизировано @vpn_vendor для VoIP и стабильной работы офиса
default-lease-time 604800;
max-lease-time 604800;
authoritative;
log-facility local7;

subnet ${LOCAL_IP%.*}.0 netmask 255.255.255.0 {
    range ${LOCAL_IP%.*}.2 ${LOCAL_IP%.*}.254;
    option routers $LOCAL_IP;
    option subnet-mask 255.255.255.0;
    
    option domain-name "vpn.vendor";
    option domain-search "vpn.vendor";
    
    option domain-name-servers 94.140.14.14, 8.8.8.8;
}
EOF
    log_info "Конфигурация dhcpd.conf обновлена."

    # 4. Привязка к интерфейсу Lan
    if grep -q "^INTERFACESv4=" "$DHCP_DEFAULT"; then
        sed -i "s/^INTERFACESv4=.*/INTERFACESv4=\"$OUT_IF\"/" "$DHCP_DEFAULT"
    else
        echo "INTERFACESv4=\"$OUT_IF\"" >> "$DHCP_DEFAULT"
    fi

    # 5. Права
    if [ ! -f /var/lib/dhcp/dhcpd.leases ]; then
        touch /var/lib/dhcp/dhcpd.leases
    fi
    chown root:dhcpd /var/lib/dhcp/dhcpd.leases
    chmod 664 /var/lib/dhcp/dhcpd.leases
    
    # 6. Запуск
    systemctl enable isc-dhcp-server >/dev/null 2>&1
    systemctl restart isc-dhcp-server

    # Диагностика
    if systemctl is-active --quiet isc-dhcp-server; then
        log_info "DHCP-сервер успешно запущен."
    else
        echo -e "${YELLOW}[WARNING] DHCP-сервер не запустился мгновенно.${NC}"
        echo "Возможная причина: Сетевой кабель не подключен к интерфейсу $OUT_IF."
        echo "Используется авто-рестарт, служба запустится сама, как только вы подключите кабель в выходящий интерфейс - $OUT_IF."
        
        # Проверка линка
        if [ -f "/sys/class/net/$OUT_IF/carrier" ]; then
            local link_status=$(cat "/sys/class/net/$OUT_IF/carrier")
            if [ "$link_status" != "1" ]; then
                 echo -e "${RED}Обнаружено: Нет физического линка на $OUT_IF! Подключите свич/устройство и подождите 10 секунд служба подтянет все сама...${NC}"
            fi
        fi
    fi
}

# Настройка iptables (Killswitch, firewall, NAT, QoS для VoIP)
configure_iptables() {
    log_info "Настройка iptables..."

    # 1. Тюнинг ядра под VoIP
    local sysctl_conf="/etc/sysctl.conf"
    
    # Форвардинг
    sed -i '/^#.*net.ipv4.ip_forward/s/^#//' "$sysctl_conf"
    if ! grep -q "net.ipv4.ip_forward=1" "$sysctl_conf"; then
        echo "net.ipv4.ip_forward=1" >> "$sysctl_conf"
    fi

    # Оптимизация Conntrack
    if ! grep -q "net.netfilter.nf_conntrack_max" "$sysctl_conf"; then
        echo "net.netfilter.nf_conntrack_max=262144" >> "$sysctl_conf"
    fi
    # Очистка сессий
    if ! grep -q "net.netfilter.nf_conntrack_udp_timeout" "$sysctl_conf"; then
        echo "net.netfilter.nf_conntrack_udp_timeout=30" >> "$sysctl_conf"
        echo "net.netfilter.nf_conntrack_udp_timeout_stream=120" >> "$sysctl_conf"
    fi

    # Применение
    sysctl -p > /dev/null 2>&1 || log_info "Параметры sysctl применены (мелкие ошибки можно игнорировать)."
    log_info "Ядро оптимизировано под VoIP."

    log_info "Отключение лишних модулей..."
    modprobe -r nf_conntrack_sip 2>/dev/null
    modprobe -r nf_nat_sip 2>/dev/null

    cat <<EOF > /etc/modprobe.d/no-sip-alg.conf
blacklist nf_conntrack_sip
blacklist nf_nat_sip
EOF

    # 3. Настройка правил Iptables
    log_info "Применение правил маршрутизации..."

    # Полная очистка
    iptables -F FORWARD
    iptables -t nat -F POSTROUTING
    
    # Сброс
    iptables -Z FORWARD
    iptables -t nat -Z POSTROUTING

    # Запрет на транзит
    iptables -P FORWARD DROP

# Режим: VPN-ШЛЮЗА
    if [ "$ROUTING_MODE" == "VPN" ]; then
        log_info "Режим: VPN-ШЛЮЗ + KillSwitch"
        
        # --- Правила Kill Switch ---
        
        # 1. Локальная сеть ($OUT_IF) -> Туннель (tun0)
        iptables -A FORWARD -i "$OUT_IF" -o tun0 -j ACCEPT
        
        # 2. Туннель (tun0) -> Локальная сеть ($OUT_IF)
        iptables -A FORWARD -i tun0 -o "$OUT_IF" -m state --state RELATED,ESTABLISHED -j ACCEPT
        
        # 3. Разрешаем трафик внутри локальной сети (LAN <-> LAN)
        iptables -A FORWARD -i "$OUT_IF" -o "$OUT_IF" -j ACCEPT

        # 4. Страховка от утечек
        iptables -A FORWARD -i "$OUT_IF" -o "$IN_IF" -j REJECT --reject-with icmp-net-unreachable
        
        log_info "Правила FORWARD настроены."

        # --- Настройка NAT ---
        iptables -t nat -A POSTROUTING -o tun0 -s "${LOCAL_IP%.*}.0/24" -j MASQUERADE
        log_info "NAT настроен через интерфейс tun0."

# Режим: ПРЯМОЙ ИНТЕРНЕТ
    elif [ "$ROUTING_MODE" == "DIRECT" ]; then
        log_info "Режим: ПРЯМОЙ ИНТЕРНЕТ (Без VPN и KillSwitch)"
        
        # 1. Локалка -> Интернет
        iptables -A FORWARD -i "$OUT_IF" -o "$WAN_IFACE" -j ACCEPT
        
        # 2. Интернет -> Локалка
        iptables -A FORWARD -i "$WAN_IFACE" -o "$OUT_IF" -m state --state RELATED,ESTABLISHED -j ACCEPT
        
        log_info "Правила FORWARD настроены: Прямой доступ через $WAN_IFACE."

        # --- Настройка NAT ---
        iptables -t nat -A POSTROUTING -o "$WAN_IFACE" -s "${LOCAL_IP%.*}.0/24" -j MASQUERADE
        log_info "NAT настроен через интерфейс $WAN_IFACE."
    fi


    # 4. Сохранение
    log_info "Сохранение конфигурации..."
    iptables-save > /etc/iptables/rules.v4
    if systemctl is-active --quiet netfilter-persistent; then
        netfilter-persistent save >/dev/null 2>&1 || log_info "netfilter-persistent save пропущен (не критично)"
    fi
    
    log_info "Правила iptables успешно применены и сохранены."
}

# Ожидание доступности DNS
wait_for_dns() {
    log_info "Диагностика сети: Проверка доступа в Интернет и работы DNS..."
    local max_wait_time=60
    local elapsed_time=0
    local spinner="/-\\|"
    local i=0

    # 1. Ping 8.8.8.8
    while ! ping -c 1 -W 2 8.8.8.8 &> /dev/null; do
        if [ "$elapsed_time" -ge "$max_wait_time" ]; then
            echo ""
            log_error "Таймаут: Нет пинга до 8.8.8.8."
            error_exit "Интернет недоступен. Проверьте настройки IP, шлюза или кабель/линк."
        fi

        # Анимация
        i=$(( (i+1) %4 ))
        printf "\r[%c] Проверка пинга на IP... (${elapsed_time}с)" "${spinner:$i:1}"
        
        sleep 1
        elapsed_time=$((elapsed_time + 1))
    done
    echo ""
    log_info "Доступ по IP (8.8.8.8) есть. Идем дальше..."

    # 2. Ping google.com
    elapsed_time=0
    while ! ping -c 1 -W 2 google.com &> /dev/null; do
        if [ "$elapsed_time" -ge "$max_wait_time" ]; then
            echo ""
            log_error "Таймаут: Нет пинга до google.com."
            error_exit "Интернет есть, но DNS не работает. Проверьте настройки DNS в Netplan."
        fi

        i=$(( (i+1) %4 ))
        printf "\r[%c] Проверка пинга на DNS... (${elapsed_time}с)" "${spinner:$i:1}"
        
        sleep 1
        elapsed_time=$((elapsed_time + 1))
    done

    echo ""
    log_info "Сеть и DNS полностью работают."
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
echo -e "${YELLOW}  Установка VPN-сервера с веб-интерфейсом (v2.5.5)${NC}"
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
