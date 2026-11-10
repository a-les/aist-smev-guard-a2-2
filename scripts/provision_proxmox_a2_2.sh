#!/usr/bin/env bash
# scripts/provision_proxmox_a2_2.sh
# Автоматическое создание SDN-моста и виртуальных машин VM 221..225 для Команды А2.2
# (Селезнева О. С. @wauwho + Панфилов А. В. @yo5hh) на узле PC-14 (1 x RTX 5080 16 GB, 32 GB RAM)
set -euo pipefail

PVE_NODE="${PVE_NODE:-pc-14}"
TEMPLATE_VMID="${TEMPLATE_VMID:-9001}"
STORAGE_POOL="${STORAGE_POOL:-local-lvm}"
BRIDGE_NAME="${BRIDGE_NAME:-vmbr221}"
SUBNET_CIDR="10.221.0.1/24"
RTX5080_PCI_ADDR="${RTX5080_PCI_ADDR:-0000:01:00}"
SSH_PUBKEY_FILE="${SSH_PUBKEY_FILE:-/root/.ssh/authorized_keys}"

log_info() {
    printf "\033[1;34m[A2.2-PROVISION]\033[0m %s\n" "$1"
}

log_err() {
    printf "\033[1;31m[A2.2-ERROR]\033[0m %s\n" "$1" >&2
}

if [[ "$(id -u)" -ne 0 ]]; then
    log_err "Скрипт должен запускаться с правами root на гипервизоре Proxmox VE 9.2 (узел ${PVE_NODE})."
    exit 1
fi

log_info "Проверка наличия золотого шаблона NixOS 25.11 (VMID=${TEMPLATE_VMID})..."
if ! qm status "${TEMPLATE_VMID}" >/dev/null 2>&1; then
    log_err "Шаблон VM ${TEMPLATE_VMID} не найден. Сначала создайте базовый образ NixOS 25.11."
    exit 1
fi

log_info "Настройка изолированного сетевого моста ${BRIDGE_NAME} (${SUBNET_CIDR})..."
if ! ip link show "${BRIDGE_NAME}" >/dev/null 2>&1; then
    ip link add name "${BRIDGE_NAME}" type bridge
    ip addr add "${SUBNET_CIDR}" dev "${BRIDGE_NAME}"
    ip link set dev "${BRIDGE_NAME}" up
    log_info "Мост ${BRIDGE_NAME} поднят с адресом шлюза ${SUBNET_CIDR}."
else
    log_info "Мост ${BRIDGE_NAME} уже существует."
fi

# Включаем NAT для выхода лабораторной подсети к пакетному кэшу NixOS
iptables -t nat -C POSTROUTING -s 10.221.0.0/24 ! -d 10.221.0.0/24 -j MASQUERADE 2>/dev/null || \
    iptables -t nat -A POSTROUTING -s 10.221.0.0/24 ! -d 10.221.0.0/24 -j MASQUERADE

clone_and_configure_vm() {
    local vmid="$1"
    local name="$2"
    local cores="$3"
    local memory_mb="$4"
    local disk_gb="$5"
    local ip_addr="$6"
    local attach_gpu="$7"

    if qm status "${vmid}" >/dev/null 2>&1; then
        log_info "ВМ ${vmid} (${name}) уже существует — пропускаем клонирование."
    else
        log_info "Клонирование Linked Clone ВМ ${vmid} (${name}) из шаблона ${TEMPLATE_VMID}..."
        qm clone "${TEMPLATE_VMID}" "${vmid}" \
            --name "${name}" \
            --full 0 \
            --storage "${STORAGE_POOL}"
    fi

    log_info "Конфигурирование ресурсов ВМ ${vmid}: ${cores} vCPU, ${memory_mb} МБ RAM, IP ${ip_addr}..."
    qm set "${vmid}" \
        --cores "${cores}" \
        --sockets 1 \
        --cpu host \
        --memory "${memory_mb}" \
        --balloon 0 \
        --net0 "virtio,bridge=${BRIDGE_NAME},firewall=1" \
        --ipconfig0 "ip=${ip_addr}/24,gw=10.221.0.1" \
        --nameserver "1.1.1.1 8.8.8.8" \
        --agent enabled=1 \
        --onboot 1 \
        --ostype l26 \
        --scsihw virtio-scsi-single

    qm resize "${vmid}" scsi0 "${disk_gb}G" || true

    if [[ -f "${SSH_PUBKEY_FILE}" ]]; then
        qm set "${vmid}" --sshkeys "${SSH_PUBKEY_FILE}"
    fi

    if [[ "${attach_gpu}" == "true" ]]; then
        log_info "Проброс видеокарты NVIDIA RTX 5080 (PCIe ${RTX5080_PCI_ADDR}) в ВМ ${vmid}..."
        qm set "${vmid}" \
            --machine q35 \
            --bios ovmf \
            --hostpci0 "${RTX5080_PCI_ADDR},pcie=1,rombar=1,x-vga=0"
    fi

    log_info "Запуск ВМ ${vmid} (${name})..."
    qm start "${vmid}" || true
}

# 1. VM 221: Главный шлюз СМЭВ-Guard + GPU RTX 5080 (12 ГБ RAM, 8 vCPU)
clone_and_configure_vm 221 "vm-221-smev-ai-guard-gpu" 8 12288 80 "10.221.0.21" "true"

# 2. VM 222: Защищаемый контур ИИ «АИСТ» + стендовые конфиги ViPNet (4 ГБ RAM, 2 vCPU)
clone_and_configure_vm 222 "vm-222-aist-mock-gov-llm" 2 4096 30 "10.221.0.22" "false"

# 3. VM 223: Полигон Red-Teaming (NVIDIA Garak + PyRIT + k6) (4 ГБ RAM, 2 vCPU)
clone_and_configure_vm 223 "vm-223-garak-pyrit-redteam" 2 4096 30 "10.221.0.23" "false"

# 4. VM 224: Криптохранилище ПДн и аудит-лога PostgreSQL 16 (4 ГБ RAM, 2 vCPU)
clone_and_configure_vm 224 "vm-224-pii-vault-postgres" 2 4096 40 "10.221.0.24" "false"

# 5. VM 225: Мониторинг ИБ ГИС К1 (Prometheus + Grafana + Alertmanager) (4 ГБ RAM, 2 vCPU)
clone_and_configure_vm 225 "vm-225-prometheus-grafana-soc" 2 4096 30 "10.221.0.25" "false"

log_info "Ожидание готовности QEMU Guest Agent на ВМ 221..225..."
for vmid in 221 222 223 224 225; do
    for attempt in $(seq 1 30); do
        if qm agent "${vmid}" ping >/dev/null 2>&1; then
            log_info "ВМ ${vmid} в сети и отвечает на команды."
            break
        fi
        sleep 2
    done
done

log_info "Стенд Команды А2.2 (VM 221..225) успешно развёрнут на узле ${PVE_NODE}!"
