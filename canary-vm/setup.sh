#!/usr/bin/env bash
# Builds the canary VM: moves real SSH out of the way, runs OpenCanary in Docker,
# installs the Wazuh agent and ships the OpenCanary JSON log to the manager.
#
# Run on a fresh Ubuntu Server VM, from this folder:
#   sudo ./setup.sh <wazuh-manager-ip> <admin-ip>
#
#   wazuh-manager-ip  IP of the Wazuh server VM
#   admin-ip          IP you manage this VM from (your Mac on the UTM network);
#                     the only address allowed to reach the real SSH on port 2222
set -euo pipefail

WAZUH_MANAGER="${1:?usage: sudo ./setup.sh <wazuh-manager-ip> <admin-ip>}"
ADMIN_IP="${2:?usage: sudo ./setup.sh <wazuh-manager-ip> <admin-ip>}"
WAZUH_VERSION="${WAZUH_VERSION:-4.14.8}"   # must not be newer than the manager
AGENT_NAME="${AGENT_NAME:-canary-01}"
ADMIN_SSH_PORT=2222
DECOY_PORTS=(21 22 23 80 3306 3389 5900 6379 9418)
CANARY_LOG=/var/log/opencanary/opencanary.log
HERE="$(cd "$(dirname "$0")" && pwd)"

[[ $EUID -eq 0 ]] || { echo "Run with sudo." >&2; exit 1; }

echo "==> 1/5 Moving real SSH to port ${ADMIN_SSH_PORT} (the decoy takes 22)"
cat > /etc/ssh/sshd_config.d/10-admin-port.conf <<EOF
Port ${ADMIN_SSH_PORT}
EOF
# Ubuntu 24.04+ uses socket activation; the generator reads Port on daemon-reload.
systemctl daemon-reload
systemctl restart ssh.socket 2>/dev/null || true
systemctl restart ssh
ss -ltn | grep -q ":${ADMIN_SSH_PORT} " || { echo "sshd is not on ${ADMIN_SSH_PORT}; stopping before the firewall locks you out." >&2; exit 1; }

echo "==> 2/5 Firewall: decoys open to the lab, real SSH only from ${ADMIN_IP}"
apt-get update -q
apt-get install -yq ufw curl gnupg apt-transport-https
ufw --force reset >/dev/null
ufw default deny incoming
ufw default allow outgoing
ufw allow from "${ADMIN_IP}" to any port "${ADMIN_SSH_PORT}" proto tcp comment 'admin ssh'
for p in "${DECOY_PORTS[@]}"; do ufw allow "${p}/tcp" comment 'opencanary decoy'; done
ufw --force enable

echo "==> 3/5 OpenCanary in Docker"
apt-get install -yq docker.io docker-compose-v2
systemctl enable --now docker
install -d -m 0755 /opt/opencanary /var/log/opencanary
install -m 0644 "${HERE}/opencanary.conf" /opt/opencanary/opencanary.conf
install -m 0644 "${HERE}/docker-compose.yml" /opt/opencanary/docker-compose.yml
docker compose -f /opt/opencanary/docker-compose.yml up -d
cat > /etc/logrotate.d/opencanary <<EOF
${CANARY_LOG} {
    daily
    rotate 14
    compress
    missingok
    notifempty
    copytruncate
}
EOF

echo "==> 4/5 Wazuh agent ${WAZUH_VERSION} -> ${WAZUH_MANAGER}"
curl -fsSL https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --dearmor --yes -o /usr/share/keyrings/wazuh.gpg
echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" > /etc/apt/sources.list.d/wazuh.list
apt-get update -q
WAZUH_MANAGER="${WAZUH_MANAGER}" WAZUH_AGENT_NAME="${AGENT_NAME}" \
  apt-get install -yq "wazuh-agent=${WAZUH_VERSION}-1"
apt-mark hold wazuh-agent >/dev/null

echo "==> 5/5 Shipping ${CANARY_LOG} to Wazuh"
OSSEC_CONF=/var/ossec/etc/ossec.conf
if ! grep -q "${CANARY_LOG}" "${OSSEC_CONF}"; then
  cat >> "${OSSEC_CONF}" <<EOF

<ossec_config>
  <localfile>
    <log_format>json</log_format>
    <location>${CANARY_LOG}</location>
  </localfile>
</ossec_config>
EOF
fi
systemctl daemon-reload
systemctl enable --now wazuh-agent
systemctl restart wazuh-agent

sleep 5
echo
echo "Done."
docker ps --filter name=opencanary --format '  container: {{.Names}} {{.Status}}'
echo "  agent:     $(systemctl is-active wazuh-agent)"
echo "  listening: $(ss -ltnH | awk '{print $4}' | sed 's/.*://' | sort -n | uniq | tr '\n' ' ')"
echo
echo "Manage this VM with: ssh -p ${ADMIN_SSH_PORT} <user>@<this-vm-ip>"
