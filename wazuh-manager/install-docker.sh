#!/usr/bin/env bash
# Loads the OpenCanary rules into a Dockerized Wazuh manager (official
# wazuh-docker single-node, e.g. the AI SOC lab) and makes it the lab's only SIEM.
#
# Run on the Wazuh VM, from this folder:
#   sudo ./install-docker.sh [compose-project-dir]
# compose-project-dir defaults to ~/ai-soc-lab of the user who ran sudo.
#
# What it does:
#   1. stops and disables a native (systemd) Wazuh install, if there is one,
#      so it never fights the containers for ports 1514/1515/443/9200 again
#   2. copies the rules and compose override to /opt/opencanary-wazuh/
#   3. adds compose.opencanary.yml to the project's COMPOSE_FILE (.env)
#   4. restores the containers' restart policies and brings the stack up
#   5. validates the rules inside the manager; rolls .env back if they fail
#
# Author: @alex_mh
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
USER_HOME="$(getent passwd "${SUDO_USER:-$USER}" | cut -d: -f6)"
PROJECT="${1:-${USER_HOME}/ai-soc-lab}"
DEST=/opt/opencanary-wazuh
OVERRIDE="${DEST}/compose.opencanary.yml"
ENV_FILE="${PROJECT}/.env"

[[ $EUID -eq 0 ]] || { echo "Run with sudo." >&2; exit 1; }
[[ -f "${PROJECT}/docker-compose.yml" ]] || { echo "No docker-compose.yml in ${PROJECT}" >&2; exit 1; }
cd "${PROJECT}"

echo "==> 1/5 Native Wazuh: stop and disable (if installed)"
for s in wazuh-dashboard wazuh-manager wazuh-indexer; do
  if systemctl cat "${s}.service" >/dev/null 2>&1; then
    systemctl disable --now "${s}" >/dev/null 2>&1 || true
    echo "  ${s}: $(systemctl is-active "${s}" || true), $(systemctl is-enabled "${s}" 2>/dev/null || true)"
  fi
done

echo "==> 2/5 Rules -> ${DEST}"
install -d -m 0755 "${DEST}"
install -m 0644 "${HERE}/opencanary_rules.xml" "${DEST}/opencanary_rules.xml"
install -m 0644 "${HERE}/compose.opencanary.yml" "${OVERRIDE}"

echo "==> 3/5 COMPOSE_FILE in ${ENV_FILE}"
touch "${ENV_FILE}"
cp -p "${ENV_FILE}" "${ENV_FILE}.bak-opencanary"
current="$(grep -E '^COMPOSE_FILE=' "${ENV_FILE}" | tail -1 | cut -d= -f2- || true)"
[[ -n "${current}" ]] || current="docker-compose.yml"
if [[ ":${current}:" != *":${OVERRIDE}:"* ]]; then
  grep -vE '^COMPOSE_FILE=' "${ENV_FILE}.bak-opencanary" > "${ENV_FILE}" || true
  echo "COMPOSE_FILE=${current}:${OVERRIDE}" >> "${ENV_FILE}"
fi
grep -E '^COMPOSE_FILE=' "${ENV_FILE}"

echo "==> 4/5 Restart policies and stack up"
for c in $(docker compose ps -aq); do
  svc="$(docker inspect -f '{{ index .Config.Labels "com.docker.compose.service" }}' "$c")"
  case "${svc}" in
    wazuh.*) docker update --restart=always "$c" >/dev/null ;;
    attacker) ;;
    *) docker update --restart=unless-stopped "$c" >/dev/null ;;
  esac
done
docker compose up -d

echo "==> 5/5 Validating rules inside the manager"
for _ in $(seq 1 36); do
  docker compose exec -T wazuh.manager test -f /var/ossec/etc/rules/opencanary_rules.xml 2>/dev/null && break
  sleep 5
done
if docker compose exec -T wazuh.manager /var/ossec/bin/wazuh-analysisd -t; then
  docker compose exec -T wazuh.manager /var/ossec/bin/wazuh-control restart >/dev/null
  echo
  echo "Done. Rules 100500-100549 are loaded in the Docker manager."
  docker compose ps --format '  {{.Service}}: {{.State}}'
else
  echo "Rule validation failed; restoring ${ENV_FILE}." >&2
  cp -p "${ENV_FILE}.bak-opencanary" "${ENV_FILE}"
  docker compose up -d
  exit 1
fi
