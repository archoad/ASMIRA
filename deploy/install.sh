#!/bin/sh
set -eu

SOURCE_DIR=${1:-$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)}
INSTALL_DIR=/opt/asmira
CONFIG_DIR=/etc/asmira
STATE_DIR=/var/lib/asmira

if [ "$(id -u)" -ne 0 ]; then
	echo "Ce script doit être exécuté avec le compte root." >&2
	exit 1
fi

apt-get update
apt-get install -y python3 python3-venv nmap netcat-openbsd openssl ca-certificates

if ! getent group asmira >/dev/null 2>&1; then
	groupadd --system asmira
fi
if ! id asmira >/dev/null 2>&1; then
	useradd --system --gid asmira --home-dir "$STATE_DIR" --shell /usr/sbin/nologin asmira
fi

install -d -o root -g root -m 0755 "$INSTALL_DIR"
install -d -o root -g asmira -m 0750 "$CONFIG_DIR"
install -d -o asmira -g asmira -m 0750 \
	"$STATE_DIR" \
	"$STATE_DIR/runs" \
	"$STATE_DIR/export" \
	"$STATE_DIR/pictures" \
	"$STATE_DIR/state"

for sourceFile in asmira.py asmiraCommon.py asmiraGrade.py fqdnCollect.py webTLS.py requirements.txt; do
	install -o root -g root -m 0644 "$SOURCE_DIR/$sourceFile" "$INSTALL_DIR/$sourceFile"
done

if [ -f "$SOURCE_DIR/DEPLOYMENT.md" ]; then
	install -o root -g root -m 0644 "$SOURCE_DIR/DEPLOYMENT.md" "$INSTALL_DIR/DEPLOYMENT.md"
fi

install -d -o root -g root -m 0755 "$INSTALL_DIR/elastic"
install -d -o root -g root -m 0755 \
	"$INSTALL_DIR/elastic/elasticsearch" \
	"$INSTALL_DIR/elastic/kibana" \
	"$INSTALL_DIR/elastic/fleet"
install -o root -g root -m 0755 "$SOURCE_DIR/elastic/setup.py" "$INSTALL_DIR/elastic/setup.py"
for sourceFile in "$SOURCE_DIR"/elastic/elasticsearch/*.json; do
	install -o root -g root -m 0644 "$sourceFile" "$INSTALL_DIR/elastic/elasticsearch/"
done
for sourceFile in "$SOURCE_DIR"/elastic/kibana/*.json; do
	install -o root -g root -m 0644 "$sourceFile" "$INSTALL_DIR/elastic/kibana/"
done
install -o root -g root -m 0644 \
	"$SOURCE_DIR/elastic/fleet/custom-logs.yml" \
	"$INSTALL_DIR/elastic/fleet/custom-logs.yml"

if [ -d "$SOURCE_DIR/data/app" ]; then
	install -d -o root -g root -m 0755 "$INSTALL_DIR/data/app"
	for sourceFile in "$SOURCE_DIR"/data/app/*; do
		[ -f "$sourceFile" ] || continue
		install -o root -g root -m 0644 "$sourceFile" "$INSTALL_DIR/data/app/"
	done
fi

python3 -m venv "$INSTALL_DIR/venv"
"$INSTALL_DIR/venv/bin/python" -m pip install --upgrade pip
"$INSTALL_DIR/venv/bin/python" -m pip install -r "$INSTALL_DIR/requirements.txt"

if [ ! -f "$CONFIG_DIR/asmira.conf" ]; then
	install -o root -g asmira -m 0640 \
		"$SOURCE_DIR/config/asmira.conf.example" \
		"$CONFIG_DIR/asmira.conf"
fi
if [ ! -f "$CONFIG_DIR/asmira.env" ]; then
	install -o root -g asmira -m 0640 \
		"$SOURCE_DIR/config/asmira.env.example" \
		"$CONFIG_DIR/asmira.env"
fi

install -o root -g root -m 0644 \
	"$SOURCE_DIR/deploy/systemd/asmira.service" \
	/etc/systemd/system/asmira.service
install -o root -g root -m 0644 \
	"$SOURCE_DIR/deploy/systemd/asmira.timer" \
	/etc/systemd/system/asmira.timer

systemctl daemon-reload

echo "Installation terminée."
echo "Édite $CONFIG_DIR/asmira.conf, remplace les domaines d’exemple et confirme authorized=true."
echo "Valide ensuite avec :"
echo "$INSTALL_DIR/venv/bin/python $INSTALL_DIR/asmira.py --config $CONFIG_DIR/asmira.conf --validate-config"
echo "Après les pilotes, active le timer avec : systemctl enable --now asmira.timer"
echo "Le timer n’a pas été activé et aucun scan n’a été démarré."
