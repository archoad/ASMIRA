# Déploiement hebdomadaire d’Asmira sur `srv`

## Portée

Le bundle prépare une exécution hebdomadaire sur `srv`, le lundi à 20:00
heure de Paris, avec un délai aléatoire maximal de 30 minutes. La collecte
passive ne vaut pas autorisation de reconnaissance active :
`[active_scan] authorized = true` doit être positionné uniquement après
validation de la liste complète des domaines.

Le script d’installation :

- installe les paquets Debian nécessaires ;
- crée le compte système non interactif `asmira` ;
- installe l’application dans `/opt/asmira` et son environnement virtuel ;
- crée `/etc/asmira` et `/var/lib/asmira` ;
- installe `asmira.timer`, sans l’activer avant validation et pilotes.

Il ne démarre pas `asmira.service` et n’active pas le timer. Son exécution modifie la liste
des paquets, les comptes système, `/opt`, `/etc`, `/var/lib` et les unités
systemd. Vérifier ces cibles avant de l’exécuter.

## Préflight en lecture seule sur `srv`

Exécuter avec le compte `root`, sans `sudo` :

```sh
uname -a
python3 --version
command -v python3 nmap openssl nc subfinder amass
systemctl is-active elastic-agent.service elasticsearch.service
systemctl show elastic-agent.service -p User -p Group -p FragmentPath
free -h
df -h / /var /opt
systemd-analyze calendar 'Mon *-*-* 20:00:00 Europe/Paris'
```

L’absence de Subfinder désactive uniquement ce collecteur. Amass reste
facultatif et désactivé par défaut. Ne pas poursuivre si la pression mémoire,
le swap ou l’espace disque de `srv` sont dégradés.

## Installation

Depuis une copie du dépôt sur `srv` :

```sh
cd /chemin/vers/asmira
./deploy/install.sh
vim /etc/asmira/asmira.conf
vim /etc/asmira/asmira.env
```

Remplacer tous les domaines d’exemple. Ne placer aucun secret dans
`asmira.conf`. Le fichier `asmira.env`, lisible uniquement par `root` et le
groupe `asmira`, peut déclarer les variables facultatives :

```sh
SHODAN_API_KEY=...
CERTSPOTTER_API_KEY=...
ASMIRA_INTERNAL_NETWORKS=...
```

`ASMIRA_INTERNAL_NETWORKS` est une liste facultative de préfixes CIDR séparés
par des virgules. Elle alimente le champ historique `pasi` sans publier le
périmètre réseau de l’opérateur dans le dépôt.

Valider ensuite la configuration et les unités :

```sh
/opt/asmira/venv/bin/python /opt/asmira/asmira.py \
	--config /etc/asmira/asmira.conf \
	--validate-config

systemd-analyze verify \
	/etc/systemd/system/asmira.service \
	/etc/systemd/system/asmira.timer

systemctl list-timers asmira.timer
```

## Pilotes progressifs

Les commandes suivantes effectuent une reconnaissance active réelle. Elles ne
doivent être exécutées qu’après avoir confirmé `authorized = true` et contrôlé
que chaque domaine est autorisé.

Premier pilote limité à 100 couples FQDN/IP :

```sh
systemctl stop asmira.service
(
	set -a
	. /etc/asmira/asmira.env
	set +a
	cd /opt/asmira
	runuser -u asmira -- \
		/opt/asmira/venv/bin/python /opt/asmira/asmira.py \
		--config /etc/asmira/asmira.conf \
		--max-endpoints 100
)
```

Deuxième pilote limité à 500 endpoints :

```sh
(
	set -a
	. /etc/asmira/asmira.env
	set +a
	cd /opt/asmira
	runuser -u asmira -- \
		/opt/asmira/venv/bin/python /opt/asmira/asmira.py \
		--config /etc/asmira/asmira.conf \
		--max-endpoints 500
)
```

Le changement de répertoire est nécessaire avant un lancement manuel avec
`runuser` : celui-ci conserve le répertoire courant. Depuis un répertoire sous
`/root`, l’utilisateur `asmira` ne peut pas exécuter le `stat .` effectué au
démarrage du moteur Amass et celui-ci échoue avec `permission denied`. Ne pas
ouvrir les permissions de `/root` pour contourner ce problème. L’unité systemd
n’est pas concernée, car elle utilise `WorkingDirectory=/opt/asmira`.
Le sous-shell exporte temporairement les variables de `asmira.env`, notamment
`SHODAN_API_KEY`, afin que `runuser` les transmette au pilote sans placer de
secret dans les arguments. Ces variables disparaissent à la fermeture du
sous-shell. Le fichier doit rester détenu par `root:asmira` avec le mode `0640`.

Contrôler après chaque pilote :

```sh
journalctl -u asmira.service --since today --no-pager
find /var/lib/asmira/runs -maxdepth 2 -type f -printf '%TY-%Tm-%Td %TH:%TM %s %p\n' | sort
find /var/lib/asmira/export -maxdepth 1 -type f -name 'asmira_*.ndjson' -printf '%s %p\n' | sort
ps -eo pid,ppid,%cpu,%mem,etime,cmd --sort=-%cpu | head -30
free -h
```

Le checkpoint se trouve dans le répertoire du run. Une relance avec le même
`--run-id` reprend les endpoints terminés, mais recommence la découverte pour
revalider le périmètre DNS.

## Timer hebdomadaire

```sh
systemctl enable --now asmira.timer
systemctl list-timers asmira.timer
```

Pour déclencher explicitement un cycle complet :

```sh
systemctl start asmira.service
journalctl -fu asmira.service
```

Pour suspendre les prochaines exécutions sans supprimer les données :

```sh
systemctl disable --now asmira.timer
```

## Elastic Agent et Fleet

Dans la policy affectée à l’Elastic Agent de `srv`, créer trois entrées
**Custom Logs (Filestream)** à partir de
`elastic/fleet/custom-logs.yml` :

| Dataset | Chemin |
| --- | --- |
| `asmira.discovery` | `/var/lib/asmira/export/asmira_discovery_*.ndjson` |
| `asmira.exposure` | `/var/lib/asmira/export/asmira_exposure_*.ndjson` |
| `asmira.run` | `/var/lib/asmira/export/asmira_run_*.ndjson` |

Pour chaque entrée, coller dans le champ Fleet **Parsers** uniquement la liste
suivante, sans ajouter de clé `parsers:` englobante :

```yaml
- ndjson:
    target: ""
    add_error_key: true
    overwrite_keys: true
```

La policy générée doit en revanche contenir cette liste sous une clé
`parsers:`. Vérifier ce rendu avant un premier run : sans décodage NDJSON, la
ligne complète reste dans `_source.message`, `asmira.asset.id` n’est pas indexé
et les transforms `latest` regroupent les événements sans clé. Ajouter ensuite
le processeur
`fingerprint` indiqué afin de copier une empreinte déterministe d’`event.id`
vers `@metadata._id`. Cela rend une réingestion idempotente. Ne pas réutiliser
un ancien input Filestream sur ces mêmes chemins, ce qui provoquerait des
doublons.

Vérifier en direct l’utilisateur de l’Elastic Agent. S’il n’est pas `root`, lui
accorder uniquement un accès en lecture et traversée au répertoire
`/var/lib/asmira/export`, sans élargir les droits des autres répertoires.

## Assets Elasticsearch et Kibana

Choisir explicitement la rétention historique après les pilotes. Exemple avec
180 jours, valeur indicative à adapter à la taille mesurée :

```sh
read -rsp 'Elastic API key: ' ELASTIC_API_KEY
echo
export ELASTIC_API_KEY
read -rsp 'Kibana API key: ' KIBANA_API_KEY
echo
export KIBANA_API_KEY

python3 elastic/setup.py \
	--elasticsearch-url "https://<elasticsearch-host>:9200" \
	--kibana-url "https://<kibana-host>:5601" \
	--retention-days 180

unset ELASTIC_API_KEY KIBANA_API_KEY
```

Adapter les URL et le certificat CA aux valeurs vérifiées en direct. Ne pas
désactiver la validation TLS dans le script. Le programme installe :

- les mappings ECS/Asmira ;
- les champs d’identité d’exposition `server.domain` et
  `server.registered_domain`, y compris dans le data stream et l’index `latest`
  existants ;
- les champs de certificat `certificate_sha256`, les OID de clé publique et de
  signature, les algorithmes PQC reconnus et `certificate_pqc_status`, y compris
  dans le data stream et l’index `latest` existants ;
- les trois data streams historiques et leur rétention ;
- les transforms continus `asmira-exposure-latest` et
  `asmira-discovery-latest` ;
- l’alias filtré `asmira-exposure-current`, alimenté par des tombstones pour
  retirer les endpoints disparus des vues courantes ;
- les Data Views ;
- le dashboard `Asmira — Surface d’exposition globale`, avec les contrôles
  épinglés **Domaine** (`server.registered_domain`) puis **FQDN**
  (`server.domain`) pour Kibana `9.5.0`.

Le setup est réexécutable sur des transforms existants : leur méthode `latest`
reste inchangée et seules les propriétés acceptées par l’API `_update` sont
transmises. Ne pas supprimer ni réinitialiser les transforms pour une simple
mise à jour des mappings ou du dashboard.

Contrôles :

```sh
curl --fail --silent --show-error \
	-H "Authorization: ApiKey $ELASTIC_API_KEY" \
	"https://<elasticsearch-host>:9200/_data_stream/logs-asmira.*-default"

curl --fail --silent --show-error \
	-H "Authorization: ApiKey $ELASTIC_API_KEY" \
	"https://<elasticsearch-host>:9200/_transform/asmira-*-latest/_stats"
```

## Exploitation

Les rapports complets restent sous `/var/lib/asmira/runs/<run-id>/`. Les
exports NDJSON sont conservés localement pendant la durée définie par
`retention_days`; cette rétention locale ne supprime ni les runs complets ni
les données déjà indexées dans Elasticsearch.

Les captures, graphiques et XLSX sont désactivés par défaut pour limiter la
charge et l’espace disque. Les réactiver ponctuellement seulement après mesure
de leur coût. Les captures Selenium et les graphiques nécessitent en plus les
dépendances et le navigateur adaptés à la distribution ; ils ne sont pas
installés par le bundle minimal.
