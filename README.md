# Asmira

**Attack Surface Mapping, Inventory, Reconnaissance & Analysis**

Asmira découvre et cartographie une surface d’exposition externe. Il agrège
des observations passives, valide leur état DNS, construit un inventaire
FQDN/IP puis analyse les services HTTP et TLS de chaque endpoint explicitement
autorisé.

## Principes de sécurité

- Une observation passive ou historique ne prouve pas qu’un hôte est exposé :
  seule la validation DNS détermine son état actuel.
- La collecte passive et la reconnaissance active restent séparées.
- Amass actif nécessite `--enable-amass` et une cible autorisée.
- La cartographie HTTP/TLS nécessite `--authorized-active-scan`.
- Les secrets sont lus depuis l’environnement et ne doivent jamais être placés
  dans le dépôt, les arguments, les journaux ou les rapports.
- Les inventaires, rapports, captures et bases de données locales sont ignorés
  par Git.
- Les plages réseau propres à l’opérateur sont chargées localement depuis
  `ASMIRA_INTERNAL_NETWORKS` et ne sont pas codées en dur.

## Composants

- `fqdnCollect.py` : découverte multisource, normalisation et validation DNS ;
- `webTLS.py` : cartographie FQDN/IP, HTTP, TLS, certificats et reporting ;
- `asmira.py` : orchestration des runs de production et exports NDJSON ;
- `asmiraCommon.py` : configuration, identifiants et écritures atomiques ;
- `elastic/` : mappings, transforms, configuration Fleet et dashboard Kibana ;
- `deploy/` : installation Debian et unités systemd.

Le détail de l’architecture et l’état confirmé du projet sont accessibles dans
[`INDEX.md`](INDEX.md) et [`MEMORY.md`](MEMORY.md).

## Installation de développement

```sh
python3 -m venv .venv
. .venv/bin/activate
python3 -m pip install --upgrade pip
python3 -m pip install -r requirements-dev.txt
```

Les fichiers locaux `data/app/geolite2-city.mmdb`,
`data/app/geolite2-asn.mmdb` et `data/app/countries.geojson` ne sont pas
versionnés. Voir [`data/app/README.md`](data/app/README.md) avant d’utiliser les
enrichissements GeoIP ou les graphiques géographiques.

## Validation

Les tests simulent les interactions externes et ne doivent contacter ni API ni
cible réelle.

```sh
python3 -m py_compile asmira.py asmiraCommon.py fqdnCollect.py webTLS.py elastic/setup.py tests/test_asmira.py tests/test_deployment_assets.py tests/test_fqdn_collect.py tests/test_web_tls.py
python3 -m pytest -q
```

## Utilisation

Découverte passive :

```sh
python3 fqdnCollect.py
```

Énumération active facultative avec Amass, uniquement sur un domaine autorisé :

```sh
python3 fqdnCollect.py --enable-amass example.com
```

Amass v5 peut alors démarrer son moteur local en arrière-plan sur
`127.0.0.1:4000`.

Cartographie active, uniquement sur des cibles autorisées :

```sh
python3 webTLS.py --authorized-active-scan
```

Pour le déploiement orchestré et l’intégration Elastic, consulter
[`DEPLOYMENT.md`](DEPLOYMENT.md). Le projet est distribué depuis son code
source ; aucune release GitHub n’est prévue.
