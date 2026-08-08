# Index du projet Asmira

Asmira assure la découverte et la cartographie de la surface d'exposition
externe. Cet index constitue le point d'entrée pour comprendre le dépôt sans
charger des rapports d'exécution potentiellement sensibles.

## Documents de référence

| Sujet | Fichier |
| --- | --- |
| Présentation et démarrage rapide | [`README.md`](README.md) |
| Directives de contribution, sécurité et tests | [`AGENTS.md`](AGENTS.md) |
| Signalement privé et données à ne pas publier | [`SECURITY.md`](SECURITY.md) |
| État confirmé, décisions et questions ouvertes | [`MEMORY.md`](MEMORY.md) |
| Orchestrateur configuré et exports Elastic | [`asmira.py`](asmira.py) |
| Configuration, identifiants et écritures atomiques | [`asmiraCommon.py`](asmiraCommon.py) |
| Découverte, normalisation et validation DNS | [`fqdnCollect.py`](fqdnCollect.py) |
| Cartographie active HTTP/TLS et reporting | [`webTLS.py`](webTLS.py) |
| Installation Debian, pilotes et exploitation | [`DEPLOYMENT.md`](DEPLOYMENT.md) |
| Exemple de configuration | [`config/asmira.conf.example`](config/asmira.conf.example) |
| Unités systemd | [`deploy/systemd/`](deploy/systemd/) |
| Assets Elasticsearch, Fleet et Kibana | [`elastic/`](elastic/) |
| Tests de l’orchestrateur et du déploiement | [`tests/test_asmira.py`](tests/test_asmira.py), [`tests/test_deployment_assets.py`](tests/test_deployment_assets.py) |
| Tests de la découverte | [`tests/test_fqdn_collect.py`](tests/test_fqdn_collect.py) |
| Tests de la cartographie TLS | [`tests/test_web_tls.py`](tests/test_web_tls.py) |

## Chaîne de traitement

1. `fqdnCollect.py` agrège des observations issues de plusieurs sources.
2. Les candidats sont normalisés, classés et validés par DNS.
3. La découverte écrit les fichiers datés `hosts_candidates`,
   `hosts_inventory` et `hosts_list` dans `data/`.
4. `webTLS.py` consomme `hosts_list` et analyse séparément chaque couple
   FQDN/IP autorisé.
5. Les rapports JSON/XLSX sont écrits dans `data/`; les captures et graphiques
   facultatifs sont écrits dans `pictures/`.

En production, `asmira.py` isole chaque exécution sous un `run-id`, produit des
exports NDJSON atomiques et conserve un checkpoint de la cartographie active.
Elastic Agent sur `srv` lit les exports, Elasticsearch les historise et Kibana
sur `lab` présente l’état courant alimenté par des transforms `latest`.

## Ordre de lecture conseillé

Pour une modification fonctionnelle, lire d'abord `MEMORY.md`, puis la section
pertinente de `AGENTS.md` et uniquement le script et les tests concernés.

Ne pas utiliser les rapports de `data/` ni les images de `pictures/` comme
documentation de référence : ils peuvent être périmés et contenir un inventaire
de cibles sensible.
