# Index du projet Asmira

Asmira assure la découverte et la cartographie de la surface d'exposition
externe. Cet index constitue le point d'entrée pour comprendre le dépôt sans
charger des rapports d'exécution potentiellement sensibles.

## Documents de référence

| Sujet | Fichier |
| --- | --- |
| Présentation et démarrage rapide | [`README.md`](README.md) |
| Signalement privé et données à ne pas publier | [`SECURITY.md`](SECURITY.md) |
| Licence GNU GPL version 3 uniquement | [`LICENSE`](LICENSE) |
| État confirmé, décisions et questions ouvertes | [`MEMORY.md`](MEMORY.md) |
| Orchestrateur configuré et exports Elastic | [`asmira.py`](asmira.py) |
| Configuration, identifiants et écritures atomiques | [`asmiraCommon.py`](asmiraCommon.py) |
| Découverte, normalisation et validation DNS | [`fqdnCollect.py`](fqdnCollect.py) |
| Cartographie active HTTP/TLS et reporting | [`webTLS.py`](webTLS.py) |
| Notation TLS et codes de constat | [`asmiraGrade.py`](asmiraGrade.py) |
| Exemple de configuration | [`config/asmira.conf.example`](config/asmira.conf.example) |
| Unités systemd | [`deploy/systemd/`](deploy/systemd/) |
| Assets Elasticsearch, Fleet et Kibana | [`elastic/`](elastic/) |
| Tests de l’orchestrateur et du déploiement | [`tests/test_asmira.py`](tests/test_asmira.py), [`tests/test_deployment_assets.py`](tests/test_deployment_assets.py) |
| Tests de la découverte | [`tests/test_fqdn_collect.py`](tests/test_fqdn_collect.py) |
| Tests de la cartographie TLS | [`tests/test_web_tls.py`](tests/test_web_tls.py) |
| Tests de la notation | [`tests/test_grade.py`](tests/test_grade.py) |

## Chaîne de traitement

1. `fqdnCollect.py` agrège des observations issues de plusieurs sources.
2. Les candidats sont normalisés, classés et validés par DNS.
3. La découverte écrit les fichiers datés `hosts_candidates`,
   `hosts_inventory` et `hosts_list` dans `data/`.
4. `webTLS.py` consomme `hosts_list` et analyse séparément chaque couple
   FQDN/IP autorisé.
5. `asmira.py` consolide toutes les observations FQDN/IP d’un même nom en une
   seule entité FQDN, compare son certificat et son statut PQC au dernier état
   connu, puis produit les exports NDJSON.
6. Les rapports JSON/XLSX sont écrits dans `data/`; les captures et graphiques
   facultatifs sont écrits dans `pictures/`.

En production, `asmira.py` isole chaque exécution sous un `run-id`, produit des
exports NDJSON atomiques et conserve un checkpoint de la cartographie active.
Elastic Agent sur `srv` lit les exports, Elasticsearch les historise et Kibana
sur `lab` présente une base durable contenant au plus un document par FQDN,
alimentée par le transform `asmira-fqdn-latest`.

## Ordre de lecture conseillé

Pour une modification fonctionnelle, lire d'abord `MEMORY.md`, puis uniquement
le script et les tests concernés. Les procédures opérateur locales ne sont pas
publiées dans le dépôt.

Ne pas utiliser les rapports de `data/` ni les images de `pictures/` comme
documentation de référence : ils peuvent être périmés et contenir un inventaire
de cibles sensible.
