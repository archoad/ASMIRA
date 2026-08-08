# Mémoire du projet Asmira

Dernière mise à jour : 2026-08-08

Ce document conserve uniquement l'état confirmé et les décisions durables du
projet. Il ne doit contenir aucun secret, identifiant ni inventaire de cible.

## Identité confirmée

- Nom du projet : **Asmira**.
- Développement du nom : **Attack Surface Mapping, Inventory, Reconnaissance &
  Analysis**.
- Description courte : **Découverte et cartographie de la surface d'exposition
  externe**.
- Le nom `tls` est historique et ne décrit plus le périmètre complet.

## Périmètre fonctionnel confirmé

Asmira couvre actuellement :

- la découverte multisource de noms d'hôtes ;
- la normalisation des FQDN, notamment IDNA ;
- la conservation de la provenance des observations ;
- la distinction entre noms explicites et observations wildcard ;
- la validation DNS et la détection des zones wildcard ;
- l'inventaire des hôtes résolus et de leurs adresses IPv4/IPv6 ;
- l'analyse indépendante de chaque couple FQDN/IP ;
- la cartographie des ports et des services HTTP/TLS ;
- l'extraction des certificats et l'énumération des suites de chiffrement ;
- la classification PQC des clés publiques et signatures de certificats X.509 ;
- les enrichissements WHOIS, GeoIP et Shodan lorsqu'ils sont disponibles ;
- les captures d'écran et graphiques facultatifs ;
- la production de rapports JSON et XLSX datés.

## Architecture confirmée

### Découverte

`fqdnCollect.py` orchestre les collecteurs passifs Shodan CTL, Subfinder,
Shodan DNS facultatif et Cert Spotter. Amass est un collecteur actif facultatif.
Chaque défaillance de source doit rester isolée et conserver un diagnostic avec
sa provenance.

La découverte produit :

- `data/YYYYMMDD_hosts_candidates.json` : tous les candidats normalisés et leur
  provenance ;
- `data/YYYYMMDD_hosts_inventory.json` : les candidats enrichis de leur état
  DNS ;
- `data/YYYYMMDD_hosts_list.json` : uniquement les FQDN explicites actuellement
  résolus, au format consommé par `webTLS.py`.

Une observation `*.example.com` reste un indice wildcard. Elle ne devient ni
`example.com` ni une cible transmise à la cartographie active.

### Cartographie

`webTLS.py` consomme le fichier `hosts_list` daté et conserve chaque couple
FQDN/IP. Il collecte les données DNS, ports, HTTP, TLS, certificats, chiffrements,
WHOIS, GeoIP et Shodan disponibles, puis produit les rapports. Les captures
d'écran et graphiques sont facultatifs.

### Exploitation installée

`asmira.py` est le point d’entrée de production. Il lit
`/etc/asmira/asmira.conf`, valide que les cibles sont des domaines enregistrés,
crée un `run-id` UTC, isole les rapports sous
`/var/lib/asmira/runs/<run-id>/` et produit trois exports NDJSON atomiques sous
`/var/lib/asmira/export/`.

Dans les événements d’exposition, le couple analysé est représenté par
`server.domain` et `server.ip`; `server.registered_domain` porte le domaine
enregistré. Asmira n’utilise plus `host.name` pour la cible, car Elastic Agent
réserve et enrichit `host.*` avec l’identité de la machine collectrice `srv`.
La sonde reste identifiée par `observer.hostname`. `dns.question.*` est conservé
pendant la transition et reste la représentation canonique des observations de
découverte DNS.

La cartographie active dispose d’une concurrence bornée par endpoint, d’un
budget global de sous-processus et d’un checkpoint permettant de reprendre un
run interrompu. Les graphes, captures et XLSX sont désactivés par défaut en
production.

Le déploiement est installé sur `srv` sous `/opt/asmira`, avec un compte système
non interactif. Les tests ont été confirmés fonctionnels et le timer systemd a
été activé le 31 juillet 2026. Depuis le 3 août 2026, il planifie une collecte
hebdomadaire le lundi à 20:00 heure de Paris. Un délai aléatoire maximal de
30 minutes signifie que le service peut réellement démarrer entre 20:00 et
20:30 ; `Persistent=true`
rattrape une échéance manquée. La première collecte automatisée du 31 juillet
2026 a terminé la découverte, puis a échoué avant la cartographie active lors du
tri d’un ensemble contenant des adresses IPv4 et IPv6. La correction locale
utilise une clé de tri commune fondée sur la version et la valeur numérique de
l’adresse. La correction a été redéployée sur `srv` et un pilote limité aux
100 premiers endpoints a réussi le 3 août 2026. L’ingestion Fleet et le
dashboard Kibana ont ensuite été validés sur ce pilote. Le premier cycle
hebdomadaire complet du lundi soir et l’évolution entre deux runs restent à
observer.

Elastic Agent doit lire les datasets `asmira.discovery`, `asmira.exposure` et
`asmira.run`. Les assets fournis créent les mappings, les data streams, les
transforms `asmira-discovery-latest` et `asmira-exposure-latest`, les Data Views
et le dashboard global. Les endpoints disparus produisent un tombstone
`present=false`; l’alias `asmira-exposure-current` filtre les vues d’état
courant, et le transform supprime les entités non rafraîchies après dix jours.
Un run plafonné par `max_endpoints` ou comportant une source incomplète est
marqué `partial` : il n’émet aucun tombstone et classe ses observations
actuelles avec `change=observed`, afin de ne pas créer de disparitions
artificielles.

Les versions installées et confirmées d’Elasticsearch et Kibana sont `9.5.0`.
Le dashboard provisionné contient deux contrôles épinglés dans cet ordre :
**Domaine** sur `server.registered_domain`, puis **FQDN** sur `server.domain`.
Cet ordre permet au choix du domaine de réduire les FQDN proposés.

Les événements d’exposition indexent l’empreinte SHA-256 du certificat, les OID
de sa clé publique et de sa signature, les algorithmes PQC reconnus et le statut
`certificate_pqc_status`. Les valeurs possibles sont `pqc`, `hybrid`, `partial`,
`classical` et `unknown`. Le dashboard courant présente leur répartition dans
le donut **Statut PQC des certificats TLS par endpoint**. ML-DSA et SLH-DSA sont
reconnus depuis leurs OID standardisés ; les OID composites ML-DSA/classiques
restent distingués comme hybrides. Ce statut décrit le certificat X.509 et ne
doit pas être interprété comme une preuve d’échange de clés TLS post-quantique.

Dans l’interface Custom Logs/Filestream utilisée pour Asmira, le champ Fleet
`Parsers` reçoit directement la liste YAML commençant par `- ndjson:` ; il ne
faut pas y ajouter une clé `parsers:` englobante. Une configuration incorrecte
avait laissé les lignes NDJSON du premier pilote dans `_source.message`, ce qui
privait les transforms d’`asmira.asset.id` et rendait l’alias courant vide. Les
documents ont été réparés, les transforms reconstruits et le dashboard a été
confirmé fonctionnel le 3 août 2026 avec 100 endpoints.

## Décisions durables

- La présence d'un nom dans une source passive ou historique ne prouve pas son
  exposition actuelle ; la validation DNS détermine son état courant.
- La collecte passive et la reconnaissance active restent séparées.
- Amass actif et sa force brute nécessitent `--enable-amass` et une cible
  explicitement autorisée.
- Un pilote manuel exécuté avec `runuser -u asmira` doit être lancé depuis
  `/opt/asmira`. `runuser` conserve le répertoire courant et Amass échoue sur
  `stat .` si celui-ci se trouve sous `/root`. Le service systemd utilise déjà
  `WorkingDirectory=/opt/asmira` et n’est pas concerné.
- Les pilotes manuels chargent `/etc/asmira/asmira.env` dans un sous-shell avant
  `runuser`, afin de transmettre notamment `SHODAN_API_KEY` sans l’inscrire dans
  les arguments. Le chargement de la clé Shodan par cette procédure est validé
  sur `srv`; sa valeur n’est pas conservée dans le dépôt.
- La cartographie avec `webTLS.py` nécessite
  `--authorized-active-scan`.
- Les tests simulent toutes les interactions DNS, HTTP/API, Selenium et
  sous-processus ; ils ne contactent aucune cible réelle.
- Les rapports, captures, caches et inventaires sensibles ne sont pas
  versionnés.
- Le dépôt GitHub privé est `archoad/ASMIRA`, sa branche principale est `main`
  et aucune release GitHub n’est prévue.
- Les bases GeoIP, le GeoJSON local et les plages propres à l’opérateur ne sont
  pas versionnés. Les préfixes facultatifs sont lus depuis
  `ASMIRA_INTERNAL_NETWORKS` dans l’environnement protégé.
- Les secrets sont lus uniquement depuis l'environnement et ne sont conservés
  ni dans le code, ni dans les arguments, ni dans les journaux, ni dans la
  documentation.
- La liste des domaines est conservée dans `/etc/asmira/asmira.conf`, sans
  secret. L’autorisation active persistante est portée par
  `[active_scan] authorized = true` dans ce fichier protégé.
- L’exécution automatique est hebdomadaire le lundi soir, et non quotidienne.
- L’ingestion utilise Elastic Agent/Filestream et des fichiers NDJSON atomiques,
  sans ajouter d’identifiants Elasticsearch au service Asmira.
- Les cibles d’exposition utilisent `server.domain`,
  `server.registered_domain` et `server.ip`; les dashboards ne doivent pas
  utiliser `host.name` comme FQDN, car ce champ décrit la machine Elastic Agent.
- Les dépendances TLS Python validées en production sont
  `cryptography==46.0.7` et `pyOpenSSL==26.0.0`. Conserver leurs contraintes
  compatibles lors des futures mises à jour.
- La classification PQC des certificats repose sur les OID X.509 et doit rester
  disponible même si `cryptography` ne sait pas construire l’objet de clé
  publique correspondant. Un OID non reconnu est `unknown`, jamais supposé
  classique.

## Vérification de référence

Depuis la racine du dépôt :

```sh
python3 -m py_compile asmira.py asmiraCommon.py fqdnCollect.py webTLS.py elastic/setup.py tests/test_asmira.py tests/test_deployment_assets.py tests/test_fqdn_collect.py tests/test_web_tls.py
python3 -m pytest -q
```

## Éléments non décidés

- Le répertoire de travail porte encore le nom historique `tls`.
- Les scripts conservent les noms `fqdnCollect.py` et `webTLS.py`.
- Aucun renommage de module, point d'entrée unifié ou paquet Python `asmira`
  n'est confirmé à ce stade ; `asmira.py` est un orchestrateur, pas encore un
  paquet installable.
- Aucun cycle complet de remédiation ou de gestion continue EASM n'est
  revendiqué ; Asmira réalise actuellement la découverte, l'inventaire, la
  reconnaissance et l'analyse.
- Les valeurs finales de `endpoint_workers` et `subprocess_budget` doivent être
  déterminées par les pilotes de 100 puis 500 endpoints.
- La durée de rétention Elasticsearch doit être choisie après mesure de la
  taille des documents et de la pression disque ; `elastic/setup.py` exige donc
  une valeur explicite.
- La policy Fleet Asmira et la lecture effective des exports sont confirmées ;
  l’utilisateur effectif de l’Elastic Agent et le détail de ses droits restent
  à documenter sur `srv`.

## Historique

- **2026-07-30 :** adoption du nom **Asmira** pour refléter l'extension du
  périmètre au-delà de TLS. Création de `INDEX.md` et `MEMORY.md`.
- **2026-07-30 :** préparation de l’exploitation hebdomadaire sur `srv`, le
  vendredi soir, avec configuration centralisée, concurrence bornée,
  checkpoints, exports Elastic, bundle systemd et dashboard global. Aucun
  déploiement serveur n’est encore affirmé.
- **2026-07-31 :** installation confirmée sur `srv`, tests fonctionnels et
  timer systemd activé. La première collecte automatisée est planifiée le soir
  même ; son exécution et ses résultats restent à confirmer.
- **2026-07-31 :** correction et validation du couple de dépendances
  `cryptography==46.0.7` et `pyOpenSSL==26.0.0` après un conflit du solveur
  `pip` pendant l’installation.
- **2026-08-03 :** le premier run automatisé est confirmé en échec après la
  découverte à cause d’un tri incompatible entre IPv4 et IPv6 dans la
  préparation des endpoints. Une clé de tri inter-familles et un test de
  régression simulé ont été ajoutés, redéployés et validés par un pilote limité
  aux 100 premiers endpoints. Le timer hebdomadaire a été déplacé au lundi à
  20:00 heure de Paris.
- **2026-08-03 :** correction de la configuration du parseur NDJSON Fleet,
  réparation des événements du pilote restés dans `message`, reconstruction
  des transforms `latest` et validation du dashboard Kibana sur 100 endpoints.
  Le premier cycle hebdomadaire complet et la comparaison entre runs restent à
  confirmer.
- **2026-08-07 :** correction du conflit ECS entre les FQDN analysés et les
  métadonnées de l’Elastic Agent. Le schéma d’exposition et le dashboard passent
  de `host.name` à `server.domain`, avec `server.registered_domain` pour le
  domaine enregistré. Le setup met à jour les mappings des index existants sans
  réindexer ni modifier l’historique déjà ingéré. Elasticsearch et Kibana
  `9.5.0` sont confirmés ; le dashboard-as-code inclut les contrôles épinglés
  Domaine et FQDN compatibles avec cette version.
- **2026-08-08 :** ajout de la classification PQC des certificats à partir des
  OID de clé publique et de signature, propagation dans les exports et mappings
  Elastic, et ajout du donut de statut PQC au dashboard global. La distinction
  entre certificat X.509 et échange de clés TLS est conservée explicitement.
  Le setup filtre également les définitions envoyées à l’API de mise à jour des
  transforms afin de ne pas transmettre le champ immuable `latest` lorsque les
  transforms existent déjà.
- **2026-08-08 :** un pilote manuel lancé depuis un répertoire sous `/root`
  provoquait l’échec du moteur Amass sur `stat .`, car `runuser` conservait le
  répertoire courant inaccessible à l’utilisateur `asmira`. Le lancement depuis
  `/opt/asmira` a été validé sur `srv` et devient la procédure documentée.
- **2026-08-08 :** la clé Shodan placée dans `/etc/asmira/asmira.env` et chargée
  temporairement avant un pilote manuel a été confirmée fonctionnelle sur
  `srv`. Seul ce mode de chargement est documenté ; aucune valeur secrète n’est
  conservée.
- **2026-08-08 :** création du dépôt GitHub privé `archoad/ASMIRA` sur la
  branche `main`, sans mécanisme de release. Ajout du README, de la politique de
  sécurité et d’une CI de tests. Les données générées, bases GeoIP/GeoJSON et
  périmètres réseau réels sont exclus du premier commit, validé localement par
  Gitleaks avant publication.
