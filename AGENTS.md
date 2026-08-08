# Directives du dépôt

- Quand l'utilisateur confirme un changement, mettre à jour AGENTS.md
- Conserver un historique synthétique des décisions importantes.
- Ne jamais enregistrer de secret.

## Identité et objectifs

Le projet s'appelle **Asmira**.

**ASMIRA** signifie **Attack Surface Mapping, Inventory, Reconnaissance & Analysis**.
Sa description courte est : **Découverte et cartographie de la surface d'exposition externe**.

Asmira découvre des noms d'hôtes, valide leur état DNS, construit un inventaire
FQDN/IP et cartographie les services exposés, en particulier HTTP et TLS. Le
projet distingue les observations passives ou historiques des hôtes actuellement
résolus et des opérations de reconnaissance active explicitement autorisées.

`INDEX.md` est le point d'entrée documentaire du dépôt. `MEMORY.md` conserve
l'état confirmé, les décisions durables et les questions encore ouvertes. Les
consulter avant toute évolution du périmètre, de l'architecture ou des formats
de sortie.

## Structure du projet et organisation des modules

Asmira contient deux scripts Python historiques, un orchestrateur de production
et des tests ciblés :

- `asmira.py` lit `/etc/asmira/asmira.conf`, crée un identifiant d’exécution
  UTC, enchaîne la découverte et la cartographie autorisée, gère les répertoires
  de runs et produit les exports NDJSON consommés par Elastic Agent. Dans les
  événements d’exposition, `server.domain` et `server.registered_domain`
  identifient la cible ; `host.*` reste réservé à la machine Elastic Agent et
  `observer.hostname` à la sonde Asmira.
- `asmiraCommon.py` regroupe la configuration validée, les identifiants stables
  et les écritures JSON/NDJSON atomiques.
- `webTLS.py` collecte les informations DNS, HTTP, TLS, les suites de chiffrement, les certificats, les données GeoIP et les captures d’écran. Il conserve chaque couple FQDN/IP, y compris les points de terminaison IPv6, afin d’analyser indépendamment les hôtes virtuels et les cibles réparties par équilibrage de charge. Il classe également les algorithmes de clé publique et de signature des certificats depuis leurs OID X.509 avec les états `pqc`, `hybrid`, `partial`, `classical` et `unknown`. Il écrit des rapports JSON/XLSX datés dans `data/` et, facultativement, des graphiques dans `pictures/`.
- `fqdnCollect.py` orchestre la découverte multisource de noms d’hôtes. Les collecteurs passifs comprennent Shodan CTL, Subfinder, Shodan DNS facultatif et Cert Spotter. Amass est un collecteur actif facultatif qui ne doit être exécuté que lorsque l’opérateur l’active explicitement.
- La validation DNS normalise et classe les candidats collectés, y compris le traitement des wildcards, avant de produire la liste consommée par `webTLS.py`.
- `data/` contient les jeux de données d’exécution. `data/app/` contient les bases GeoLite et le fichier GeoJSON des pays.
- `tests/` contient les tests unitaires. Toutes les interactions externes DNS, HTTP/API et avec des sous-processus doivent être simulées.
- `README.md` présente le projet, `SECURITY.md` décrit le signalement privé et
  `.github/workflows/tests.yml` exécute les contrôles de syntaxe et les tests
  sur GitHub Actions.

Conserver la logique réutilisable dans des fonctions plutôt que d’étendre les blocs `__main__`. Ne pas versionner les rapports générés, les captures d’écran ou les caches, sauf s’il s’agit de jeux de données de test intentionnels.

Séparer clairement la collecte passive de l’énumération active. Les échecs des sources passives doivent être isolés et signalés avec leur provenance, sans interrompre l’ensemble de la collecte. Ne pas déduire qu’un nom d’hôte est actuellement exposé simplement parce qu’il apparaît dans une source passive ou historique ; utiliser la validation DNS pour déterminer son état actuel.

Le processus de découverte des noms d’hôtes produit trois fichiers JSON datés :

- `data/YYYYMMDD_hosts_candidates.json` contient tous les candidats normalisés ainsi que la provenance de leurs sources, y compris les noms historiques ou actuellement non résolus.
- `data/YYYYMMDD_hosts_inventory.json` contient l’inventaire enrichi et l’état de validation DNS.
- `data/YYYYMMDD_hosts_list.json` contient uniquement les noms d’hôtes explicites actuellement résolus, dans le schéma consommé par `webTLS.py`.

Lors d’une exécution orchestrée, chaque run est isolé sous
`/var/lib/asmira/runs/<run-id>/` et trois familles d’exports atomiques sont
écrites sous `/var/lib/asmira/export/` :

- `asmira_discovery_<run-id>.ndjson` pour les candidats et leur état DNS ;
- `asmira_exposure_<run-id>.ndjson` pour chaque couple FQDN/IP ;
- `asmira_run_<run-id>.ndjson` pour la santé, les durées et les compteurs.

Elastic Agent/Filestream collecte ces fichiers vers les datasets
`asmira.discovery`, `asmira.exposure` et `asmira.run`. Les fichiers JSON
historiques restent disponibles pour les diagnostics et la compatibilité.
L’export d’exposition compare le run au précédent et émet un tombstone
`present=false` pour chaque endpoint disparu. Le transform `latest` conserve
ainsi un état explicite, tandis que l’alias filtré
`asmira-exposure-current` ne présente que les endpoints encore observés.
Elasticsearch et Kibana `9.5.0` sont les versions confirmées en production. Le
dashboard déclare deux contrôles épinglés et ordonnés, **Domaine** sur
`server.registered_domain`, puis **FQDN** sur `server.domain`. Le donut
**Statut PQC des certificats TLS par endpoint** répartit les certificats selon
`asmira.exposure.tls.certificate_pqc_status`. Cette classification porte sur
la clé publique et la signature X.509 du certificat ; elle ne prouve pas que
l’échange de clés TLS négocié est post-quantique.

Les noms de certificats wildcard constituent des indices, pas des hôtes concrets. Conserver les observations wildcard dans les métadonnées des candidats et de l’inventaire, mais ne pas transformer `*.example.com` en `example.com` et ne pas transmettre de motifs wildcard à `webTLS.py`.

## Commandes de compilation, de test et de développement

Il n’existe pas de système de compilation. Utiliser un environnement virtuel et exécuter les contrôles de syntaxe ainsi que la suite de tests ciblés avant tout commit :

```sh
python3 -m py_compile asmira.py asmiraCommon.py fqdnCollect.py webTLS.py elastic/setup.py tests/test_asmira.py tests/test_deployment_assets.py tests/test_fqdn_collect.py tests/test_web_tls.py
python3 -m pytest -q
```

Exécuter la découverte passive depuis la racine du dépôt :

```sh
python3 fqdnCollect.py
```

Activer l’énumération active facultative avec Amass uniquement pour des cibles explicitement autorisées et seulement avec l’option dédiée :

```sh
python3 fqdnCollect.py --enable-amass example.com
```

L’interface en ligne de commande Amass v5 peut démarrer son moteur de collecte local en arrière-plan sur
`127.0.0.1:4000`. Informer l’opérateur de cette conséquence avant de l’activer
et ne pas démarrer ni arrêter ce moteur pendant les tests simulés.

Exécuter la cartographie TLS uniquement sur des cibles autorisées :

```sh
python3 webTLS.py --authorized-active-scan
```

Valider la configuration de production sans collecte :

```sh
python3 asmira.py --config /etc/asmira/asmira.conf --validate-config
```

Effectuer un pilote actif limité, après confirmation du périmètre :

```sh
cd /opt/asmira
python3 asmira.py --config /etc/asmira/asmira.conf --max-endpoints 100
```

Pour un pilote manuel de production avec `runuser -u asmira`, se placer
également dans `/opt/asmira` avant l’appel. `runuser` conserve le répertoire
courant et Amass ne peut pas démarrer depuis un répertoire sous `/root` auquel
le compte `asmira` n’a pas accès. Ne pas modifier les permissions de `/root` ;
l’unité systemd utilise déjà `WorkingDirectory=/opt/asmira`.
Charger `/etc/asmira/asmira.env` dans un sous-shell avec `set -a` avant
`runuser`, afin que les secrets facultatifs soient transmis au processus sans
figurer dans ses arguments ni persister dans le shell appelant.

L’option confirmant l’autorisation est obligatoire, car `webTLS.py` effectue des résolutions DNS, des scans de ports, des sondes HTTP/TLS, une énumération des suites de chiffrement et, facultativement, des chargements de pages avec Selenium. Utiliser `--skip-screenshots` ou `--skip-graphs` pour désactiver ces étapes, et `--keep-pictures` pour conserver les images générées lors des exécutions précédentes. Sans `--keep-pictures`, seuls les fichiers gérés `graph_*` et `screenshot_*` sont supprimés de `pictures/`.

Les collecteurs externes comme Subfinder et Amass doivent être appelés par de petits adaptateurs de sous-processus avec des délais d’expiration explicites, des codes de retour contrôlés et une sortie analysable. L’absence d’un outil facultatif ou de ses identifiants doit uniquement désactiver le collecteur concerné et produire un diagnostic clair. `webTLS.py` dépend de `nmap`, d’OpenSSL et de netcat aux chemins absolus déclarés dans `dicTools` ; Shodan reste facultatif lorsque `SHODAN_API_KEY` est absent.

En production Debian, les chemins de `nmap`, OpenSSL et netcat sont détectés
depuis `PATH` ou fournis par `[tools]` dans `asmira.conf`. La cartographie
utilise une concurrence d’endpoints et un budget global de sous-processus
distincts ; ne pas augmenter ces valeurs sans mesurer le CPU, la RAM, le swap,
la durée P95 et la charge Elasticsearch sur `srv`.

Le timer de référence est hebdomadaire, le lundi à 20:00 heure de Paris,
avec un délai aléatoire maximal de 30 minutes et `Persistent=true`. Les fichiers
de déploiement se trouvent sous `deploy/`. L’installation effective sur `srv`,
les tests et l’activation du timer ont été confirmés le 31 juillet 2026.
Les trois entrées Fleet, les transforms `latest` et le dashboard Kibana ont été
validés le 3 août 2026 sur un pilote de 100 endpoints. Le premier cycle
hebdomadaire complet du lundi soir reste à confirmer séparément.

## Style de code et conventions de nommage

Cibler Python 3 et conserver les tabulations existantes. Respecter le style de nommage actuel : `camelCase` pour les fonctions et les variables locales, `UPPER_CASE` uniquement pour les véritables constantes, et des clés de dictionnaire descriptives correspondant aux colonnes des rapports. Regrouper les imports en haut des fichiers et privilégier les petites fonctions à responsabilité unique. Aucun formateur ni outil d’analyse statique n’est actuellement configuré.

## Directives de test

Pour chaque modification, exécuter le contrôle de syntaxe et la suite de tests indiqués ci-dessus. Ajouter des tests ciblés dans `tests/` avec des noms tels que `test_fqdn_collect.py` et `test_extract_tls_data.py`. Simuler le DNS, Shodan CTL, Shodan DNS, Cert Spotter, les autres services HTTP, les sous-processus Subfinder/Amass, Selenium et tous les appels liés aux scans afin que les tests n’accèdent jamais au réseau et n’énumèrent aucune cible réelle.

Tester chaque collecteur indépendamment, notamment les délais d’expiration, les réponses mal formées, la pagination, les limitations de débit, les identifiants absents, les exécutables manquants et les codes de retour non nuls des sous-processus. Tester la normalisation, IDNA, l’extraction du domaine enregistré, la provenance des sources, la déduplication, le traitement des wildcards, les états DNS et l’ordre déterministe. Lorsque le schéma de découverte change, vérifier les trois sorties JSON et la compatibilité de `hosts_list` avec `webTLS.py` ; lorsque le schéma des rapports change, vérifier les sorties JSON et XLSX.

Tester également la validation d’`asmira.conf`, l’absence de secrets, les
identifiants de run, les écritures atomiques, la reprise des checkpoints, la
limitation d’endpoints, les trois exports NDJSON, les assets JSON Elastic et le
calendrier systemd. Les tests ne doivent jamais appeler Elasticsearch, Kibana,
Fleet ni les cibles réelles.

## Directives relatives aux commits et aux demandes de fusion

L’historique Git n’est pas disponible dans cette copie de travail ; aucune convention de commit existante ne peut donc être confirmée. Utiliser des sujets concis à l’impératif, par exemple `Corrige l’analyse de l’expiration des certificats`. Les demandes de fusion doivent décrire le comportement attendu, les commandes et résultats des tests, les champs de sortie affectés ainsi que toute nouvelle dépendance externe. Référencer le ticket concerné et joindre un exemple de sortie anonymisé ou des captures d’écran lorsque les rapports ou graphiques changent.

## Sécurité et configuration

Ne jamais versionner de clés d’API, d’identifiants, de certificats privés ou d’inventaires de cibles sensibles. Les identifiants de Shodan, Cert Spotter et des autres services doivent uniquement être lus depuis des variables d’environnement ; ne jamais placer de secrets dans le code source, les arguments de ligne de commande, les fichiers JSON générés, les journaux, les données de test ou `AGENTS.md`. Considérer les feuilles de calcul fournies et les résultats de scans générés comme potentiellement sensibles.

Les bases GeoIP, le GeoJSON local et les plages réseau propres à l’opérateur ne
sont pas publiés. Fournir les préfixes CIDR facultatifs avec
`ASMIRA_INTERNAL_NETWORKS` dans l’environnement local protégé.

La découverte passive n’autorise pas l’énumération active. Le mode actif d’Amass, la force brute DNS, les scans de ports, les sondes HTTP et les autres opérations actives doivent nécessiter une option explicite et une cible autorisée. Les tests ne doivent pas non plus effectuer de véritables requêtes vers les API passives.

## Historique synthétique des décisions

- **2026-07-30 — Adoption du nom Asmira.** Le nom historique `tls` ne
  représentait plus le périmètre, désormais étendu à la découverte multisource,
  à la validation DNS, à l'inventaire FQDN/IP et à la cartographie de la surface
  d'exposition externe. Le répertoire et les noms des scripts historiques ne
  sont pas renommés par cette décision.
- **2026-07-30 — Exploitation hebdomadaire sur `srv`.** Le pipeline est préparé
  pour être installé sous `/opt/asmira`, configuré par
  `/etc/asmira/asmira.conf`, exécuté par systemd le vendredi soir et ingéré par
  Elastic Agent dans le cluster `srv` + `lab`. La concurrence finale, la
  rétention Elastic et le déploiement réel restent à confirmer par des pilotes
  progressifs sur `srv`.
- **2026-07-31 — Installation et timer confirmés sur `srv`.** L’installation
  et les tests sont fonctionnels, et le timer systemd hebdomadaire est activé.
  La première collecte automatisée est planifiée le soir même ; son exécution,
  ses résultats et l’activation Fleet restent à confirmer.
- **2026-07-31 — Dépendances TLS Python compatibles.** Le couple
  `cryptography==46.0.7` et `pyOpenSSL==26.0.0` est validé après correction du
  conflit rencontré par `pip`. Conserver des contraintes compatibles lors des
  futures mises à jour.
- **2026-08-03 — Correction du tri des endpoints dual-stack.** Le premier run
  automatisé a terminé la découverte, puis a échoué avant la cartographie lors
  du tri d’un ensemble mêlant IPv4 et IPv6. Le tri utilise désormais une clé
  stable fondée sur la version et la valeur numérique de l’adresse, avec un
  test de régression simulé. La correction a été redéployée et validée sur les
  100 premiers endpoints. Le timer hebdomadaire a été déplacé au lundi à 20:00
  heure de Paris.
- **2026-08-03 — Ingestion Fleet et dashboard validés.** Les trois datasets
  Asmira sont ingérés par Custom Logs/Filestream. Le parseur NDJSON doit être
  configuré dans le champ Fleet `Parsers` comme une liste commençant par
  `- ndjson:`, sans clé `parsers:` englobante. Les documents du pilote
  initialement conservés dans `message` ont été réparés, les transforms
  `latest` reconstruits et le dashboard validé sur 100 endpoints. L’évolution
  lors du premier cycle hebdomadaire complet reste à observer.
- **2026-08-07 — Séparation de la cible et de la sonde dans ECS.** Elastic Agent
  remplaçait `host.name` par le nom de la machine collectrice `srv`, ce qui
  masquait les FQDN dans le dashboard. Les événements d’exposition utilisent
  désormais `server.domain` pour le FQDN et `server.registered_domain` pour le
  domaine enregistré. `observer.hostname` conserve l’identité de la sonde et
  les visualisations d’exposition ne dépendent plus de `host.name`. Les versions
  Elasticsearch et Kibana `9.5.0` sont confirmées et les contrôles Domaine/FQDN
  sont intégrés au JSON du dashboard selon ce schéma d’API.
- **2026-08-08 — Classification PQC des certificats.** Les OID X.509 de clé
  publique et de signature sont classés sans dépendre de la matérialisation de
  la clé par `cryptography`. ML-DSA et SLH-DSA standardisés sont distingués des
  algorithmes composites ML-DSA/classiques encore hybrides, et les états
  `pqc`, `hybrid`, `partial`, `classical` et `unknown` alimentent un donut du
  dashboard courant. Cette mesure ne qualifie pas l’échange de clés TLS. Lors
  d’un redéploiement, `elastic/setup.py` ne transmet à l’API `_update` que les
  propriétés modifiables des transforms et exclut leur définition `latest`.
- **2026-08-08 — Répertoire des pilotes manuels.** Un lancement avec `runuser`
  depuis un répertoire sous `/root` empêchait le démarrage du moteur Amass sur
  `stat .`. Le lancement depuis `/opt/asmira` a été validé sur `srv` ; cette
  règle est désormais intégrée aux commandes de déploiement. Le service systemd
  reste inchangé, son `WorkingDirectory` étant déjà correct.
- **2026-08-08 — Chargement manuel de la clé Shodan.** Le chargement temporaire
  de `/etc/asmira/asmira.env` dans un sous-shell avant `runuser` a été validé
  sur `srv`. La clé Shodan est ainsi disponible pendant les pilotes sans être
  placée dans les arguments ni conservée dans la documentation.
- **2026-08-08 — Création du dépôt GitHub privé.** Le dépôt
  `archoad/ASMIRA` utilise `main`, exécute la syntaxe et les tests dans GitHub
  Actions et ne prévoit aucune release. Avant le premier commit, les rapports,
  inventaires, captures, bases GeoIP/GeoJSON et périmètres réseau réels ont été
  exclus ou externalisés, puis le contenu destiné à GitHub a été contrôlé avec
  Gitleaks.
