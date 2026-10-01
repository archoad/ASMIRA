# Mémoire du projet Asmira

Dernière mise à jour : 2026-09-30

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
- l'inventaire unique des FQDN et de leurs adresses IPv4/IPv6 ;
- l'analyse indépendante de chaque couple FQDN/IP, puis sa consolidation en
  une entité durable par FQDN ;
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

`webTLS.py` consomme le fichier `hosts_list` daté et analyse chaque couple
FQDN/IP. Il collecte les données DNS, ports, HTTP, TLS, certificats,
chiffrements, WHOIS, GeoIP et Shodan disponibles, puis produit les rapports.
`asmira.py` regroupe ensuite toutes les observations IP d’un même nom dans un
seul événement FQDN. Les captures d'écran et graphiques sont facultatifs.

### Exploitation installée

`asmira.py` est le point d’entrée de production. Il lit
`/etc/asmira/asmira.conf`, valide que les cibles sont des domaines enregistrés,
crée un `run-id` UTC, isole les rapports sous
`/var/lib/asmira/runs/<run-id>/` et produit trois exports NDJSON atomiques sous
`/var/lib/asmira/export/`.

Dans les événements d’exposition, `server.domain` est la clé unique du FQDN et
`asmira.asset.id` est calculé uniquement depuis ce FQDN normalisé. `server.ip`
est multivalué et conserve toutes les adresses observées ; les observations
FQDN/IP détaillées restent sous `asmira.raw.endpoints`.
`server.registered_domain` porte le domaine enregistré. Asmira n’utilise plus
`host.name` pour la cible, car Elastic Agent réserve et enrichit `host.*` avec
l’identité de la machine collectrice `srv`. La sonde reste identifiée par
`observer.hostname`. `dns.question.*` reste la représentation canonique des
observations de découverte DNS.

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
transforms `asmira-discovery-latest` et `asmira-fqdn-latest`, les Data Views et
le dashboard global. Le transform FQDN est dédupliqué sur `server.domain` et ne
porte aucune rétention temporelle : la base conserve durablement au plus un
document par FQDN. Un FQDN absent d’un run complet produit un tombstone
`present=false`, qui met à jour sa ligne sans la supprimer. L’alias
`asmira-exposure-current` filtre les vues sur les FQDN présents ; l’alias
`asmira-exposure-certificates-current` exige en plus une empreinte de
certificat. Un run plafonné par `max_endpoints` ou comportant une source
incomplète est marqué `partial` : il ajoute ou met à jour les FQDN observés mais
n’émet aucun tombstone, afin de ne pas créer de disparitions artificielles.

Les versions installées et confirmées d’Elasticsearch et Kibana sont `9.5.4`
(constaté le 1er octobre 2026). Les data streams Asmira sont configurés en
production avec une rétention de 730 jours (`--retention-days 730`).
Le dashboard provisionné **[archoad] Asmira — Surface d’exposition globale**
contient deux contrôles épinglés dans cet ordre : **Domaine** sur
`server.registered_domain`, puis **FQDN** sur `server.domain`. Cet ordre permet
au choix du domaine de réduire les FQDN proposés.

Le dashboard décrit l’exposition comme le meilleur état connu, car un run
partiel conserve les FQDN antérieurs. Il affiche séparément la santé du
dernier run, construit le volume historique depuis
`asmira.run.counts.fqdns`, et nomme la répartition des changements selon la
période réellement sélectionnée. Les panneaux de découverte DNS utilisent
`asmira-discovery-latest` et ignorent explicitement les contrôles d’exposition,
dont les champs `server.*` n’existent pas dans les événements de découverte.
Des panneaux Markdown précèdent chaque section majeure, les graphiques XY
masquent leurs titres d’axes, et le panneau d’erreurs d’endpoints a été retiré
au profit de la santé synthétique du run. À côté du statut PQC, le panneau
**Suites cryptographiques TLS négociées** répartit
`asmira.exposure.tls.negotiated_cipher`, c’est-à-dire la suite effectivement
négociée lorsque la sonde a pu établir une session TLS.

Les événements d’exposition indexent l’empreinte SHA-256 du certificat, les OID
de sa clé publique et de sa signature, les algorithmes PQC reconnus et le statut
`certificate_pqc_status`. À chaque observation, l’orchestrateur compare les
empreintes et statuts au dernier état connu. Il renseigne
`certificate_changed`, `pqc_status_changed`, ainsi que les valeurs précédentes,
et classe le FQDN `updated` lorsque son état matériel change. Le dashboard
affiche ces transitions dans un tableau dédié.

Les statuts possibles sont `pqc`, `hybrid`, `partial`, `classical` et `unknown`.
Le dashboard courant présente leur répartition dans le donut **Statut PQC des
certificats TLS par FQDN**. ML-DSA et SLH-DSA sont
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
- Le dépôt GitHub public est `archoad/ASMIRA`, sa branche principale est `main`,
  sa licence est `GPL-3.0-only` et aucune release GitHub n’est prévue.
- `AGENTS.md` et `DEPLOYMENT.md` restent des documents locaux ignorés par Git ;
  ils ne sont pas publiés dans le dépôt GitHub.
- Les bases GeoIP et le GeoJSON local ne sont pas versionnés.
- Les écritures atomiques (`atomicWriteJson`, `atomicWriteNdjson`) appliquent
  l’umask du processus au lieu du mode 0600 imposé par `mkstemp()` : sous
  `UMask=0027`, les rapports, exports et états sont créés en 0640. Sur `srv`,
  le compte de maintenance `codex` lit `/var/lib/asmira` par ACL (accès et
  défaut), `.config` restant fermé ; le répertoire n’est pas ouvert aux autres
  comptes.
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
- La base entity-centric utilise `server.domain` comme clé unique durable. Les
  runs ajoutent ou mettent à jour cette ligne ; ils ne créent pas une ligne par
  adresse IP et la base ne comporte pas de rétention temporelle.
- Les dépendances TLS Python validées en production sont
  `cryptography==46.0.7` et `pyOpenSSL==26.0.0`. Conserver leurs contraintes
  compatibles lors des futures mises à jour.
- Shodan DNS (`/dns/domain`) consomme un crédit de requête par page ; le plan
  `dev` en fournit 100 par mois. Le collecteur interroge `/api-info` avant la
  collecte, répartit les crédits restants entre les domaines, réutilise ceux
  laissés par les domaines terminés, et marque la source en échec (run
  `partial`) lorsque le budget est épuisé, en conservant les pages obtenues.
  `shodan_history` vaut `false` par défaut pour limiter le nombre de pages.
- Cert Spotter est utilisé sans clé (quota non authentifié d’une dizaine de
  requêtes, porté par l’IP de `srv`). Le collecteur est incrémental : il
  conserve par domaine le curseur `after` et les noms déjà vus dans
  `[storage] state_dir/certspotter.json` (défaut `/var/lib/asmira/state`),
  sauvegarde sa progression après chaque page, sérialise ses requêtes, gère
  lui-même les 429 (attente de `Retry-After` dans un budget cumulé de 30 min
  par run) et conserve les noms connus lorsqu’il s’arrête. Supprimer ce
  fichier force un rechargement complet de l’historique.
- La classification PQC des certificats repose sur les OID X.509 et doit rester
  disponible même si `cryptography` ne sait pas construire l’objet de clé
  publique correspondant. Un OID non reconnu est `unknown`, jamais supposé
  classique.

## Vérification de référence

Depuis la racine du dépôt :

```sh
python3 -m py_compile asmira.py asmiraCommon.py asmiraGrade.py fqdnCollect.py webTLS.py elastic/setup.py tests/test_asmira.py tests/test_deployment_assets.py tests/test_fqdn_collect.py tests/test_grade.py tests/test_web_tls.py
python3 -m pytest -q
```

## Feuille de route validée le 1er octobre 2026

Objectifs reprécisés : découverte exhaustive des FQDN des domaines ciblés,
ports et certificats de chaque FQDN, note de conformité TLS par FQDN avec suivi
des corrections, visibilité DNS/CAA pour le déploiement d’ACME interne, et
visibilité PQC. La notion de propriétaire par FQDN n’est pas retenue.

1. Corrections et indexation : bug de la suite TLS 1.3 négociée, indexation
   des champs de certificat déjà collectés, HSTS, note v1 (`asmiraGrade.py`,
   modèle inspiré de SSL Labs, versionné) et sections Synthèse, Conformité,
   Certificats du dashboard. **Déployée sur `srv` (code et mapping) le
   1er octobre 2026.**
2. Collecte DNS/CAA : présence d’un CAA effectif par FQDN et autorités
   autorisées ; graphe FQDN avec ou sans CAA et CA autorisée.
3. Sonde PQC : échange de clés hybride ML-KEM (`X25519MLKEM768`, OpenSSL 3.5
   disponible sur `srv`) et vue PQC.
4. Constats et suivi des corrections (sans propriétaires).
5. Ports élargis à 22, 25, 80, 443, 465, 587, 993, 995, 3389, 8080 et 8443,
   avec un indicateur de présence TLS par port pour repérer les services non
   chiffrés.

Les phases 2 à 5 sont réalisées et validées sur les données du 29 septembre,
puis déployées sur `srv` (code et mapping) le 1er octobre 2026, avant le run de
test du soir. `setup.py` pousse désormais tout le bloc `exposure` du mapping
sur les index existants. Le
dashboard refondu (49 panneaux) est publié dans Kibana sous l’identifiant
`asmira-global-preview` en attendant de remplacer `asmira-global`. Le fichier
`elastic/kibana/asmira-global-dashboard.json` en reste la source de vérité.

Points techniques retenus :

- Le CAA effectif suit la RFC 8659 jusqu’au domaine enregistré ; 189 FQDN
  résolus avaient un CAA au 29 septembre, posé sur des sous-domaines.
- La sonde PQC lit d’abord le groupe négocié par la connexion `testTLS`
  (OpenSSL 3.5 propose ML-KEM en premier) et ne force une négociation limitée
  aux groupes ML-KEM que si le serveur a choisi un groupe classique.
- Un port à TLS implicite dont la connexion TCP aboutit sans réponse TLS est
  classé en clair : un serveur TLS répond toujours au ClientHello.
- Le port 80 est classé en clair sans sonde et n’entre pas dans
  `cleartext_ports`.
- Le suivi des constats est porté par l’entité FQDN (`findings_since` au
  format `CODE@date`), sans nouveau data stream ni modification Fleet.
- Sur `srv`, `fqdnCollect.py` conserve `DEFAULT_HOSTS` adapté à l’opérateur :
  cette valeur locale doit être préservée à chaque déploiement.
- La notion de plages réseau internes (`INTERNAL_NETWORKS`,
  `ASMIRA_INTERNAL_NETWORKS`, champ `pasi`) et le balayage de ces plages ont
  été supprimés le 1er octobre 2026 ; ils n’étaient pas exploités.

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
- **2026-08-08 :** publication du dépôt GitHub `archoad/ASMIRA` sur la branche
  `main` sous licence `GPL-3.0-only`, sans mécanisme de release. Ajout du README,
  de la politique de sécurité et d’une CI de tests. Les données générées, bases
  GeoIP/GeoJSON et périmètres réseau réels sont exclus des commits, validés
  localement par Gitleaks avant publication.
- **2026-08-08 :** `AGENTS.md` et `DEPLOYMENT.md` ont été retirés de l’index Git
  et ajoutés aux exclusions. Le script d’installation tolère désormais
  l’absence du guide opérateur local, et l’unité systemd renvoie vers le README
  public.
- **2026-08-09 :** audit et correction du dashboard global. Le titre
  `[archoad]` est aligné avec l’objet Kibana, l’état courant est décrit comme le
  meilleur état connu lors des runs partiels, la santé du dernier run et la
  découverte DNS sont rendues visibles, le volume historique repose sur les
  compteurs de run et les changements sont qualifiés par la période affichée.
  Le donut PQC utilise un alias filtré sur les endpoints possédant une empreinte
  de certificat afin que son dénominateur corresponde aux certificats analysés.
  Des explications Markdown structurent les sections, les titres d’axes XY sont
  masqués, le panneau vide d’erreurs de cartographie est retiré et les suites
  TLS effectivement négociées sont affichées à côté du statut PQC.
- **2026-08-09 :** passage du modèle courant FQDN/IP au modèle entity-centric
  FQDN. Les observations actives restent exécutées par adresse, mais
  `asmira.py` les consolide en un événement unique par nom normalisé. Le
  transform `asmira-fqdn-latest` est dédupliqué sur `server.domain` sans
  rétention temporelle ; les tombstones conservent les FQDN absents avec
  `present=false`. Les empreintes de certificat et statuts PQC sont comparés au
  dernier état, avec conservation des valeurs précédentes et visualisation des
  transitions dans Kibana.
- **2026-09-30 :** diagnostic de l’échec de Shodan DNS sur `srv` : les 401
  provenaient de l’épuisement des 100 crédits de requête mensuels du plan
  `dev`, et non d’une clé invalide. Le timer se déclenchait tous les deux à
  trois jours et chaque run consommait environ 30 crédits avec
  `history=true`, épuisant le quota vers le 8 du mois. Le timer a été remis au
  rythme hebdomadaire, le collecteur gère désormais un budget de crédits et
  journalise le message d’erreur renvoyé par Shodan, et `shodan_history` passe
  à `false`.
- **2026-09-30 :** Cert Spotter échouait en 429 sur 4 à 6 domaines sur 12 à
  chaque run : chaque run retéléchargeait tout l’historique, jusqu’à quatre
  domaines en parallèle, et un 429 en cours de pagination perdait toutes les
  pages obtenues. Aucune alternative gratuite et fiable n’a été retenue
  (crt.sh est déjà interrogé via Subfinder et renvoyait des 502). Le
  collecteur est devenu incrémental avec état persistant et a été déployé sur
  `srv` ; les premiers runs complètent l’historique des gros domaines et
  peuvent rester `partial`.
- **2026-10-01 :** comparaison de la production Kibana/Elasticsearch `9.5.4`
  avec le dépôt. Dashboard, data views, component template, index templates,
  transforms et alias sont identiques, hors valeurs par défaut ajoutées par
  Kibana. La description du dashboard, vidée en production, est vidée dans le
  dépôt. La rétention des data streams est de 730 jours. Le transform
  historique `asmira-exposure-latest` (ancien modèle FQDN/IP) tournait encore,
  le setup Elasticsearch n’ayant pas été rejoué depuis le 9 août : il a été
  arrêté puis supprimé avec son index, sans référence restante. `setup.py`
  supprime désormais ce transform et cet index au lieu de seulement l’arrêter.
- **2026-10-01 :** création du site d’information statique d’ASMIRA, sur le
  modèle de celui d’OpenIRN : accueil, centre de documentation, carte
  fonctionnelle et huit guides (installation, configuration, intégration
  Elastic, administration, notation et constats, lecture du dashboard,
  référence des données, sécurité). Les guides sont rédigés en Markdown dans
  `site/content/` et générés dans `web/guides/` par `site/build.sh` (pandoc).
  Le site est autonome et sous CSP stricte, sans ressource externe ni style
  inline ; il ne mentionne aucun domaine, serveur ni adresse réels. Il est
  publié sur <https://www.archoad.io/asmira/>. `site/` et le résultat généré
  `web/` (ancien `docs/`) restent locaux et exclus de Git ; les guides n’offrent
  donc pas de lien vers leur source Markdown.
- **2026-10-01 — Approche hybride post-quantique (ANSSI), note v2.** La sonde
  établit désormais la liste exacte des groupes ML-KEM acceptés
  (`pqc_kex_groups`) et distingue les groupes hybrides (`X25519MLKEM768`,
  `SecP256r1MLKEM768`, `SecP384r1MLKEM1024`) de ML-KEM seul, non conforme à la
  position de l’ANSSI (`pqc_kex_status = pure`, constat `PQC_KEX_NOT_HYBRID`).
  `pqc_hybrid` et `pqc_hybrid_level` (`complete`, `key_exchange`, `signature`,
  `none`) signalent l’adoption de l’hybridation, échange de clés et signature
  du certificat. Le modèle de note passe en v2 : +10 points sur l’échange de
  clés avec un groupe hybride, et A+ exige HSTS et l’échange de clés hybride.
