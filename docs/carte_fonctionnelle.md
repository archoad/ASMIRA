archoad/ASMIRA · main @ fef1f76 + budget Shodan DNS (non commité) · 30 sept. 2026

# Carte fonctionnelle Asmira

Comment un run hebdomadaire traverse les quatre scripts Python : qui appelle quoi, dans quel ordre, en parallèle ou non, et quels fichiers chaque étape laisse derrière elle. Les noms de fonctions sont ceux du code ; le graphe d’appels a été extrait de l’AST puis vérifié à la lecture.

## Vue d’ensemble

**Deux lectures superposées.** Les flèches pleines portent les données d’une étape à la suivante ; le rail pointillé violet montre que c’est `run()` qui appelle chaque étape, les modules ne s’appellent pas entre eux. La découverte est exportée dès sa fin, avant le scan actif : un échec de cartographie laisse quand même `asmira_discovery_*` et, grâce au `finally`, toujours `asmira_run_*`. Les fichiers de travail vivent sous `/var/lib/asmira/runs/<run-id>/`, les exports sous `/var/lib/asmira/export/`.

asmira.py — orchestration (`main` → `run`)

- main(argv)Point d’entrée du service systemd. Parse `--config`, `--run-id`, `--max-endpoints`, `--discovery-only`, `--validate-config`.
  - loadConfig()asmiraCommon — lit `/etc/asmira/asmira.conf`, refuse tout secret dans le fichier.
  - validateConfigScope()Chaque cible doit être un domaine enregistré (pas un sous-domaine) ; sources connues ; Amass seulement via `enable_amass`.
  - run(config)Crée le run-id UTC et `runs/<id>/`, puis enchaîne :
    - fqdnCollect.hostCartography()Étape 1 — découverte.
    - buildDiscoveryEvents()Un événement par candidat (DNS, sources, wildcard) → `asmira_discovery_<id>.ndjson`.
    - webTLS.configureTools() · testTools()Chemins netcat / nmap / openssl, vérifiés avant tout scan. Exige `[active_scan] authorized = true`.
    - webTLS.tlsCartography()Étape 2 — cartographie active sur `hosts_list.json`.
    - findPreviousExposureEvents()Relit les `asmira_exposure_*` précédents : dernier état connu par FQDN.
    - buildExposureEvents()Étape 3 — consolidation par FQDN et comparaison → `asmira_exposure_<id>.ndjson`.
    - buildRunEvent()Dans le `finally` : statut, `partial`, `coverage_reasons`, compteurs → `asmira_run_<id>.ndjson`.
    - cleanExports()Supprime les NDJSON plus vieux que `retention_days`.

## 1 · Découverte fqdnCollect.py · hostCartography()

Passive, sauf Amass. Transforme une liste de domaines en FQDN explicites qui résolvent aujourd’hui, en gardant la trace de quelle source a vu quoi.

**Toutes les sources voient tous les domaines, en parallèle, et chaque défaillance reste isolée** : `runCollector()` transforme une exception en rapport `failed`, une indisponibilité (clé absente, binaire manquant, crédits à 0) en `skipped`. Tout statut autre que `success` rendra le run `partial`. Un `*.example.com` reste un indice wildcard et n’entre jamais dans `hosts_list`. ● shodan-dns interroge d’abord `/api-info` et répartit les crédits restants entre domaines.

Arbre d’appels — fqdnCollect.py

- hostCartography()Orchestre la découverte et écrit les 5 fichiers datés du run.
  - extractListDomains()Normalise chaque entrée (`extractHostFromRow`, `normalizeHost` : IDNA, labels, pas d’IP) et en tire le domaine enregistré via `extractDomain`. Écrit `domains_list.json`.
  - buildCollectors()Instancie un collecteur par source configurée ; les clés viennent de l’environnement (`SHODAN_API_KEY`, `CERTSPOTTER_API_KEY`).
  - collectFindings()Ajoute chaque domaine comme `seed`, appelle `prepare(domains)` sur chaque collecteur, puis exécute toutes les paires (source, domaine) dans un pool de `collector_workers` threads.
    - runCollector()`availability()` → `collect(domain)` ; convertit tout en rapport `success / failed / skipped` avec durée, secrets masqués par `redactSecrets()`. Garde les résultats partiels levés par `IncompleteCollectionError`. nouveau
    - ShodanCtlCollector.collectGET `ctl.shodan.io/…/hostnames` → liste de noms.
    - SubfinderCollector.collectLance `subfinder -d … -all -oJ` avec délai, lit le JSONL ; la source devient `subfinder:<fournisseur>`.
    - ShodanDnsCollector.prepare`/api-info` (gratuit) → `query_credits` répartis équitablement entre domaines. nouveau
    - ShodanDnsCollector.collectPagine `/dns/domain/<d>` ; chaque page réserve un crédit (`reserveCredit`), le reliquat est rendu au pot commun (`releaseCredits`). Erreurs Shodan journalisées avec leur vrai message (`shodanErrorMessage`). nouveau
    - CertSpotterCollector.collectPagine `/v1/issuances` avec `after` ; garde id, dates et SHA-256 du certificat comme preuve.
    - AmassCollector.collect`amass enum -active -brute` puis `amass subs` ; seulement si `enable_amass`.
    - appendFinding() → createFinding()Normalise le nom, garde le préfixe wildcard, rejette ce qui sort du périmètre du domaine (avertissement, pas d’échec).
  - buildCandidateRecords()Regroupe par (domaine, nom, wildcard), fusionne les sources et dédoublonne les preuves. Écrit `hosts_candidates.json`.
  - resolveCandidateHosts()Valide l’état DNS courant de chaque nom explicite.
    - DnsValidator.resolveHost()A, AAAA, CNAME avec TTL ; statut `NOERROR / NXDOMAIN / ERROR`. Pool de `dns_workers`.
    - getWildcardZones() → getParentZones()Toutes les zones parentes des noms trouvés, plus les motifs `*.` observés.
    - detectWildcardZone()Résout `fqdncollect-<uuid>.zone` ; si tous les échantillons répondent, la zone est wildcard. `dnsSignature()` compare ensuite les réponses d’un hôte à celles du wildcard.
  - writeJson / writeJsonRecordsÉcritures atomiques : `hosts_inventory.json`, `hosts_list.json` (noms explicites résolus), `collection_report.json`.

## 2 · Cartographie active webTLS.py · tlsCartography()

Deux temps : construire la liste des couples FQDN/IP enrichis une fois par IP, puis analyser chaque couple indépendamment, avec reprise sur checkpoint.

**Le coût est borné à deux niveaux.** Les threads (`endpoint_workers`) fixent combien de couples sont analysés à la fois ; le sémaphore `subprocess_budget`, pris par `commandSlot()`, fixe combien de ● sous-processus nmap / openssl / netcat tournent réellement en même temps. Les ports ne sont scannés qu’une fois par IP, même si dix FQDN la partagent. Une exception dans une sonde marque le couple `scan_status = failed` sans arrêter le run. `getAllCipherSuites()` est appelé une seule fois au démarrage pour le repli de `reqNmap`.

Arbre d’appels — webTLS.py

- tlsCartography()Crée le sémaphore de sous-processus et enchaîne les deux temps ; renvoie `output[]` à `asmira.run()`.
  - getAllCipherSuites()`openssl ciphers -v ALL:COMPLEMENTOFALL`, mis en cache dans `cipherList`. sous-processus
  - extractListHosts()Lit `hosts_list.json` produit par la découverte.
  - buildListIps()Construit `list_ip.json`, une entrée par couple FQDN/IP, avec les caches par domaine et par IP.
    - getNameServer()Enregistrements NS du domaine.
    - getDomainInfo() → queryWhois()WHOIS : dates de création/expiration, registrar ; valeurs « inconnues » si échec.
    - getIPs()A et AAAA, triés par `ipSortKey` (compatible IPv4/IPv6).
    - getPorts() → extractNmapPorts()`nmap -Pn -p22,80,443` par IP unique. sous-processus
    - getGeoData()Pays, ville, ASN via les bases GeoIP locales (si présentes).
    - testIPnet()L’IP appartient-elle à `ASMIRA_INTERNAL_NETWORKS` ? → champ `pasi`.
  - tlsAnalyse()Reprend le checkpoint, distribue les couples restants, écrit `hosts_analyse.json` (et le XLSX via `dfToExcel` si activé).
    - analyseEndpoint()Toutes les sondes d’un couple, conditionnées par les ports ouverts ; horodate `observed_at` et mesure la durée.
      - getHTTPData() → reqNetcat()Requête HTTP/1.0 brute : code, raison, en-tête `Server`. sous-processus
      - testShodan() → extractShodanData()Repli si le port 80 ne répond pas : données HTTP que Shodan connaît pour l’IP (`http_source = shodan`). Échecs silencieux.
      - getHTTPheadersHash()GET HTTPS sans vérification ; SHA-256 de la liste ordonnée des en-têtes.
      - getScreenShot()Capture Selenium ; désactivée en production.
      - testTLS() → extractTLSdata()`openssl s_client` avec SNI et vérification : version et suite négociées, chaîne. sous-processus
      - extractCertificateData()Sujet, émetteur, validité, SAN, empreinte SHA-256, auto-signé ou non.
      - classifyCertificatePqc()Classe les OID de clé et de signature : `pqc / hybrid / partial / classical / unknown`.
      - reqNmap() → extractNmapCipher()`nmap --script ssl-enum-ciphers` : suites acceptées par version TLS. sous-processus
      - testAllCipherSuites() → testOneCipherSuite()Repli si nmap ne rend rien : une tentative openssl par suite, en parallèle. sous-processus
  - computeGraphs()Graphiques matplotlib et carte ; désactivés en production.

## 3 · Consolidation et exports asmira.py

Le scan travaille par couple FQDN/IP ; Elastic stocke une entité par FQDN. C’est ici que les observations sont regroupées et comparées au dernier état connu.

**La boucle se ferme par les fichiers, pas par Elasticsearch** : le run suivant relit ses propres exports sur disque pour savoir ce qui a changé. Un FQDN absent n’est déclaré `disappeared` (tombstone `present=false`) que si le run est complet ; dès qu’une source n’est pas `success` ou que `max_endpoints` plafonne le scan, le run est `partial` et aucune disparition n’est émise.

Arbre d’appels — construction des événements

- buildDiscoveryEvents()Joint candidats et inventaire ; champs `dns.question.*`, adresses résolues, sources, indices wildcard.
  - baseEvent() · stableId()Squelette ECS commun (`event.dataset`, `observer.hostname`…) et identifiants déterministes.
- findPreviousExposureEvents()Parcourt `asmira_exposure_*.ndjson` (hors run courant) via `readNdjson()` ; garde le dernier état par FQDN.
- buildExposureEvents()Cœur du modèle entity-centric.
  - previousItems()Récupère les observations brutes (`asmira.raw.endpoints`) d’un ancien événement.
  - buildFqdnObservation()Fusionne les couples d’un même FQDN : `server.ip` multivalué, ports, HTTP, TLS, certificats, PQC, WHOIS, géo ; `asmira.asset.id` dérivé du seul FQDN.
  - exposureState() → eventValues()État « matériel » comparable ; différent → `updated`, avec `certificate_changed` / `pqc_status_changed` et valeurs précédentes.
- buildRunEvent()Statut, durée, compteurs (FQDN, hôtes résolus, disparitions), `failed_sources` / `skipped_sources`, `partial` et ses raisons.
- atomicWriteNdjson()asmiraCommon — écriture temporaire puis renommage : Filestream ne lit jamais un fichier à moitié écrit.

## Socle commun asmiraCommon.py

| Fonction | Rôle | Utilisée par |
| --- | --- | --- |
| `loadConfig()` | Lit l’INI, applique les valeurs par défaut, types et bornes ; `validateNoSecrets()` refuse toute clé dans la config. | asmira |
| `createRunId()` · `validateRunId()` | Identifiant UTC du run, qui préfixe tous les fichiers. | les trois |
| `atomicWriteJson()` · `atomicWriteNdjson()` | Écriture dans un fichier temporaire, `fsync`, puis renommage. | les trois |
| `readJson()` | Lecture tolérante (valeur par défaut si absent) — relit `list_ip.json` et le checkpoint. | webTLS |
| `utcNow()` · `stableId()` | Horodatage ISO UTC ; hash déterministe pour les identifiants d’événements. | les trois |

## Où agir

Les paramètres de `/etc/asmira/asmira.conf` et la fonction qu’ils pilotent.

| Paramètre | Pilote | Effet |
| --- | --- | --- |
| `sources` · `enable_amass` | `buildCollectors()` | Quelles sources tournent ; Amass seulement par son drapeau. |
| `collector_workers` | `collectFindings()` | Paires (source, domaine) simultanées. |
| `source_timeout` · `max_pages` | collecteurs | Délai par source ; pages API maximales par domaine. |
| `shodan_history` | `ShodanDnsCollector` | Historique DNS Shodan : plus de pages, plus de crédits. `false` depuis le 30 sept. |
| `dns_workers` · `dns_timeout` · `wildcard_samples` | `resolveCandidateHosts()` | Parallélisme et rigueur de la validation DNS. |
| `endpoint_workers` | `buildListIps()` · `tlsAnalyse()` | Couples FQDN/IP analysés en parallèle. |
| `subprocess_budget` | `commandSlot()` | Plafond réel de nmap / openssl / netcat simultanés. |
| `checkpoint_every` | `tlsAnalyse()` | Fréquence de sauvegarde pour reprendre un run interrompu. |
| `max_endpoints` | `buildListIps()` | Plafonne le scan (pilotes) ; rend le run `partial`. |
| `authorized` | `run()` | Sans `true`, aucun scan actif ne démarre. |

### Règles qui traversent le code

- Une source qui échoue n’arrête jamais la découverte : elle devient un rapport `failed` ou `skipped`, et le run devient `partial`.
- Un couple FQDN/IP qui échoue n’arrête jamais la cartographie : `scan_status = failed` et on passe au suivant.
- Les secrets ne viennent que de l’environnement et sont masqués par `redactSecrets()` dans tout message d’erreur.
- Toute écriture est atomique ; seul le checkpoint est relu en cours de run.
- Présence dans une source ≠ exposition : seul un nom explicite qui résout aujourd’hui atteint le scan actif.