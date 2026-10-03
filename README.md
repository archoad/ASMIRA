# Asmira

**Attack Surface Mapping, Inventory, Reconnaissance & Analysis**

Asmira découvre et cartographie une surface d’exposition externe. Il agrège
des observations passives, valide leur état DNS, construit un inventaire
de FQDN uniques puis analyse les services HTTP et TLS de chaque endpoint
FQDN/IP explicitement autorisé. Les observations de toutes les adresses d’un
même FQDN sont consolidées dans une seule entité courante, mise à jour à chaque
run.

## Principes de sécurité

- Une observation passive ou historique ne prouve pas qu’un hôte est exposé :
  seule la validation DNS détermine son état actuel.
- La collecte passive et la reconnaissance active restent séparées.
- Amass actif nécessite `--enable-amass` et une cible autorisée fournie
  explicitement ; la cible passive par défaut n’est jamais réutilisée.
- Le brute-force DNS et la tentative de transfert de zone de dnsx nécessitent
  `--enable-dnsx`, une liste de mots lisible et une cible autorisée fournie
  explicitement.
- La cartographie HTTP/TLS nécessite `--authorized-active-scan`.
- Les secrets sont lus depuis l’environnement et ne doivent jamais être placés
  dans le dépôt, les arguments, les journaux ou les rapports.
- Les inventaires, rapports, captures et bases de données locales sont ignorés
  par Git.

## Composants

- `fqdnCollect.py` : découverte multisource, normalisation et validation DNS ;
- `webTLS.py` : cartographie FQDN/IP, HTTP, TLS, certificats et reporting ;
- `asmira.py` : orchestration, consolidation unique par FQDN, détection des
  changements et exports NDJSON ;
- `asmiraGrade.py` : notation TLS des FQDN et constats associés ;
- `asmiraReport.py` : bilan HTML autonome de chaque run et e-mail de
  synthèse ;
- `asmiraCommon.py` : configuration, identifiants et écritures atomiques ;
- `elastic/` : mappings, transforms, configuration Fleet et dashboard Kibana ;
- `deploy/` : installation Debian et unités systemd.

La documentation détaillée (installation, configuration, intégration Elastic,
administration, notation) et la carte fonctionnelle sont publiées sur
<https://www.archoad.io/asmira/>.

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
python3 -m py_compile asmira.py asmiraCommon.py asmiraGrade.py asmiraReport.py fqdnCollect.py webTLS.py elastic/setup.py tests/test_asmira.py tests/test_deployment_assets.py tests/test_fqdn_collect.py tests/test_grade.py tests/test_report.py tests/test_web_tls.py
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

Amass 4.2.0 est requis : la version 5, qui ne restitue pas ses découvertes
(issue owasp-amass/amass#1074), est refusée avec un diagnostic explicite.
`--amass-timeout` (ou `amass_timeout` dans `asmira.conf`) lui donne un délai
propre ; à son dépassement, les noms déjà écrits par Amass sont conservés et la
source est marquée en échec.

Brute-force DNS et tentative de transfert de zone (AXFR) avec dnsx, uniquement
sur un domaine autorisé :

```sh
python3 fqdnCollect.py --enable-dnsx --dnsx-wordlist subdomains.txt example.com
```

dnsx interroge les résolveurs du système (ou ceux de `--dnsx-resolvers`),
jamais sa liste intégrée. Une réponse n’est écartée dans une zone wildcard que
si sa signature DNS complète est identique à celle d’un libellé aléatoire.
AXFR et brute-force partagent le délai maximal du collecteur.

Cartographie active, uniquement sur des cibles autorisées :

```sh
python3 webTLS.py --authorized-active-scan
```

Les assets de déploiement orchestré et d’intégration Elastic sont fournis dans
`deploy/` et `elastic/`. Les procédures opérateur propres à l’environnement de
production restent locales et ne sont pas versionnées. Le projet est distribué
depuis son code source, par versions étiquetées (`v1.0.0` le 1er octobre
2026) dont GitHub fournit les archives.

## Notation TLS

Chaque FQDN servant HTTPS reçoit une note de A+ à F, accompagnée de constats
codés (`TLS10_ENABLED`, `CERT_EXPIRED`, `WEAK_64BIT_CIPHER`…) et du texte de
correction associé. Le modèle s’inspire du
[guide de notation de Qualys SSL Labs](https://github.com/ssllabs/research/wiki/SSL-Server-Rating-Guide)
sans prétendre le reproduire : il ne note que ce que la sonde observe.

- **Score** : protocoles 30 %, échange de clés 30 %, chiffrement 40 %. Les
  seuils A ≥ 80, B ≥ 65, C ≥ 50, D ≥ 35, E ≥ 20 sont ceux du guide. Un échange
  de clés hybride ML-KEM ajoute 10 points au sous-score d’échange de clés.
- **Plafonds** : suites NULL, EXPORT ou anonymes, clé < 1024 bits ou signature
  MD5 → F ; SSLv3, RC4 ou suites à blocs de 64 bits → C ; TLS 1.0 ou 1.1, absence
  de confidentialité persistante ou d’AEAD, clé RSA < 2048 bits ou signature
  SHA-1 → B ; absence de TLS 1.3 → A- ; A sans réserve, HSTS d’au moins six
  mois et échange de clés hybride → A+.
- **Certificat** : T si le certificat est expiré, auto-signé ou si la chaîne
  n’est pas reconnue ; M si le nom n’est pas couvert. La note cryptographique
  reste disponible dans `grade_if_trusted`.
- **Agrégation** : un FQDN à plusieurs IP prend la note de la plus faible ;
  NA désigne un port 443 ouvert sans session TLS exploitable.

Toute modification des seuils ou des plafonds impose d’incrémenter
`GRADE_VERSION`, stocké avec chaque note.

## Indicateurs complémentaires

- **Ports et chiffrement** : 22, 25, 80, 443, 465, 587, 993, 995, 3389, 8080 et
  8443 sont sondés. Pour chaque port ouvert, Asmira vérifie la présence de TLS
  direct, de STARTTLS (SMTP), de CredSSP/TLS (RDP) ou classe le port en SSH ;
  un port n’est classé en clair que sur preuve, et seul le port 80 (HTTP) ne
  compte pas comme service non chiffré. Un 8080 en clair qui redirige vers une
  URL `https://` est classé `redirect` et n’est pas compté non plus : la
  redirection prouve que le service n’est servi qu’en TLS. Les
  constats `CLEARTEXT_SERVICE` et `RDP_EXPOSED` s’appliquent aussi aux FQDN sans
  HTTPS.
- **CAA** : le CAA effectif de chaque FQDN est celui qu’une autorité appliquerait
  (RFC 8659), avec les autorités autorisées et l’existence connue d’une offre
  ACME. `CAA_ISSUER_NOT_AUTHORIZED` signale un certificat dont l’émetteur n’est
  pas autorisé par le CAA.
- **PQC** : conformément à la position de l’ANSSI, seule l’association d’un
  algorithme classique et d’un algorithme post-quantique normalisé est jugée
  conforme. Chaque groupe TLS 1.3 (`X25519MLKEM768`, `SecP256r1MLKEM768`,
  `SecP384r1MLKEM1024`, ML-KEM seul) est testé par une négociation réelle. Les
  indicateurs `pqc_hybrid` et `pqc_hybrid_level` signalent les FQDN qui ont
  adopté l’approche hybride, pour l’échange de clés et la signature du
  certificat (ML-DSA composite).
- **Suivi des constats** : chaque constat est daté de sa première observation ;
  chaque run indique les constats apparus et corrigés.

## Bilan de run

Après chaque run, `asmira.py` écrit `runs/<run-id>/<run-id>_report.html`, un
bilan détaillé autonome (CSS et graphiques SVG intégrés, ni script ni ressource
externe, CSP `default-src 'none'`) : synthèse et points d’attention, durées,
sources par domaine et apport de chacune (dont les noms vus seulement par Amass
et dnsx), surface par domaine, nouveaux FQDN et FQDN prioritaires, notes TLS
comparées au run précédent, PQC, certificats, autorités émettrices, CAA,
constats avec leur correction, chiffrement par port et hébergement. Avec
`[report] email = true`, un e-mail texte résume le run et porte le bilan en
pièce jointe ; il passe par le relais SMTP configuré (le MTA local par défaut),
un mot de passe éventuel étant lu dans `ASMIRA_SMTP_PASSWORD`. Un échec du
bilan ou de l’envoi est signalé dans le journal sans affecter le run. Le bilan
décrit la surface d’attaque : il est sensible.

## Licence

Asmira est distribué sous la licence **GNU General Public License version 3
uniquement** (`GPL-3.0-only`). Voir [`LICENSE`](LICENSE).
