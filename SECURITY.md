# Politique de sécurité

## Données à ne jamais publier

Ne jamais joindre à une issue, une pull request ou un commit :

- une clé d’API, un token, un mot de passe ou un certificat privé ;
- un fichier `asmira.conf` ou `asmira.env` réel ;
- un inventaire de cibles, un rapport de scan ou un export NDJSON ;
- une capture d’écran ou toute autre donnée issue d’une reconnaissance ;
- une base GeoIP locale dont le droit de redistribution n’est pas établi.

Utiliser uniquement des exemples anonymisés avec les domaines réservés
`example.com`, `example.net` ou `example.org`, et les préfixes documentaires
prévus par les RFC 5737 et 3849.

## Signaler une vulnérabilité

Ne pas ouvrir d’issue publique pour une vulnérabilité ou une fuite potentielle.
Utiliser le signalement privé disponible dans l’onglet **Security** du dépôt
GitHub. Ne transmettre que le minimum nécessaire à la reproduction et révoquer
immédiatement tout secret qui aurait pu être exposé.
