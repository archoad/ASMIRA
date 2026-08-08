# Données applicatives locales

Ce répertoire peut contenir les fichiers utilisés par les enrichissements
GeoIP et les graphiques géographiques :

- `geolite2-city.mmdb` ;
- `geolite2-asn.mmdb` ;
- `countries.geojson`.

Ces données ne sont pas versionnées. Installe-les localement depuis une source
autorisée, vérifie leur licence et conserve les noms de fichiers attendus par
`webTLS.py`. Leur absence désactive ou dégrade uniquement les enrichissements
et visualisations concernés.
