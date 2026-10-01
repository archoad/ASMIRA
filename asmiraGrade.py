#!/usr/bin/env python3
"""Notation TLS d’Asmira, inspirée du guide de notation de Qualys SSL Labs.

Le modèle reprend la structure du guide (trois sous-scores pondérés puis des
plafonds), mais il n’en est pas une reproduction : il ne travaille qu’avec ce
que la sonde observe (versions, suites, certificat, chaîne, HSTS). Toute
modification des seuils, pondérations ou plafonds impose d’incrémenter
GRADE_VERSION, afin que l’historique reste comparable.
"""

import re


GRADE_VERSION = '2'

# Groupes d’échange de clés hybrides : ML-KEM associé à un algorithme classique,
# l’approche exigée par l’ANSSI. Dupliqué de webTLS pour garder ce module sans
# dépendance.
PQC_HYBRID_KEX_GROUPS = ('X25519MLKEM768', 'SecP256r1MLKEM768', 'SecP384r1MLKEM1024')
PQC_HYBRID_KEX_BONUS = 10

# Ordre du meilleur au plus mauvais. T (confiance) et M (nom) sont des
# problèmes de certificat : ils passent devant toute note cryptographique.
GRADE_ORDER = ('A+', 'A', 'A-', 'B', 'C', 'D', 'E', 'F', 'M', 'T')
NOT_GRADED = 'NA'

PROTOCOL_SCORES = {
	'SSLv3': 80,
	'TLSv1.0': 90,
	'TLSv1.1': 95,
	'TLSv1.2': 100,
	'TLSv1.3': 100,
}
SCORE_WEIGHTS = {'protocol': 0.3, 'key_exchange': 0.3, 'cipher': 0.4}
SCORE_GRADES = ((80, 'A'), (65, 'B'), (50, 'C'), (35, 'D'), (20, 'E'))
HSTS_MIN_AGE = 15552000
EXPIRY_WARNING_DAYS = 30
MAX_CERTIFICATE_LIFETIME_DAYS = 398

# code : (gravité, plafond éventuel, texte de correction)
FINDINGS = {
	'TLS_HANDSHAKE_FAILED': ('high', None, 'Le port 443 est ouvert mais aucune session TLS n’a pu être établie.'),
	'CERT_EXPIRED': ('critical', 'T', 'Renouveler le certificat expiré.'),
	'CERT_SELF_SIGNED': ('critical', 'T', 'Remplacer le certificat auto-signé par un certificat émis par une autorité reconnue.'),
	'CHAIN_UNTRUSTED': ('critical', 'T', 'Corriger la chaîne de certification (certificats intermédiaires manquants ou autorité non reconnue).'),
	'CERT_HOSTNAME_MISMATCH': ('critical', 'M', 'Émettre un certificat dont le CN ou les SAN couvrent ce FQDN.'),
	'NULL_OR_EXPORT_CIPHER': ('critical', 'F', 'Désactiver les suites NULL, EXPORT et anonymes.'),
	'WEAK_KEY_UNDER_1024': ('critical', 'F', 'Réémettre le certificat avec une clé RSA d’au moins 2048 bits ou ECDSA P-256.'),
	'MD5_SIGNATURE': ('critical', 'F', 'Réémettre le certificat avec une signature SHA-256 ou plus.'),
	'SSLV3_ENABLED': ('high', 'C', 'Désactiver SSLv3 (POODLE).'),
	'RC4_CIPHER': ('high', 'C', 'Désactiver les suites RC4.'),
	'WEAK_64BIT_CIPHER': ('high', 'C', 'Désactiver les suites à blocs de 64 bits (3DES, DES, IDEA) : Sweet32.'),
	'TLS10_ENABLED': ('medium', 'B', 'Désactiver TLS 1.0.'),
	'TLS11_ENABLED': ('medium', 'B', 'Désactiver TLS 1.1.'),
	'NO_FORWARD_SECRECY': ('medium', 'B', 'Proposer des suites ECDHE ou TLS 1.3 (confidentialité persistante).'),
	'NO_AEAD_CIPHER': ('medium', 'B', 'Proposer des suites AEAD (AES-GCM, ChaCha20-Poly1305).'),
	'WEAK_KEY_UNDER_2048': ('medium', 'B', 'Réémettre le certificat avec une clé RSA d’au moins 2048 bits.'),
	'SHA1_SIGNATURE': ('medium', 'B', 'Réémettre le certificat avec une signature SHA-256 ou plus.'),
	'NO_TLS13': ('low', 'A-', 'Activer TLS 1.3.'),
	'HSTS_MISSING': ('info', None, 'Ajouter l’en-tête Strict-Transport-Security (max-age ≥ 6 mois) pour viser A+.'),
	'CERT_EXPIRES_30D': ('high', None, 'Le certificat expire dans moins de 30 jours : planifier le renouvellement.'),
	'CERT_LIFETIME_OVER_398D': ('medium', None, 'Durée de vie supérieure à 398 jours : non conforme aux exigences CA/B Forum.'),
	'NO_PQC_KEX': ('low', None, 'Activer un échange de clés hybride en TLS 1.3 (X25519MLKEM768, SecP256r1MLKEM768 ou SecP384r1MLKEM1024 ; OpenSSL ≥ 3.5, BoringSSL ou équivalent) contre le déchiffrement différé.'),
	'PQC_KEX_NOT_HYBRID': ('medium', None, 'ML-KEM est proposé seul : l’ANSSI impose de l’associer à un algorithme classique. Proposer un groupe hybride (X25519MLKEM768, SecP256r1MLKEM768 ou SecP384r1MLKEM1024).'),
	'RDP_EXPOSED': ('high', None, 'Le bureau à distance (RDP, 3389) est exposé sur Internet : le placer derrière un VPN ou une passerelle d’accès.'),
	'CLEARTEXT_SERVICE': ('medium', None, 'Un service exposé n’offre pas de chiffrement (TLS ou STARTTLS) : l’activer ou le fermer.'),
	'CAA_ISSUER_NOT_AUTHORIZED': ('high', None, 'Le CAA n’autorise pas l’autorité qui a émis le certificat actuel : le prochain renouvellement échouera. Aligner le CAA ou changer d’autorité.'),
}
SEVERITY_ORDER = ('critical', 'high', 'medium', 'low', 'info')


def maxSeverity(codes):
	severities = [FINDINGS[code][0] for code in codes if code in FINDINGS]
	return(min(severities, key=SEVERITY_ORDER.index) if severities else None)


def gradeRank(grade):
	return(GRADE_ORDER.index(grade) if grade in GRADE_ORDER else len(GRADE_ORDER))


def worstGrade(grades):
	grades = [grade for grade in grades if grade in GRADE_ORDER]
	return(max(grades, key=gradeRank) if grades else None)


def capGrade(grade, cap):
	return(cap if gradeRank(cap) > gradeRank(grade) else grade)


def scoreToGrade(score):
	for threshold, grade in SCORE_GRADES:
		if score >= threshold:
			return(grade)
	return('F')


def cipherBits(name):
	# Accepte les noms IANA (nmap) et OpenSSL (repli testAllCipherSuites).
	value = name.upper().replace('-', '_')
	if 'NULL' in value:
		return(0)
	if 'EXPORT' in value or value.startswith('EXP_'):
		return(40)
	if re.search(r'3DES|DES_EDE|DES_CBC3', value):
		return(112)
	if re.search(r'(^|_)DES(_|$)', value) or 'DES_CBC_' in value:
		return(56)
	if 'RC4' in value or 'SEED' in value or 'IDEA' in value:
		return(128)
	if re.search(r'AES_?256|CHACHA20|CAMELLIA_?256|ARIA_?256', value):
		return(256)
	if re.search(r'AES_?128|CAMELLIA_?128|ARIA_?128', value):
		return(128)
	return(None)


def cipherFlags(name):
	value = name.upper().replace('-', '_')
	return({
		'null_export_anon': bool(re.search(r'NULL|EXPORT|^EXP_|ANON|^ADH_|^AECDH_', value)),
		'rc4': 'RC4' in value,
		'block64': bool(re.search(r'3DES|DES_EDE|DES_CBC|(^|_)DES(_|$)|IDEA', value)),
		# TLS 1.3 (TLS_AES_*, TLS_CHACHA20_*, TLS_AKE_* chez nmap) est toujours éphémère.
		'forward_secrecy': (
			value.startswith(('TLS_AES_', 'TLS_CHACHA20_', 'TLS_AKE_'))
			or 'DHE' in value
			or value.startswith('EDH_')
		),
		'aead': bool(re.search(r'GCM|CHACHA20|CCM', value)),
	})


def bitsScore(bits):
	if bits == 0:
		return(0)
	if bits < 128:
		return(20)
	if bits < 256:
		return(80)
	return(100)


def keyStrength(keyType, keySize):
	# Équivalence RSA des courbes : P-256 ≈ RSA 3072, P-384 ≈ RSA 7680.
	if keyType in ('EllipticCurvePublicKey',):
		return(3072 if (keySize or 0) < 384 else 7680)
	if keyType in ('Ed25519PublicKey', 'X25519PublicKey'):
		return(3072)
	if keyType in ('Ed448PublicKey', 'X448PublicKey'):
		return(7680)
	return(keySize)


def keyScore(strength):
	if strength is None:
		return(None)
	if strength < 512:
		return(20)
	if strength < 1024:
		return(40)
	if strength < 2048:
		return(80)
	if strength < 4096:
		return(90)
	return(100)


def kexClass(item):
	"""Échange de clés post-quantique d’un couple FQDN/IP : hybrid, pure,
	none ou None si la sonde n’a rien établi."""
	groups = item.get('pqc_kex_groups')
	if not isinstance(groups, list):
		groups = [item['pqc_kex_group']] if item.get('pqc_kex_group') else []
	if any(group in PQC_HYBRID_KEX_GROUPS for group in groups):
		return('hybrid')
	if groups or item.get('pqc_kex_supported') is True:
		return('pure')
	if item.get('pqc_kex_supported') is False:
		return('none')
	return(None)


def endpointVersions(item):
	versions = [
		version
		for version in PROTOCOL_SCORES
		if isinstance(item.get(version), list) and item[version]
	]
	if not versions and item.get('negotiated_protocol') in PROTOCOL_SCORES:
		versions = [item['negotiated_protocol']]
	return(versions)


def endpointCiphers(item):
	ciphers = [
		cipher
		for version in PROTOCOL_SCORES
		for cipher in (item.get(version) if isinstance(item.get(version), list) else [])
	]
	if not ciphers and item.get('negotiated_cipher'):
		ciphers = [item['negotiated_cipher']]
	return(ciphers)


def gradeEndpoint(item):
	"""Note un couple FQDN/IP. Renvoie None si le port 443 n’est pas ouvert."""
	if item.get('port443') != 'open':
		return(None)
	if not item.get('certificate_sha256'):
		return({
			'grade': NOT_GRADED,
			'grade_if_trusted': NOT_GRADED,
			'score': None,
			'protocol_score': None,
			'key_exchange_score': None,
			'cipher_score': None,
			'findings': ['TLS_HANDSHAKE_FAILED'],
		})

	findings = set()
	versions = endpointVersions(item)
	ciphers = endpointCiphers(item)

	protocolScores = [PROTOCOL_SCORES[version] for version in versions]
	protocolScore = (
		(max(protocolScores) + min(protocolScores)) / 2 if protocolScores else None
	)
	strength = keyStrength(item.get('public_key'), item.get('key_size'))
	keyExchangeScore = keyScore(strength)
	kex = kexClass(item)
	if kex == 'hybrid' and keyExchangeScore is not None:
		# v2 : l’échange de clés hybride ML-KEM renforce le sous-score.
		keyExchangeScore = min(100, keyExchangeScore + PQC_HYBRID_KEX_BONUS)
	bits = [value for value in (cipherBits(cipher) for cipher in ciphers) if value is not None]
	cipherScore = (bitsScore(max(bits)) + bitsScore(min(bits))) / 2 if bits else None

	parts = {
		'protocol': protocolScore,
		'key_exchange': keyExchangeScore,
		'cipher': cipherScore,
	}
	known = {name: value for name, value in parts.items() if value is not None}
	if known:
		weight = sum(SCORE_WEIGHTS[name] for name in known)
		score = round(sum(SCORE_WEIGHTS[name] * value for name, value in known.items()) / weight)
	else:
		score = None

	if 'SSLv3' in versions:
		findings.add('SSLV3_ENABLED')
	if 'TLSv1.0' in versions:
		findings.add('TLS10_ENABLED')
	if 'TLSv1.1' in versions:
		findings.add('TLS11_ENABLED')
	if versions and 'TLSv1.3' not in versions:
		findings.add('NO_TLS13')
	flags = [cipherFlags(cipher) for cipher in ciphers]
	if any(flag['null_export_anon'] for flag in flags):
		findings.add('NULL_OR_EXPORT_CIPHER')
	if any(flag['rc4'] for flag in flags):
		findings.add('RC4_CIPHER')
	if any(flag['block64'] for flag in flags):
		findings.add('WEAK_64BIT_CIPHER')
	if flags and not any(flag['forward_secrecy'] for flag in flags):
		findings.add('NO_FORWARD_SECRECY')
	if flags and not any(flag['aead'] for flag in flags):
		findings.add('NO_AEAD_CIPHER')
	if strength is not None and strength < 1024:
		findings.add('WEAK_KEY_UNDER_1024')
	elif strength is not None and strength < 2048:
		findings.add('WEAK_KEY_UNDER_2048')
	signatureHash = (item.get('signature_hash') or '').lower()
	if signatureHash == 'md5':
		findings.add('MD5_SIGNATURE')
	elif signatureHash == 'sha1':
		findings.add('SHA1_SIGNATURE')

	if item.get('has_expired'):
		findings.add('CERT_EXPIRED')
	if item.get('self-signed'):
		findings.add('CERT_SELF_SIGNED')
	verifyMessage = (item.get('verify_message') or '').lower()
	if 'hostname mismatch' in verifyMessage:
		findings.add('CERT_HOSTNAME_MISMATCH')
	elif item.get('chain_valid') is False and not item.get('has_expired') and not item.get('self-signed'):
		findings.add('CHAIN_UNTRUSTED')
	remain = item.get('remain')
	if isinstance(remain, int) and 0 < remain <= EXPIRY_WARNING_DAYS:
		findings.add('CERT_EXPIRES_30D')
	lifetime = item.get('certificate_lifetime_days')
	if isinstance(lifetime, int) and lifetime > MAX_CERTIFICATE_LIFETIME_DAYS:
		findings.add('CERT_LIFETIME_OVER_398D')
	# Hors notation SSL Labs : objectif PQC de l’entité, sans plafond.
	if kex == 'none':
		findings.add('NO_PQC_KEX')
	elif kex == 'pure':
		findings.add('PQC_KEX_NOT_HYBRID')
	hstsMaxAge = item.get('hsts_max_age')
	if not isinstance(hstsMaxAge, int) or hstsMaxAge < HSTS_MIN_AGE:
		findings.add('HSTS_MISSING')

	grade = scoreToGrade(score) if score is not None else 'F'
	trustCaps = []
	for code in findings:
		cap = FINDINGS[code][1]
		if cap in ('T', 'M'):
			trustCaps.append(cap)
		elif cap is not None:
			grade = capGrade(grade, cap)
	# v2 : A+ exige HSTS et un échange de clés hybride sur l’adresse notée.
	if grade == 'A' and kex == 'hybrid' and not (findings & {'HSTS_MISSING', 'NO_TLS13'}):
		grade = 'A+'
	gradeIfTrusted = grade
	if trustCaps:
		grade = worstGrade(trustCaps)

	return({
		'grade': grade,
		'grade_if_trusted': gradeIfTrusted,
		'score': score,
		'protocol_score': None if protocolScore is None else round(protocolScore),
		'key_exchange_score': keyExchangeScore,
		'cipher_score': None if cipherScore is None else round(cipherScore),
		'findings': sorted(findings),
	})


def gradeFqdn(items):
	"""Agrège les couples d’un FQDN : la note retenue est celle de la pire IP."""
	results = [result for result in (gradeEndpoint(item) for item in items) if result]
	if not results:
		return(None)
	graded = [result for result in results if result['grade'] != NOT_GRADED]

	def worst(fieldName):
		values = [result[fieldName] for result in graded if result[fieldName] is not None]
		return(min(values) if values else None)

	findings = sorted({code for result in results for code in result['findings']})
	return({
		'grade': worstGrade(result['grade'] for result in graded) or NOT_GRADED,
		'grade_if_trusted': (
			worstGrade(result['grade_if_trusted'] for result in graded) or NOT_GRADED
		),
		'grade_version': GRADE_VERSION,
		'score': worst('score'),
		'protocol_score': worst('protocol_score'),
		'key_exchange_score': worst('key_exchange_score'),
		'cipher_score': worst('cipher_score'),
		'findings': findings,
		'findings_severity': sorted(
			{FINDINGS[code][0] for code in findings},
			key=SEVERITY_ORDER.index,
		),
	})
