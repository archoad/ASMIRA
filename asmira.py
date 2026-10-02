#!/usr/bin/env python3

import argparse
import json
import socket
import sys
import time
from datetime import datetime
from pathlib import Path

import asmiraGrade
import fqdnCollect
import webTLS
from asmiraCommon import (
	DEFAULT_CONFIG_PATH,
	atomicWriteNdjson,
	createRunId,
	loadConfig,
	stableId,
	utcNow,
	validateRunId,
)


def baseEvent(dataset, runId, timestamp, eventId, action, outcome='success'):
	return({
		'@timestamp': timestamp,
		'data_stream': {
			'type': 'logs',
			'dataset': f'asmira.{dataset}',
			'namespace': 'default',
		},
		'event': {
			'id': eventId,
			'kind': 'state',
			'category': ['host', 'network'],
			'type': ['info'],
			'dataset': f'asmira.{dataset}',
			'action': action,
			'outcome': outcome,
		},
		'observer': {
			'hostname': socket.gethostname(),
			'product': 'Asmira',
			'type': 'external-scan',
			'vendor': 'Asmira',
		},
		'asmira': {
			'run': {'id': runId},
		},
	})


# Identifiants CAA usuels → (autorité, offre ACME publique connue). Indicatif :
# un identifiant absent de la table est affiché tel quel, sans présumer d’ACME.
CAA_AUTHORITIES = {
	'letsencrypt.org': ('Let\'s Encrypt', True),
	'pki.goog': ('Google Trust Services', True),
	'sectigo.com': ('Sectigo', True),
	'comodoca.com': ('Sectigo', True),
	'comodo.com': ('Sectigo', True),
	'usertrust.com': ('Sectigo', True),
	'trust-provider.com': ('Sectigo', True),
	'digicert.com': ('DigiCert', True),
	'symantec.com': ('DigiCert', True),
	'geotrust.com': ('DigiCert', True),
	'rapidssl.com': ('DigiCert', True),
	'thawte.com': ('DigiCert', True),
	'digitalcertvalidation.com': ('DigiCert', True),
	'globalsign.com': ('GlobalSign', True),
	'buypass.com': ('Buypass', True),
	'buypass.no': ('Buypass', True),
	'ssl.com': ('SSL.com', True),
	'actalis.it': ('Actalis', True),
	'harica.gr': ('HARICA', True),
	'amazon.com': ('Amazon', False),
	'amazontrust.com': ('Amazon', False),
	'awstrust.com': ('Amazon', False),
	'amazonaws.com': ('Amazon', False),
	'microsoft.com': ('Microsoft', False),
	'entrust.net': ('Entrust', None),
	'certigna.fr': ('Certigna', None),
	'certinomis.com': ('Certinomis', None),
	'certinomis.fr': ('Certinomis', None),
}
CAA_DENY_ALL = '(aucune)'


def caaIssuerDomain(value):
	return(value.split(';', 1)[0].strip().lower())


def caaFields(caa):
	if not isinstance(caa, dict) or caa.get('status') not in ('present', 'absent', 'error'):
		return(None)
	records = [record for record in caa.get('records') or [] if isinstance(record, dict)]

	def tagValues(tag):
		return([record['value'] for record in records if record.get('tag') == tag])

	issue = sortedUnique(caaIssuerDomain(value) or CAA_DENY_ALL for value in tagValues('issue'))
	issueWild = sortedUnique(
		caaIssuerDomain(value) or CAA_DENY_ALL for value in tagValues('issuewild')
	)
	authorities = sortedUnique(
		CAA_AUTHORITIES.get(domain, (domain, None))[0] if domain != CAA_DENY_ALL else CAA_DENY_ALL
		for domain in issue
	)
	acme = [CAA_AUTHORITIES.get(domain, (None, None))[1] for domain in issue]
	return({
		'status': caa['status'],
		'source': caa.get('source'),
		'issue': issue,
		'issuewild': issueWild,
		'iodef': sortedUnique(tagValues('iodef')),
		'authorized_ca': authorities,
		'acme_available': True if any(acme) else (False if acme and all(v is False for v in acme) else None),
		# RFC 8657 : accounturi / validationmethods n’ont de sens qu’avec ACME.
		'acme_parameters': any(
			'accounturi=' in value or 'validationmethods=' in value
			for value in tagValues('issue') + tagValues('issuewild')
		),
		'deny_all': issue == [CAA_DENY_ALL],
	})


# Noms d’émetteurs historiques rattachés à l’autorité qui les a absorbés.
ISSUER_ALIASES = {
	'comodo': 'sectigo',
	'usertrust': 'sectigo',
	'geotrust': 'digicert',
	'thawte': 'digicert',
	'rapidssl': 'digicert',
	'symantec': 'digicert',
}


def issuerAuthorizedByCaa(caa, issuerOrganizations):
	# Rapprochement par nom : « GlobalSign » autorise « GlobalSign nv-sa ».
	if not caa or caa['status'] != 'present' or not caa['issue'] or not issuerOrganizations:
		return(None)
	authorities = [name.lower() for name in caa['authorized_ca'] if name != CAA_DENY_ALL]

	def names(organization):
		organization = organization.lower()
		return([organization] + [
			canonical for alias, canonical in ISSUER_ALIASES.items() if alias in organization
		])

	return(all(
		any(authority in name for authority in authorities for name in names(organization))
		for organization in issuerOrganizations
	))


def addFindings(tls, codes):
	tls['findings'] = sorted(set(tls.get('findings') or []) | set(codes))
	tls['findings_severity'] = sorted(
		{asmiraGrade.FINDINGS[code][0] for code in tls['findings']},
		key=asmiraGrade.SEVERITY_ORDER.index,
	)
	tls['max_severity'] = asmiraGrade.maxSeverity(tls['findings'])


def pqcKexStatus(items):
	"""hybrid (toutes les adresses proposent un groupe hybride, approche ANSSI),
	pure (ML-KEM seul partout), partial, classical, no_tls13 ou unknown."""
	tlsItems = [item for item in items if item.get('port443') == 'open' and item.get('certificate_sha256')]
	if not tlsItems:
		return(None)
	classes = [asmiraGrade.kexClass(item) for item in tlsItems]
	if all(value == 'hybrid' for value in classes):
		return('hybrid')
	if all(value == 'pure' for value in classes):
		return('pure')
	if any(value in ('hybrid', 'pure') for value in classes):
		return('partial')
	if any(value is None for value in classes):
		return('unknown')
	hasTls13 = any(
		item.get('TLSv1.3') or item.get('negotiated_protocol') == 'TLSv1.3'
		for item in tlsItems
	)
	return('classical' if hasTls13 else 'no_tls13')


def tlsItemsOf(items):
	return([item for item in items if item.get('port443') == 'open' and item.get('certificate_sha256')])


def pqcHybridLevel(kexStatus, certificatePqcStatuses):
	"""Adoption de l’approche hybride : échange de clés et signature du certificat."""
	kex = kexStatus == 'hybrid'
	signature = bool(certificatePqcStatuses) and all(
		status == 'hybrid' for status in certificatePqcStatuses
	)
	if kex and signature:
		return('complete')
	if kex:
		return('key_exchange')
	if signature:
		return('signature')
	return('none')


def parseFindingsSince(values):
	since = {}
	for value in values or []:
		if isinstance(value, str) and '@' in value:
			code, date = value.split('@', 1)
			since[code] = date
	return(since)


def trackFindings(tls, previousFindings, previousSince, previousTimestamp, timestamp):
	"""Date d’ouverture de chaque constat, constats apparus et corrigés depuis le run
	précédent. Un constat déjà présent avant la mise en place du suivi prend la date
	du run précédent, seule date connue."""
	if 'findings' not in tls:
		return
	current = set(tls['findings'])
	previous = set(previousFindings or [])
	since = {}
	for code in current:
		if code in previous:
			since[code] = previousSince.get(code) or previousTimestamp or timestamp
		else:
			since[code] = timestamp
	tls['findings_since'] = sorted(f'{code}@{date}' for code, date in since.items())
	tls['findings_opened'] = sorted(current - previous)
	tls['findings_resolved'] = sorted(previous - current)


def attachDnsContext(items, inventory):
	# Le CAA est copié dans chaque observation : il suit ainsi raw.endpoints et
	# reste disponible quand un run ultérieur recalcule l’état précédent.
	caaByName = {
		record['name']: record.get('caa')
		for record in inventory or []
		if isinstance(record, dict) and record.get('name')
	}
	for item in items:
		caa = caaByName.get(item.get('host'))
		if caa is not None:
			item['caa'] = caa
	return(items)


def parseLegacyDate(value):
	if not isinstance(value, str) or value in ('', 'Unknown'):
		return(None)
	for dateFormat in ('%d-%m-%Y', '%Y-%m-%d'):
		try:
			return(datetime.strptime(value, dateFormat).date().isoformat())
		except ValueError:
			continue
	return(None)


def buildDiscoveryEvents(result, runId, timestamp):
	inventoryByName = {
		record['name']: record
		for record in result['inventory']
	}
	events = []
	for candidate in result['candidates']:
		inventory = inventoryByName.get(candidate['name'])
		dnsData = {} if inventory is None else inventory.get('dns', {})
		addresses = sorted({
			address
			for recordType in ('A', 'AAAA')
			for address in dnsData.get('records', {}).get(recordType, [])
		})
		assetId = stableId('discovery', candidate['domain'], candidate['name'])
		event = baseEvent(
			'discovery',
			runId,
			timestamp,
			stableId(runId, assetId),
			'discovered',
		)
		event['dns'] = {
			'question': {
				'name': candidate['name'],
				'registered_domain': candidate['domain'],
			},
		}
		if not candidate['wildcard_pattern']:
			event['host'] = {'name': candidate['name']}
			if addresses:
				event['host']['ip'] = addresses
		event['asmira'].update({
			'asset': {'id': assetId},
			'discovery': {
				'wildcard_pattern': candidate['wildcard_pattern'],
				'sources': candidate['sources'],
				'resolvable': None if inventory is None else inventory.get('resolvable', False),
				'dns_status': dnsData.get('status'),
				'dns_wildcard_zone': (
					None if inventory is None else inventory.get('dns_wildcard_zone')
				),
				'dns_wildcard_match': (
					None if inventory is None else inventory.get('dns_wildcard_match')
				),
				'wildcard_zones': (
					[] if inventory is None else inventory.get('wildcard_zones', [])
				),
			},
			'raw': {
				'candidate': candidate,
				'inventory': inventory,
			},
		})
		events.append(event)
	return(events)


def readNdjson(filePath):
	records = []
	with Path(filePath).open('r', encoding='utf-8') as fileHandle:
		for lineNumber, line in enumerate(fileHandle, start=1):
			if not line.strip():
				continue
			try:
				record = json.loads(line)
			except json.JSONDecodeError as error:
				raise ValueError(
					f'NDJSON invalide dans {filePath}, ligne {lineNumber}: {error}'
				) from error
			if not isinstance(record, dict):
				raise ValueError(
					f'NDJSON invalide dans {filePath}, ligne {lineNumber}: objet attendu'
				)
			records.append(record)
	return(records)


def findPreviousExposureEvents(exportDir, currentRunId):
	candidates = [
		filePath
		for filePath in Path(exportDir).glob('asmira_exposure_*.ndjson')
		if currentRunId not in filePath.name
	]
	currentByFqdn = {}
	for filePath in sorted(candidates, key=lambda path: path.name):
		eventsByFqdn = {}
		for event in readNdjson(filePath):
			fqdn = event.get('server', {}).get('domain')
			if fqdn:
				fqdn = fqdnCollect.normalizeHost(fqdn)
				eventsByFqdn.setdefault(fqdn, []).append(event)
		for fqdn, events in eventsByFqdn.items():
			presentEvents = [
				event
				for event in events
				if event.get('asmira', {}).get('exposure', {}).get('present', True)
			]
			if presentEvents:
				currentByFqdn[fqdn] = presentEvents
			else:
				currentByFqdn[fqdn] = [max(
					events,
					key=lambda event: event.get('@timestamp', ''),
				)]
	return([
		event
		for fqdn in sorted(currentByFqdn)
		for event in currentByFqdn[fqdn]
	])


def certificateLifetimeDays(item):
	if isinstance(item.get('certificate_lifetime_days'), int):
		return(item['certificate_lifetime_days'])
	notBefore = parseLegacyDate(item.get('not_before'))
	notAfter = parseLegacyDate(item.get('not_after'))
	if not notBefore or not notAfter:
		return(None)
	return((datetime.fromisoformat(notAfter) - datetime.fromisoformat(notBefore)).days)


def gradingItems(items):
	# Les observations antérieures à la notation n’ont pas la durée de vie :
	# elle est recalculée depuis les dates pour que l’état précédent soit comparable.
	return([
		{**item, 'certificate_lifetime_days': certificateLifetimeDays(item)}
		for item in items
	])


def sortedUnique(values):
	uniqueByJson = {}
	for value in values:
		if value in (None, ''):
			continue
		key = json.dumps(value, ensure_ascii=False, sort_keys=True)
		uniqueByJson[key] = value
	return([uniqueByJson[key] for key in sorted(uniqueByJson)])


def itemValues(items, fieldName):
	return(sortedUnique(item.get(fieldName) for item in items))


def itemListValues(items, fieldName):
	return(sortedUnique(
		value
		for item in items
		for value in (
			item.get(fieldName, [])
			if isinstance(item.get(fieldName), list)
			else [item.get(fieldName)]
		)
	))


def eventValues(event, *fieldNames):
	value = event
	for fieldName in fieldNames:
		if not isinstance(value, dict):
			return([])
		value = value.get(fieldName)
	if value in (None, ''):
		return([])
	return(sortedUnique(value if isinstance(value, list) else [value]))


def exposureState(event):
	return({
		'ip': eventValues(event, 'server', 'ip'),
		'http_status': eventValues(event, 'http', 'response', 'status_code'),
		'port22': eventValues(event, 'asmira', 'exposure', 'port', '22', 'state'),
		'port80': eventValues(event, 'asmira', 'exposure', 'port', '80', 'state'),
		'port443': eventValues(event, 'asmira', 'exposure', 'port', '443', 'state'),
		'http_header_hash': eventValues(
			event, 'asmira', 'exposure', 'http', 'header_hash'
		),
		'tls_versions': eventValues(
			event, 'asmira', 'exposure', 'tls', 'supported_versions'
		),
		'cipher_suites': eventValues(
			event, 'asmira', 'exposure', 'tls', 'cipher_suites'
		),
		'negotiated_version': eventValues(
			event, 'asmira', 'exposure', 'tls', 'negotiated_version'
		),
		'negotiated_cipher': eventValues(
			event, 'asmira', 'exposure', 'tls', 'negotiated_cipher'
		),
		'certificate_sha256': eventValues(
			event, 'asmira', 'exposure', 'tls', 'certificate_sha256'
		),
		'certificate_pqc_status': eventValues(
			event, 'asmira', 'exposure', 'tls', 'certificate_pqc_status'
		),
		'certificate_not_after': eventValues(
			event, 'asmira', 'exposure', 'tls', 'certificate_not_after'
		),
		'scan_status': eventValues(event, 'asmira', 'exposure', 'scan', 'status'),
		'tls_grade': eventValues(event, 'asmira', 'exposure', 'tls', 'grade'),
	})


def previousItems(event):
	raw = event.get('asmira', {}).get('raw', {})
	if isinstance(raw.get('endpoints'), list):
		return([
			item
			for item in raw['endpoints']
			if isinstance(item, dict) and item.get('host')
		])
	if isinstance(raw, dict) and raw.get('host'):
		return([raw])
	return([])


def buildFqdnObservation(items, runId):
	items = sorted(
		items,
		key=lambda item: (
			webTLS.ipSortKey(item['ip'])
			if item.get('ip')
			else (0, 0)
		),
	)
	fqdn = fqdnCollect.normalizeHost(items[0].get('host'))
	domainNames = itemValues(items, 'domain_name')
	timestamps = itemValues(items, 'observed_at')
	timestamp = max(timestamps) if timestamps else utcNow()
	assetId = stableId('exposure-fqdn', fqdn)
	scanStatuses = itemValues(items, 'scan_status') or ['success']
	if scanStatuses == ['success']:
		scanStatus = 'success'
	elif 'success' in scanStatuses:
		scanStatus = 'partial'
	else:
		scanStatus = 'failed'
	event = baseEvent(
		'exposure',
		runId,
		timestamp,
		stableId(runId, assetId),
		'active-scan',
		outcome='success' if scanStatus == 'success' else 'failure',
	)
	event['server'] = {
		'address': fqdn,
		'domain': fqdn,
		'registered_domain': domainNames[0] if domainNames else None,
	}
	ipAddresses = sortedUnique(item.get('ip') for item in items)
	if ipAddresses:
		event['server']['ip'] = sorted(ipAddresses, key=webTLS.ipSortKey)
	countries = itemValues(items, 'geo_country')
	locations = sortedUnique(
		{'lat': item['geo_latitude'], 'lon': item['geo_longitude']}
		for item in items
		if item.get('geo_latitude') is not None
		and item.get('geo_longitude') is not None
	)
	if countries or locations:
		event['server']['geo'] = {}
		if countries:
			event['server']['geo']['country_iso_code'] = countries
		if locations:
			event['server']['geo']['location'] = locations
	asNumbers = itemValues(items, 'geo_asn_number')
	asOrganizations = itemValues(items, 'geo_asn_org')
	if asNumbers or asOrganizations:
		event['server']['as'] = {}
		if asNumbers:
			event['server']['as']['number'] = asNumbers
		if asOrganizations:
			event['server']['as']['organization'] = {'name': asOrganizations}
	event['dns'] = {
		'question': {
			'name': fqdn,
			'registered_domain': domainNames[0] if domainNames else None,
		},
	}
	httpStatuses = itemValues(items, 'http_code')
	if httpStatuses:
		event['http'] = {'response': {'status_code': httpStatuses}}
	tlsVersions = sortedUnique(
		version
		for item in items
		for version in webTLS.TLS_VERSIONS
		if isinstance(item.get(version), list) and item[version]
	)
	cipherSuites = sortedUnique(
		cipher
		for item in items
		for version in tlsVersions
		for cipher in (
			item.get(version, [])
			if isinstance(item.get(version), list)
			else []
		)
	)
	certificateDates = sortedUnique(
		parseLegacyDate(item.get('not_after'))
		for item in items
	)
	certificateStartDates = sortedUnique(
		parseLegacyDate(item.get('not_before'))
		for item in items
	)
	grading = asmiraGrade.gradeFqdn(gradingItems(items))
	openPorts = sorted({
		port
		for item in items
		for port in webTLS.SCANNED_PORTS
		if item.get(f'port{port}') == 'open'
	})
	caa = next(
		(fields for fields in (caaFields(item.get('caa')) for item in items) if fields),
		None,
	)
	durations = [
		item.get('scan_duration_seconds')
		for item in items
		if isinstance(item.get('scan_duration_seconds'), (int, float))
	]
	event['asmira'].update({
		'asset': {'id': assetId},
		'exposure': {
			'present': True,
			'change': 'new',
			'first_seen_at': timestamp,
			'last_seen_at': timestamp,
			'endpoint_count': len(items),
			'ip_count': len(ipAddresses),
			'live': itemValues(items, 'live'),
			'port': {
				str(port): {
					'state': itemValues(items, f'port{port}'),
					'tls': itemValues(items, f'tls_port{port}'),
				}
				for port in webTLS.SCANNED_PORTS
			},
			'open_ports': openPorts,
			'cleartext_ports': sorted({
				port
				for item in items
				for port in webTLS.SCANNED_PORTS
				# Seul le port 80 est du HTTP en clair par nature (HTTP_CLEARTEXT_PORTS).
				if port not in webTLS.HTTP_CLEARTEXT_PORTS
				and item.get(f'port{port}') == 'open'
				and item.get(f'tls_port{port}') == 'clear'
			}),
			'services': sortedUnique(
				f'{port}:{item.get(f"tls_port{port}") or "inconnu"}'
				for item in items
				for port in webTLS.SCANNED_PORTS
				if item.get(f'port{port}') == 'open'
			),
			'http': {
				'server': itemValues(items, 'server'),
				'title': itemValues(items, 'web_page_title'),
				'header_hash': itemValues(items, 'hhhash'),
			},
			'tls': {
				'supported_versions': tlsVersions,
				'cipher_suites': cipherSuites,
				'negotiated_version': itemValues(items, 'negotiated_protocol'),
				'negotiated_cipher': itemValues(items, 'negotiated_cipher'),
				'self_signed': itemValues(items, 'self-signed'),
				'chain_valid': itemValues(items, 'chain_valid'),
				'certificate_sha256': itemValues(items, 'certificate_sha256'),
				'certificate_public_key_algorithm_oid': itemValues(
					items, 'public_key_algorithm_oid'
				),
				'certificate_signature_algorithm_oid': itemValues(
					items, 'signature_algorithm_oid'
				),
				'certificate_pqc_algorithms': itemListValues(items, 'pqc_algorithms'),
				'certificate_pqc_status': itemValues(items, 'pqc_status') or ['unknown'],
				'certificate_not_after': certificateDates,
				'certificate_days_remaining': itemValues(items, 'remain'),
				'certificate_expired': itemValues(items, 'has_expired'),
				'issuer_organization': itemValues(items, 'issuer_organization'),
				'issuer_common_name': itemValues(items, 'issuer_common_name'),
				'certificate_not_before': certificateStartDates,
				'certificate_lifetime_days': sortedUnique(
					certificateLifetimeDays(item) for item in items
				),
				'certificate_key_type': itemValues(items, 'public_key'),
				'certificate_key_size': itemValues(items, 'key_size'),
				'certificate_signature_hash': itemValues(items, 'signature_hash'),
				'certificate_subject_alt_names': itemListValues(items, 'subject_alt_names'),
				'verify_message': itemValues(items, 'verify_message'),
				'hsts_max_age': itemValues(items, 'hsts_max_age'),
				'negotiated_group': itemValues(items, 'negotiated_group'),
				'pqc_kex_group': itemValues(items, 'pqc_kex_group'),
				'pqc_kex_groups': itemListValues(items, 'pqc_kex_groups'),
				'pqc_kex_status': pqcKexStatus(items),
				'pqc_kex_preferred': (
					all(item.get('negotiated_group') in asmiraGrade.PQC_HYBRID_KEX_GROUPS for item in tlsItemsOf(items))
					if tlsItemsOf(items) else None
				),
				'certificate_changed': False,
				'pqc_status_changed': False,
				'previous_certificate_sha256': [],
				'previous_certificate_pqc_status': [],
			},
			'scan': {
				'status': scanStatus,
				'error': itemValues(items, 'scan_error'),
				'duration_seconds': round(sum(durations), 3),
			},
		},
		'raw': {'endpoints': items},
	})
	exposure = event['asmira']['exposure']
	tls = exposure['tls']
	if tls['pqc_kex_status'] is not None:
		tls['pqc_hybrid_level'] = pqcHybridLevel(
			tls['pqc_kex_status'],
			[status for status in tls['certificate_pqc_status'] if status != 'unknown'],
		)
		tls['pqc_hybrid'] = tls['pqc_kex_status'] == 'hybrid'
	if caa is not None:
		exposure['dns'] = {'caa': caa}
	if grading is not None:
		tls.update(grading)
		tls.update({'grade_changed': False, 'previous_grade': None})
		authorized = issuerAuthorizedByCaa(caa, itemValues(items, 'issuer_organization'))
		tls['certificate_issuer_authorized'] = authorized
		addFindings(tls, {'CAA_ISSUER_NOT_AUTHORIZED'} if authorized is False else set())
	# Constats d’exposition : ils valent aussi pour un FQDN sans HTTPS.
	exposureFindings = set()
	if exposure['cleartext_ports']:
		exposureFindings.add('CLEARTEXT_SERVICE')
	# RDP n’est signalé que si la sonde a obtenu une réponse RDP : derrière un CDN,
	# le port 3389 peut accepter la connexion sans rien servir.
	if any(item.get('port3389') == 'open' and item.get('tls_port3389') in ('tls', 'clear') for item in items):
		exposureFindings.add('RDP_EXPOSED')
	if exposureFindings:
		addFindings(tls, exposureFindings)
	return(event)


def buildExposureEvents(items, runId, previousEvents=None, completeObservation=True):
	previousEvents = [] if previousEvents is None else previousEvents
	previousEventsByFqdn = {}
	for event in previousEvents:
		fqdn = event.get('server', {}).get('domain')
		if fqdn:
			fqdn = fqdnCollect.normalizeHost(fqdn)
			previousEventsByFqdn.setdefault(fqdn, []).append(event)
	previousByFqdn = {}
	previousPresentByFqdn = {}
	previousSinceByFqdn = {}
	for fqdn, fqdnEvents in previousEventsByFqdn.items():
		presentEvents = [
			event
			for event in fqdnEvents
			if event.get('asmira', {}).get('exposure', {}).get('present', True)
		]
		stateEvents = presentEvents or fqdnEvents
		itemsFromPrevious = [
			item
			for event in stateEvents
			for item in previousItems(event)
		]
		previous = (
			buildFqdnObservation(itemsFromPrevious, runId)
			if itemsFromPrevious
			else max(stateEvents, key=lambda event: event.get('@timestamp', ''))
		)
		firstSeenValues = [
			event.get('asmira', {}).get('exposure', {}).get('first_seen_at')
			or event.get('@timestamp')
			for event in stateEvents
		]
		firstSeenValues = [value for value in firstSeenValues if value]
		if firstSeenValues:
			previous.setdefault('asmira', {}).setdefault('exposure', {})[
				'first_seen_at'
			] = min(firstSeenValues)
		previousByFqdn[fqdn] = previous
		previousPresentByFqdn[fqdn] = bool(presentEvents)
		latest = max(stateEvents, key=lambda event: event.get('@timestamp', ''))
		previousSinceByFqdn[fqdn] = (
			parseFindingsSince(
				latest.get('asmira', {}).get('exposure', {}).get('tls', {}).get('findings_since')
			),
			latest.get('@timestamp'),
		)
	itemsByFqdn = {}
	for item in items:
		if item.get('host'):
			fqdn = fqdnCollect.normalizeHost(item['host'])
			itemsByFqdn.setdefault(fqdn, []).append(item)
	events = []
	for fqdn in sorted(itemsByFqdn):
		event = buildFqdnObservation(itemsByFqdn[fqdn], runId)
		previous = previousByFqdn.get(fqdn)
		if previous is not None:
			currentState = exposureState(event)
			previousState = exposureState(previous)
			currentTls = event['asmira']['exposure']['tls']
			previousExposure = previous.get('asmira', {}).get('exposure', {})
			event['asmira']['exposure']['first_seen_at'] = (
				previousExposure.get('first_seen_at')
				or previous.get('@timestamp')
				or event['@timestamp']
			)
			previousCertificates = previousState['certificate_sha256']
			previousPqcStatuses = previousState['certificate_pqc_status']
			currentTls['certificate_changed'] = (
				currentState['certificate_sha256'] != previousCertificates
			)
			currentTls['pqc_status_changed'] = (
				currentState['certificate_pqc_status'] != previousPqcStatuses
			)
			if currentTls['certificate_changed']:
				currentTls['previous_certificate_sha256'] = previousCertificates
			if currentTls['pqc_status_changed']:
				currentTls['previous_certificate_pqc_status'] = previousPqcStatuses
			previousGrade = previous.get('asmira', {}).get('exposure', {}).get('tls', {}).get('grade')
			if 'grade' in currentTls and previousGrade and previousGrade != currentTls['grade']:
				currentTls['grade_changed'] = True
				currentTls['previous_grade'] = previousGrade
			trackFindings(
				currentTls,
				previous.get('asmira', {}).get('exposure', {}).get('tls', {}).get('findings'),
				*previousSinceByFqdn.get(fqdn, ({}, None)),
				event['@timestamp'],
			)
			event['asmira']['exposure']['change'] = (
				'unchanged' if currentState == previousState else 'updated'
			)
		else:
			trackFindings(event['asmira']['exposure']['tls'], None, {}, None, event['@timestamp'])
		events.append(event)

	disappearedAt = utcNow()
	disappearedFqdns = (
		sorted({
			fqdn
			for fqdn, isPresent in previousPresentByFqdn.items()
			if isPresent and fqdn not in itemsByFqdn
		})
		if completeObservation
		else []
	)
	for fqdn in disappearedFqdns:
		previous = previousByFqdn[fqdn]
		assetId = stableId('exposure-fqdn', fqdn)
		event = baseEvent(
			'exposure',
			runId,
			disappearedAt,
			stableId(runId, assetId, 'disappeared'),
			'asset-disappeared',
		)
		for fieldName in ('server', 'dns'):
			if fieldName in previous:
				event[fieldName] = previous[fieldName]
		previousExposure = previous.get('asmira', {}).get('exposure', {})
		previousTls = previousExposure.get('tls', {})
		event['asmira'].update({
			'asset': {'id': assetId},
			'exposure': {
				**previousExposure,
				'present': False,
				'change': 'disappeared',
				'last_seen_at': previous.get('@timestamp'),
				'tls': {
					**previousTls,
					'certificate_changed': False,
					'pqc_status_changed': False,
					'previous_certificate_sha256': [],
					'previous_certificate_pqc_status': [],
					'grade_changed': False,
					'previous_grade': None,
					'findings_opened': [],
					'findings_resolved': [],
				},
				'scan': {
					'status': 'not_observed',
					'error': None,
					'duration_seconds': 0,
				},
			},
			'raw': {
				'previous_event_id': previous.get('event', {}).get('id'),
			},
		})
		events.append(event)
	return(events)


def buildRunEvent(
	runId,
	startedAt,
	finishedAt,
	status,
	durationSeconds,
	discoveryResult=None,
	exposureResult=None,
	error=None,
):
	event = baseEvent(
		'run',
		runId,
		finishedAt,
		stableId(runId, 'run'),
		'run-completed',
		outcome='success' if status == 'success' else 'failure',
	)
	sourceReports = [] if discoveryResult is None else discoveryResult.get('source_reports', [])
	failedSources = [
		f'{report.get("domain")}:{report.get("source")}'
		for report in sourceReports
		if report.get('status') == 'failed'
	]
	skippedSources = [
		f'{report.get("domain")}:{report.get("source")}'
		for report in sourceReports
		if report.get('status') == 'skipped'
	]
	exposureItems = [] if exposureResult is None else exposureResult.get('output', [])
	exposureItemsByFqdn = {}
	for item in exposureItems:
		if item.get('host'):
			exposureItemsByFqdn.setdefault(item['host'], []).append(item)
	counts = {
		'domains': 0 if discoveryResult is None else len(discoveryResult.get('domains', [])),
		'candidates': 0 if discoveryResult is None else len(discoveryResult.get('candidates', [])),
		'inventory': 0 if discoveryResult is None else len(discoveryResult.get('inventory', [])),
		'resolvable_hosts': 0 if discoveryResult is None else len(discoveryResult.get('hosts', [])),
		'endpoints': len(exposureItems),
		'fqdns': len(exposureItemsByFqdn),
		'failed_endpoints': (
			sum(
				item.get('scan_status') == 'failed'
				for item in exposureItems
			)
		),
		'failed_fqdns': sum(
			all(item.get('scan_status') == 'failed' for item in fqdnItems)
			for fqdnItems in exposureItemsByFqdn.values()
		),
		'disappeared_endpoints': (
			0 if exposureResult is None else exposureResult.get('disappeared', 0)
		),
		'disappeared_fqdns': (
			0 if exposureResult is None else exposureResult.get('disappeared', 0)
		),
		'failed_sources': len(failedSources),
		'skipped_sources': len(skippedSources),
	}
	event['asmira']['run'].update({
		'status': status,
		'partial': False if exposureResult is None else exposureResult.get('partial', False),
		'coverage_reasons': (
			[] if exposureResult is None else exposureResult.get('coverage_reasons', [])
		),
		'started_at': startedAt,
		'finished_at': finishedAt,
		'duration_seconds': round(durationSeconds, 3),
		'counts': counts,
		'failed_sources': failedSources,
		'skipped_sources': skippedSources,
		'error': error,
	})
	return(event)


def cleanExports(exportDir, retentionDays, currentTime=None):
	exportDir = Path(exportDir)
	if not exportDir.is_dir():
		return([])
	currentTime = time.time() if currentTime is None else currentTime
	cutoff = currentTime - retentionDays * 86400
	removed = []
	for filePath in exportDir.glob('asmira_*.ndjson'):
		if filePath.is_file() and filePath.stat().st_mtime < cutoff:
			filePath.unlink()
			removed.append(filePath)
	return(removed)


def validateConfigScope(config):
	for configuredDomain in config.domains:
		fqdnCollect.requireRegisteredDomain(configuredDomain)
	fqdnCollect.parseSourceNames(','.join(config.sources))
	if config.enableAmass and 'amass' in config.sources:
		raise ValueError(
			'Ne pas ajouter amass à [discovery] sources ; utiliser enable_amass = true'
		)
	if config.enableDnsx:
		fqdnCollect.requireReadableFile(config.dnsxWordlist, '[discovery] dnsx_wordlist')
	fqdnCollect.parseDnsxResolvers(config.dnsxResolvers)
	return(True)


def run(config, runId=None, maxEndpoints=None, discoveryOnly=False):
	validateConfigScope(config)
	runId = createRunId() if runId is None else validateRunId(runId)
	startedAt = utcNow()
	startedMonotonic = time.monotonic()
	runDir = config.runsDir / runId
	runDir.mkdir(parents=True, exist_ok=True)
	config.exportDir.mkdir(parents=True, exist_ok=True)
	config.picturesDir.mkdir(parents=True, exist_ok=True)
	config.stateDir.mkdir(parents=True, exist_ok=True)
	discoveryResult = None
	exposureResult = None
	status = 'failed'
	errorMessage = None
	try:
		sourceNames = fqdnCollect.parseSourceNames(','.join(config.sources))
		if config.enableAmass:
			sourceNames.append('amass')
			print(
				'[avertissement] Amass actif et brute-force sont autorisés par la configuration '
				'(Amass 4.2.0 requis ; la v5 est refusée).',
				file=sys.stderr,
			)
		if config.enableDnsx:
			sourceNames.append('dnsx')
			print(
				'[avertissement] dnsx actif : brute-force DNS et tentative de transfert de zone '
				'(AXFR) autorisés par la configuration.',
				file=sys.stderr,
			)
		discoveryResult = fqdnCollect.hostCartography(
			list(config.domains),
			dataDir=runDir,
			txtdnsDir=runDir / 'txtdns',
			stateDir=config.stateDir,
			sourceNames=sourceNames,
			sourceTimeout=config.sourceTimeout,
			maxPages=config.maxPages,
			subfinderPath=config.subfinderPath or fqdnCollect.DEFAULT_SUBFINDER_PATH,
			amassPath=config.amassPath or fqdnCollect.DEFAULT_AMASS_PATH,
			dnsxPath=config.dnsxPath or fqdnCollect.DEFAULT_DNSX_PATH,
			dnsxWordlist=config.dnsxWordlist,
			dnsxResolvers=fqdnCollect.parseDnsxResolvers(config.dnsxResolvers),
			dnsxRateLimit=config.dnsxRateLimit,
			shodanHistory=config.shodanHistory,
			collectorWorkers=config.collectorWorkers,
			dnsWorkers=config.dnsWorkers,
			dnsTimeout=config.dnsTimeout,
			wildcardSamples=config.wildcardSamples,
			runId=runId,
			collectedAt=startedAt,
		)
		discoveryEvents = buildDiscoveryEvents(discoveryResult, runId, startedAt)
		atomicWriteNdjson(
			config.exportDir / f'asmira_discovery_{runId}.ndjson',
			discoveryEvents,
		)

		if config.activeEnabled and not discoveryOnly:
			if not config.activeAuthorized:
				raise RuntimeError(
					'Le scan actif est activé mais [active_scan] authorized n’est pas true'
				)
			webTLS.configureTools(
				netcat=config.netcatPath,
				nmap=config.nmapPath,
				openssl=config.opensslPath,
			)
			webTLS.PICTURES_DIR = config.picturesDir
			webTLS.testTools()
			effectiveMaxEndpoints = (
				maxEndpoints if maxEndpoints is not None else config.maxEndpoints
			)
			exposureResult = webTLS.tlsCartography(
				captureScreenshots=config.captureScreenshots,
				generateGraphs=config.generateGraphs,
				generateXlsx=config.generateXlsx,
				inputFile=discoveryResult['files']['hosts'],
				dataDir=runDir,
				runId=runId,
				endpointWorkers=config.endpointWorkers,
				subprocessBudget=config.subprocessBudget,
				checkpointEvery=config.checkpointEvery,
				maxEndpoints=effectiveMaxEndpoints,
			)
			attachDnsContext(exposureResult['output'], discoveryResult.get('inventory'))
			incompleteSources = [
				f'{report.get("domain")}:{report.get("source")}:{report.get("status")}'
				for report in discoveryResult.get('source_reports', [])
				if report.get('status') != 'success'
			]
			coverageReasons = list(incompleteSources)
			if effectiveMaxEndpoints is not None:
				coverageReasons.append(f'max_endpoints:{effectiveMaxEndpoints}')
			completeObservation = not coverageReasons
			previousExposureEvents = findPreviousExposureEvents(
				config.exportDir,
				runId,
			)
			exposureEvents = buildExposureEvents(
				exposureResult['output'],
				runId,
				previousEvents=previousExposureEvents,
				completeObservation=completeObservation,
			)
			exposureResult['partial'] = not completeObservation
			exposureResult['coverage_reasons'] = coverageReasons
			exposureResult['disappeared'] = sum(
				event['asmira']['exposure']['change'] == 'disappeared'
				for event in exposureEvents
			)
			atomicWriteNdjson(
				config.exportDir / f'asmira_exposure_{runId}.ndjson',
				exposureEvents,
			)
		status = 'success'
	except Exception as error:
		errorMessage = f'{type(error).__name__}: {error}'
		raise
	finally:
		finishedAt = utcNow()
		runEvent = buildRunEvent(
			runId,
			startedAt,
			finishedAt,
			status,
			time.monotonic() - startedMonotonic,
			discoveryResult=discoveryResult,
			exposureResult=exposureResult,
			error=errorMessage,
		)
		atomicWriteNdjson(
			config.exportDir / f'asmira_run_{runId}.ndjson',
			[runEvent],
		)
		cleanExports(config.exportDir, config.retentionDays)
	return({
		'run_id': runId,
		'run_dir': str(runDir),
		'status': status,
		'discovery': discoveryResult,
			'exposure': exposureResult,
	})


def parseArguments(argv=None):
	parser = argparse.ArgumentParser(
		description='Exécute le pipeline Asmira configuré et produit les exports Elastic NDJSON.',
	)
	parser.add_argument('--config', type=Path, default=DEFAULT_CONFIG_PATH)
	parser.add_argument('--run-id')
	parser.add_argument('--max-endpoints', type=int)
	parser.add_argument('--discovery-only', action='store_true')
	parser.add_argument(
		'--validate-config',
		action='store_true',
		help='valide la configuration sans effectuer de collecte',
	)
	return(parser.parse_args(argv))


def main(argv=None):
	args = parseArguments(argv)
	if args.max_endpoints is not None and args.max_endpoints <= 0:
		print('[erreur] --max-endpoints doit être strictement positif', file=sys.stderr)
		return(2)
	try:
		config = loadConfig(args.config)
		validateConfigScope(config)
		if args.validate_config:
			print(json.dumps({
				'status': 'valid',
				'config': str(args.config),
				'domains': len(config.domains),
				'active_scan': config.activeEnabled,
				'active_authorized': config.activeAuthorized,
			}, ensure_ascii=False))
			return(0)
		result = run(
			config,
			runId=args.run_id,
			maxEndpoints=args.max_endpoints,
			discoveryOnly=args.discovery_only,
		)
	except (OSError, RuntimeError, TypeError, ValueError) as error:
		print(f'[erreur] {error}', file=sys.stderr)
		return(1)
	print(
		f'Exécution {result["run_id"]} terminée avec succès ; '
		f'rapports : {result["run_dir"]}'
	)
	return(0)


if __name__ == '__main__':
	sys.exit(main())
