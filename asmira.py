#!/usr/bin/env python3

import argparse
import json
import socket
import sys
import time
from datetime import datetime
from pathlib import Path

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
				'22': {'state': itemValues(items, 'port22')},
				'80': {'state': itemValues(items, 'port80')},
				'443': {'state': itemValues(items, 'port443')},
			},
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
			event['asmira']['exposure']['change'] = (
				'unchanged' if currentState == previousState else 'updated'
			)
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
		normalized = fqdnCollect.normalizeHost(configuredDomain)
		registeredDomain = fqdnCollect.extractDomain(normalized)
		if normalized != registeredDomain:
			raise ValueError(
				f'La cible {configuredDomain!r} n’est pas un domaine enregistré ; '
				f'utiliser {registeredDomain!r} explicitement si tout ce périmètre est autorisé'
			)
	fqdnCollect.parseSourceNames(','.join(config.sources))
	if config.enableAmass and 'amass' in config.sources:
		raise ValueError(
			'Ne pas ajouter amass à [discovery] sources ; utiliser enable_amass = true'
		)
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
				'[avertissement] Amass actif et brute-force sont autorisés par la configuration ; '
				'Amass v5 peut démarrer son moteur local sur 127.0.0.1:4000.',
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
