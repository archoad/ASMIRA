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
	if not candidates:
		return([])
	return(readNdjson(max(candidates, key=lambda filePath: filePath.name)))


def buildExposureEvents(items, runId, previousEvents=None, completeObservation=True):
	previousEvents = [] if previousEvents is None else previousEvents
	previousCurrentByAsset = {
		event.get('asmira', {}).get('asset', {}).get('id'): event
		for event in previousEvents
		if (
			event.get('asmira', {}).get('asset', {}).get('id')
			and event.get('asmira', {}).get('exposure', {}).get('present', True)
		)
	}
	events = []
	currentAssetIds = set()
	for item in items:
		timestamp = item.get('observed_at') or utcNow()
		assetId = stableId('exposure', item.get('host'), item.get('ip'))
		currentAssetIds.add(assetId)
		outcome = 'success' if item.get('scan_status', 'success') == 'success' else 'failure'
		event = baseEvent(
			'exposure',
			runId,
			timestamp,
			stableId(runId, assetId),
			'active-scan',
			outcome=outcome,
		)
		event['server'] = {
			'address': item.get('ip') or item.get('host'),
			'domain': item.get('host'),
			'registered_domain': item.get('domain_name'),
		}
		if item.get('ip'):
			event['server']['ip'] = item['ip']
			if item.get('geo_country'):
				event['server']['geo'] = {'country_iso_code': item['geo_country']}
			if item.get('geo_latitude') is not None and item.get('geo_longitude') is not None:
				event.setdefault('server', {}).setdefault('geo', {})['location'] = {
					'lat': item['geo_latitude'],
					'lon': item['geo_longitude'],
				}
			if item.get('geo_asn_number') is not None:
				event['server']['as'] = {
					'number': item['geo_asn_number'],
					'organization': {'name': item.get('geo_asn_org')},
				}
		event['dns'] = {
			'question': {
				'name': item.get('host'),
				'registered_domain': item.get('domain_name'),
			},
		}
		if item.get('http_code') not in ('', None):
			event['http'] = {'response': {'status_code': item['http_code']}}
		tlsVersions = [
			version
			for version in webTLS.TLS_VERSIONS
			if isinstance(item.get(version), list) and item[version]
		]
		cipherSuites = sorted({
			cipher
			for version in tlsVersions
			for cipher in item.get(version, [])
		})
		certificateNotAfter = parseLegacyDate(item.get('not_after'))
		event['asmira'].update({
			'asset': {'id': assetId},
			'exposure': {
				'present': True,
				'change': (
					'unchanged'
					if assetId in previousCurrentByAsset
					else 'new' if completeObservation else 'observed'
				),
				'live': item.get('live'),
				'port': {
					'22': {'state': item.get('port22')},
					'80': {'state': item.get('port80')},
					'443': {'state': item.get('port443')},
				},
				'http': {
					'server': item.get('server'),
					'title': item.get('web_page_title'),
					'header_hash': item.get('hhhash'),
				},
				'tls': {
					'supported_versions': tlsVersions,
					'cipher_suites': cipherSuites,
					'negotiated_version': item.get('negotiated_protocol'),
					'negotiated_cipher': item.get('negotiated_cipher'),
					'self_signed': item.get('self-signed'),
					'chain_valid': item.get('chain_valid'),
					'certificate_sha256': item.get('certificate_sha256'),
					'certificate_public_key_algorithm_oid': item.get('public_key_algorithm_oid'),
					'certificate_signature_algorithm_oid': item.get('signature_algorithm_oid'),
					'certificate_pqc_algorithms': item.get('pqc_algorithms', []),
					'certificate_pqc_status': item.get('pqc_status', 'unknown'),
					'certificate_not_after': certificateNotAfter,
					'certificate_days_remaining': item.get('remain'),
					'certificate_expired': item.get('has_expired'),
					'issuer_organization': item.get('issuer_organization'),
				},
				'scan': {
					'status': item.get('scan_status', 'success'),
					'error': item.get('scan_error'),
					'duration_seconds': item.get('scan_duration_seconds'),
				},
			},
			'raw': item,
		})
		events.append(event)

	disappearedAt = utcNow()
	disappearedAssetIds = (
		sorted(set(previousCurrentByAsset) - currentAssetIds)
		if completeObservation
		else []
	)
	for assetId in disappearedAssetIds:
		previous = previousCurrentByAsset[assetId]
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
		event['asmira'].update({
			'asset': {'id': assetId},
			'exposure': {
				**previousExposure,
				'present': False,
				'change': 'disappeared',
				'last_seen_at': previous.get('@timestamp'),
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
	counts = {
		'domains': 0 if discoveryResult is None else len(discoveryResult.get('domains', [])),
		'candidates': 0 if discoveryResult is None else len(discoveryResult.get('candidates', [])),
		'inventory': 0 if discoveryResult is None else len(discoveryResult.get('inventory', [])),
		'resolvable_hosts': 0 if discoveryResult is None else len(discoveryResult.get('hosts', [])),
		'endpoints': 0 if exposureResult is None else len(exposureResult.get('output', [])),
		'failed_endpoints': (
			0
			if exposureResult is None
			else sum(
				item.get('scan_status') == 'failed'
				for item in exposureResult.get('output', [])
			)
		),
		'disappeared_endpoints': (
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
			previousExposureEvents = (
				findPreviousExposureEvents(config.exportDir, runId)
				if completeObservation
				else []
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
