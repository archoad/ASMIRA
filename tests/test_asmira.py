import json
import os
import time
from pathlib import Path

import pytest

import asmira
import asmiraCommon
import webTLS


def writeConfig(filePath, extra=''):
	filePath.write_text(
		'''
[targets]
domains =
	example.com
	example.org

[discovery]
sources = shodan-ctl,certspotter

[active_scan]
enabled = true
authorized = true
endpoint_workers = 3
subprocess_budget = 7
checkpoint_every = 2
max_endpoints = 100

[storage]
runs_dir = /tmp/asmira-runs
export_dir = /tmp/asmira-export
pictures_dir = /tmp/asmira-pictures
retention_days = 14
''' + extra,
		encoding='utf-8',
	)


def testLoadConfigParsesDomainsAndBudgets(tmp_path):
	configFile = tmp_path / 'asmira.conf'
	writeConfig(configFile)

	config = asmiraCommon.loadConfig(configFile)

	assert config.domains == ('example.com', 'example.org')
	assert config.sources == ('shodan-ctl', 'certspotter')
	assert config.activeAuthorized is True
	assert config.endpointWorkers == 3
	assert config.subprocessBudget == 7
	assert config.maxEndpoints == 100


def testLoadConfigRejectsSecrets(tmp_path):
	configFile = tmp_path / 'asmira.conf'
	writeConfig(configFile, '\n[credentials]\napi_key = secret-value\n')

	with pytest.raises(ValueError, match='interdit'):
		asmiraCommon.loadConfig(configFile)


def testRunIdAndAtomicNdjson(tmp_path):
	runId = asmiraCommon.createRunId()
	output = tmp_path / 'events.ndjson'

	count = asmiraCommon.atomicWriteNdjson(output, [
		{'event': 1},
		{'event': 2},
	])

	assert asmiraCommon.validateRunId(runId) == runId
	assert count == 2
	assert [json.loads(line) for line in output.read_text().splitlines()] == [
		{'event': 1},
		{'event': 2},
	]
	assert not list(tmp_path.glob('*.tmp'))


def testDiscoveryEventsKeepWildcardAsEvidence():
	result = {
		'candidates': [
			{
				'name': 'api.example.com',
				'domain': 'example.com',
				'wildcard_pattern': False,
				'sources': ['seed'],
				'evidence': [],
				'collected_at': '2026-07-31T00:00:00+00:00',
			},
			{
				'name': '*.example.com',
				'domain': 'example.com',
				'wildcard_pattern': True,
				'sources': ['certspotter'],
				'evidence': [],
				'collected_at': '2026-07-31T00:00:00+00:00',
			},
		],
		'inventory': [{
			'name': 'api.example.com',
			'resolvable': True,
			'dns_wildcard_zone': False,
			'dns_wildcard_match': False,
			'wildcard_zones': [],
			'dns': {
				'status': 'NOERROR',
				'records': {'A': ['192.0.2.1'], 'AAAA': [], 'CNAME': []},
			},
		}],
	}

	events = asmira.buildDiscoveryEvents(
		result,
		'20260731T200000Z-12345678',
		'2026-07-31T20:00:00+00:00',
	)

	explicit, wildcard = events
	assert explicit['host']['ip'] == ['192.0.2.1']
	assert explicit['asmira']['discovery']['resolvable'] is True
	assert 'host' not in wildcard
	assert wildcard['dns']['question']['name'] == '*.example.com'
	assert wildcard['asmira']['discovery']['wildcard_pattern'] is True


def testExposureEventsProduceStableEntityFields():
	items = [{
		'host': 'www.example.com',
		'ip': '192.0.2.10',
		'domain_name': 'example.com',
		'port22': 'closed',
		'port80': 'open',
		'port443': 'open',
		'live': 'up',
		'geo_country': 'FR',
		'geo_latitude': 48.8,
		'geo_longitude': 2.3,
		'TLSv1.3': ['TLS_AES_256_GCM_SHA384'],
		'certificate_sha256': 'a' * 64,
		'public_key_algorithm_oid': '2.16.840.1.101.3.4.3.18',
		'signature_algorithm_oid': '1.2.840.113549.1.1.11',
		'pqc_algorithms': ['ML-DSA-65'],
		'pqc_status': 'partial',
		'not_after': '30-08-2026',
		'remain': 30,
		'has_expired': False,
		'scan_status': 'success',
		'scan_duration_seconds': 12.5,
		'observed_at': '2026-07-31T20:00:00+00:00',
	}]

	event = asmira.buildExposureEvents(
		items,
		'20260731T200000Z-12345678',
	)[0]

	assert event['server']['ip'] == ['192.0.2.10']
	assert event['server']['address'] == 'www.example.com'
	assert event['server']['domain'] == 'www.example.com'
	assert event['server']['registered_domain'] == 'example.com'
	assert 'host' not in event
	assert event['server']['geo']['location'] == [{'lat': 48.8, 'lon': 2.3}]
	assert event['asmira']['exposure']['port']['443']['state'] == ['open']
	assert event['asmira']['exposure']['present'] is True
	assert event['asmira']['exposure']['change'] == 'new'
	assert event['asmira']['exposure']['tls']['supported_versions'] == ['TLSv1.3']
	assert event['asmira']['exposure']['tls']['certificate_sha256'] == ['a' * 64]
	assert event['asmira']['exposure']['tls']['certificate_public_key_algorithm_oid'] == (
		['2.16.840.1.101.3.4.3.18']
	)
	assert event['asmira']['exposure']['tls']['certificate_signature_algorithm_oid'] == (
		['1.2.840.113549.1.1.11']
	)
	assert event['asmira']['exposure']['tls']['certificate_pqc_algorithms'] == ['ML-DSA-65']
	assert event['asmira']['exposure']['tls']['certificate_pqc_status'] == ['partial']
	assert event['asmira']['exposure']['tls']['certificate_not_after'] == ['2026-08-30']
	assert event['asmira']['exposure']['tls']['certificate_changed'] is False
	assert event['asmira']['exposure']['tls']['pqc_status_changed'] is False
	assert len(event['asmira']['asset']['id']) == 64


def testExposureEventsAggregateEndpointsAndDetectCertificateChangesPerFqdn():
	previous = asmira.buildExposureEvents([{
		'host': 'www.example.com',
		'ip': '192.0.2.10',
		'domain_name': 'example.com',
		'certificate_sha256': 'a' * 64,
		'pqc_status': 'classical',
		'scan_status': 'success',
		'observed_at': '2026-07-24T20:00:00+00:00',
	}], '20260724T200000Z-12345678')

	events = asmira.buildExposureEvents([{
		'host': 'www.example.com',
		'ip': '2001:db8::10',
		'domain_name': 'example.com',
		'certificate_sha256': 'b' * 64,
		'pqc_status': 'pqc',
		'pqc_algorithms': ['ML-DSA-65'],
		'scan_status': 'success',
		'observed_at': '2026-07-31T20:00:00+00:00',
	}, {
		'host': 'www.example.com',
		'ip': '192.0.2.10',
		'domain_name': 'example.com',
		'certificate_sha256': 'b' * 64,
		'pqc_status': 'pqc',
		'pqc_algorithms': ['ML-DSA-65'],
		'scan_status': 'success',
		'observed_at': '2026-07-31T20:00:01+00:00',
	}], '20260731T200000Z-12345678', previousEvents=previous)

	assert len(events) == 1
	event = events[0]
	assert event['server']['domain'] == 'www.example.com'
	assert event['server']['ip'] == ['192.0.2.10', '2001:db8::10']
	assert event['asmira']['exposure']['change'] == 'updated'
	tls = event['asmira']['exposure']['tls']
	assert tls['certificate_sha256'] == ['b' * 64]
	assert tls['certificate_changed'] is True
	assert tls['previous_certificate_sha256'] == ['a' * 64]
	assert tls['certificate_pqc_status'] == ['pqc']
	assert tls['pqc_status_changed'] is True
	assert tls['previous_certificate_pqc_status'] == ['classical']
	assert len(event['asmira']['raw']['endpoints']) == 2


def testExposureEventsCanonicalizeFqdnAndKeepOneEntity():
	events = asmira.buildExposureEvents([{
		'host': 'WWW.Example.COM.',
		'ip': '192.0.2.10',
		'domain_name': 'example.com',
	}, {
		'host': 'www.example.com',
		'ip': '192.0.2.11',
		'domain_name': 'example.com',
	}], '20260731T200000Z-12345678')

	assert len(events) == 1
	assert events[0]['server']['domain'] == 'www.example.com'
	assert events[0]['server']['ip'] == ['192.0.2.10', '192.0.2.11']


def testExposureEventsUpdateReappearingFqdnWithoutLosingCertificateHistory():
	previous = asmira.buildExposureEvents([{
		'host': 'www.example.com',
		'ip': '192.0.2.10',
		'domain_name': 'example.com',
		'certificate_sha256': 'a' * 64,
		'pqc_status': 'classical',
		'observed_at': '2026-07-24T20:00:00+00:00',
	}], '20260724T200000Z-12345678')
	tombstone = asmira.buildExposureEvents(
		[],
		'20260731T200000Z-12345678',
		previousEvents=previous,
	)[0]

	event = asmira.buildExposureEvents([{
		'host': 'www.example.com',
		'ip': '192.0.2.20',
		'domain_name': 'example.com',
		'certificate_sha256': 'b' * 64,
		'pqc_status': 'pqc',
		'observed_at': '2026-08-07T20:00:00+00:00',
	}], '20260807T200000Z-12345678', previousEvents=[tombstone])[0]

	assert event['asmira']['exposure']['change'] == 'updated'
	assert event['asmira']['exposure']['first_seen_at'] == (
		'2026-07-24T20:00:00+00:00'
	)
	tls = event['asmira']['exposure']['tls']
	assert tls['certificate_changed'] is True
	assert tls['previous_certificate_sha256'] == ['a' * 64]
	assert tls['pqc_status_changed'] is True
	assert tls['previous_certificate_pqc_status'] == ['classical']


def testExposureEventsMarkUnchangedFqdnWhenOnlyTimingChanges():
	previous = asmira.buildExposureEvents([{
		'host': 'www.example.com',
		'ip': '192.0.2.10',
		'domain_name': 'example.com',
		'certificate_sha256': 'a' * 64,
		'pqc_status': 'classical',
		'scan_status': 'success',
		'scan_duration_seconds': 1,
	}], '20260724T200000Z-12345678')

	event = asmira.buildExposureEvents([{
		'host': 'www.example.com',
		'ip': '192.0.2.10',
		'domain_name': 'example.com',
		'certificate_sha256': 'a' * 64,
		'pqc_status': 'classical',
		'scan_status': 'success',
		'scan_duration_seconds': 9,
	}], '20260731T200000Z-12345678', previousEvents=previous)[0]

	assert event['asmira']['exposure']['change'] == 'unchanged'
	assert event['asmira']['exposure']['tls']['certificate_changed'] is False
	assert event['asmira']['exposure']['tls']['pqc_status_changed'] is False


def testExposureEventsEmitTombstoneForDisappearedAsset():
	previous = asmira.buildExposureEvents([{
		'host': 'old.example.com',
		'ip': '192.0.2.20',
		'domain_name': 'example.com',
		'port22': 'closed',
		'port80': 'open',
		'port443': 'open',
		'scan_status': 'success',
		'observed_at': '2026-07-24T20:00:00+00:00',
	}], '20260724T200000Z-12345678')
	previous[0]['host'] = {'name': 'old.example.com'}

	events = asmira.buildExposureEvents(
		[],
		'20260731T200000Z-12345678',
		previousEvents=previous,
	)

	assert len(events) == 1
	tombstone = events[0]
	assert tombstone['event']['action'] == 'asset-disappeared'
	assert 'host' not in tombstone
	assert tombstone['server']['domain'] == 'old.example.com'
	assert tombstone['asmira']['exposure']['present'] is False
	assert tombstone['asmira']['exposure']['change'] == 'disappeared'
	assert tombstone['asmira']['exposure']['last_seen_at'] == '2026-07-24T20:00:00+00:00'


def testPartialExposureDoesNotEmitDisappearances():
	previous = asmira.buildExposureEvents([{
		'host': 'old.example.com',
		'ip': '192.0.2.20',
		'domain_name': 'example.com',
		'scan_status': 'success',
	}], '20260724T200000Z-12345678')

	events = asmira.buildExposureEvents(
		[{
			'host': 'pilot.example.com',
			'ip': '192.0.2.30',
			'domain_name': 'example.com',
			'scan_status': 'success',
		}],
		'20260731T200000Z-12345678',
		previousEvents=previous,
		completeObservation=False,
	)

	assert len(events) == 1
	assert events[0]['asmira']['exposure']['change'] == 'new'
	assert events[0]['asmira']['exposure']['present'] is True


def testPreviousExposureStateMergesPartialRunsByFqdn(tmp_path):
	fullRun = asmira.buildExposureEvents([{
		'host': 'one.example.com',
		'ip': '192.0.2.1',
		'domain_name': 'example.com',
		'scan_status': 'success',
	}, {
		'host': 'two.example.com',
		'ip': '192.0.2.2',
		'domain_name': 'example.com',
		'scan_status': 'success',
	}], '20260724T200000Z-12345678')
	partialRun = asmira.buildExposureEvents([{
		'host': 'one.example.com',
		'ip': '192.0.2.10',
		'domain_name': 'example.com',
		'scan_status': 'success',
	}], '20260731T200000Z-12345678', previousEvents=fullRun, completeObservation=False)
	asmiraCommon.atomicWriteNdjson(
		tmp_path / 'asmira_exposure_20260724T200000Z-12345678.ndjson',
		fullRun,
	)
	asmiraCommon.atomicWriteNdjson(
		tmp_path / 'asmira_exposure_20260731T200000Z-12345678.ndjson',
		partialRun,
	)

	previous = asmira.findPreviousExposureEvents(
		tmp_path,
		'20260807T200000Z-12345678',
	)
	eventsByFqdn = {}
	for event in previous:
		eventsByFqdn.setdefault(event['server']['domain'], []).append(event)

	assert set(eventsByFqdn) == {'one.example.com', 'two.example.com'}
	assert eventsByFqdn['one.example.com'][0]['server']['ip'] == ['192.0.2.10']
	assert eventsByFqdn['two.example.com'][0]['server']['ip'] == ['192.0.2.2']


def testPreviousExposureStateKeepsLatestTombstone(tmp_path):
	previous = asmira.buildExposureEvents([{
		'host': 'old.example.com',
		'ip': '192.0.2.1',
		'domain_name': 'example.com',
	}], '20260724T200000Z-12345678')
	tombstone = asmira.buildExposureEvents(
		[],
		'20260731T200000Z-12345678',
		previousEvents=previous,
	)
	asmiraCommon.atomicWriteNdjson(
		tmp_path / 'asmira_exposure_20260724T200000Z-12345678.ndjson',
		previous,
	)
	asmiraCommon.atomicWriteNdjson(
		tmp_path / 'asmira_exposure_20260731T200000Z-12345678.ndjson',
		tombstone,
	)

	state = asmira.findPreviousExposureEvents(
		tmp_path,
		'20260807T200000Z-12345678',
	)

	assert len(state) == 1
	assert state[0]['server']['domain'] == 'old.example.com'
	assert state[0]['asmira']['exposure']['present'] is False


def testTlsAnalyseResumesFromCheckpoint(monkeypatch, tmp_path):
	inputFile = tmp_path / 'targets.json'
	checkpointFile = tmp_path / 'checkpoint.json'
	outputFile = tmp_path / 'output.json'
	first = {'host': 'one.example.com', 'ip': '192.0.2.1', 'scan_status': 'success'}
	second = {'host': 'two.example.com', 'ip': '192.0.2.2'}
	asmiraCommon.atomicWriteJson(inputFile, [
		{'host': first['host'], 'ip': first['ip']},
		second,
	])
	asmiraCommon.atomicWriteJson(checkpointFile, [first])
	calls = []

	def fakeAnalyse(item, captureScreenshots, commandSemaphore, cipherWorkers):
		calls.append(item['host'])
		return({
			**item,
			'scan_status': 'success',
			'scan_error': None,
			'scan_duration_seconds': 1,
			'observed_at': '2026-07-31T20:00:00+00:00',
		})

	monkeypatch.setattr(webTLS, 'analyseEndpoint', fakeAnalyse)

	result = webTLS.tlsAnalyse(
		captureScreenshots=False,
		listIpFile=inputFile,
		destinationFile=outputFile,
		checkpointFile=checkpointFile,
		workers=2,
		checkpointEvery=1,
		generateXlsx=False,
	)

	assert calls == ['two.example.com']
	assert [item['host'] for item in result] == ['one.example.com', 'two.example.com']
	assert json.loads(outputFile.read_text()) == result


def testCleanExportsOnlyRemovesManagedExpiredFiles(tmp_path):
	oldExport = tmp_path / 'asmira_run_old.ndjson'
	recentExport = tmp_path / 'asmira_run_recent.ndjson'
	unmanaged = tmp_path / 'other.ndjson'
	for filePath in (oldExport, recentExport, unmanaged):
		filePath.write_text('{}\n')
	now = time.time()
	os.utime(oldExport, (now - 20 * 86400, now - 20 * 86400))

	removed = asmira.cleanExports(tmp_path, retentionDays=14, currentTime=now)

	assert removed == [oldExport]
	assert not oldExport.exists()
	assert recentExport.exists()
	assert unmanaged.exists()


def testRunnerWritesThreeElasticExports(monkeypatch, tmp_path):
	configFile = tmp_path / 'asmira.conf'
	configFile.write_text(f'''
[targets]
domains = example.com

[discovery]
sources = shodan-ctl

[active_scan]
enabled = true
authorized = true
endpoint_workers = 1
subprocess_budget = 1
checkpoint_every = 1
screenshots = false
graphs = false
xlsx = false

[storage]
runs_dir = {tmp_path / "runs"}
export_dir = {tmp_path / "export"}
pictures_dir = {tmp_path / "pictures"}
retention_days = 14
''')
	config = asmiraCommon.loadConfig(configFile)

	def fakeDiscovery(hosts, **kwargs):
		runDir = Path(kwargs['dataDir'])
		hostsFile = runDir / 'hosts.json'
		asmiraCommon.atomicWriteJson(hostsFile, [{'host': 'www.example.com'}])
		candidate = {
			'name': 'www.example.com',
			'domain': 'example.com',
			'wildcard_pattern': False,
			'sources': ['shodan-ctl'],
			'evidence': [],
			'collected_at': '2026-07-31T20:00:00+00:00',
		}
		inventory = {
			**candidate,
			'resolvable': True,
			'dns_wildcard_zone': False,
			'dns_wildcard_match': False,
			'wildcard_zones': [],
			'dns': {
				'status': 'NOERROR',
				'records': {'A': ['192.0.2.1'], 'AAAA': [], 'CNAME': []},
			},
		}
		return({
			'domains': ['example.com'],
			'candidates': [candidate],
			'inventory': [inventory],
			'hosts': ['www.example.com'],
			'source_reports': [{
				'domain': 'example.com',
				'source': 'shodan-ctl',
				'status': 'success',
			}],
			'wildcard_reports': [],
			'files': {'hosts': str(hostsFile)},
		})

	def fakeExposure(**kwargs):
		return({
			'output': [{
				'host': 'www.example.com',
				'ip': '192.0.2.1',
				'domain_name': 'example.com',
				'port22': 'closed',
				'port80': 'open',
				'port443': 'open',
				'scan_status': 'success',
				'scan_duration_seconds': 1,
				'observed_at': '2026-07-31T20:00:00+00:00',
			}],
			'files': {},
		})

	monkeypatch.setattr(asmira.fqdnCollect, 'hostCartography', fakeDiscovery)
	monkeypatch.setattr(asmira.webTLS, 'configureTools', lambda **kwargs: None)
	monkeypatch.setattr(asmira.webTLS, 'testTools', lambda: None)
	monkeypatch.setattr(asmira.webTLS, 'tlsCartography', fakeExposure)

	result = asmira.run(config, runId='20260731T200000Z-12345678')

	assert result['status'] == 'success'
	exportDir = tmp_path / 'export'
	assert len(list(exportDir.glob('asmira_discovery_*.ndjson'))) == 1
	assert len(list(exportDir.glob('asmira_exposure_*.ndjson'))) == 1
	runFile = next(exportDir.glob('asmira_run_*.ndjson'))
	runEvent = json.loads(runFile.read_text())
	assert runEvent['asmira']['run']['status'] == 'success'
	assert runEvent['asmira']['run']['counts']['endpoints'] == 1
	assert runEvent['asmira']['run']['counts']['fqdns'] == 1
