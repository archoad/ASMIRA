import json
import os
import time
from pathlib import Path

import pytest

import asmira
import asmiraGrade
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


def gradedItem(**overrides):
	item = {
		'host': 'www.example.com',
		'ip': '192.0.2.10',
		'domain_name': 'example.com',
		'port443': 'open',
		'TLSv1.3': ['TLS_AKE_WITH_AES_256_GCM_SHA384'],
		'TLSv1.2': ['TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384'],
		'certificate_sha256': 'a' * 64,
		'public_key': 'RSAPublicKey',
		'key_size': 2048,
		'signature_hash': 'sha256',
		'chain_valid': True,
		'verify_message': 'ok',
		'not_before': '01-07-2026',
		'not_after': '29-09-2026',
		'remain': 60,
		'has_expired': False,
		'scan_status': 'success',
		'observed_at': '2026-07-31T20:00:00+00:00',
	}
	item.update(overrides)
	return(item)


def testExposureEventsCarryGradeAndCertificateDetails():
	event = asmira.buildExposureEvents([gradedItem()], '20260731T200000Z-12345678')[0]
	tls = event['asmira']['exposure']['tls']

	assert tls['grade'] == 'A'
	assert tls['grade_version'] == asmiraGrade.GRADE_VERSION
	assert tls['findings'] == ['HSTS_MISSING']
	assert tls['certificate_lifetime_days'] == [90]
	assert tls['certificate_not_before'] == ['2026-07-01']
	assert tls['certificate_key_size'] == [2048]
	assert tls['grade_changed'] is False


def testExposureEventsDetectGradeChange():
	runId = '20260801T200000Z-12345678'
	previous = asmira.buildExposureEvents(
		[gradedItem(**{'TLSv1.0': ['TLS_RSA_WITH_3DES_EDE_CBC_SHA']})],
		'20260731T200000Z-12345678',
	)

	event = asmira.buildExposureEvents([gradedItem()], runId, previousEvents=previous)[0]
	tls = event['asmira']['exposure']['tls']

	assert event['asmira']['exposure']['change'] == 'updated'
	assert tls['grade_changed'] is True
	assert tls['previous_grade'] == 'C'
	assert tls['grade'] == 'A'


def testExposureEventsWithoutHttpsHaveNoGrade():
	event = asmira.buildExposureEvents(
		[gradedItem(port443='filtered', certificate_sha256=None)],
		'20260731T200000Z-12345678',
	)[0]

	assert 'grade' not in event['asmira']['exposure']['tls']


def caaResult(*records, source='example.com'):
	return({
		'status': 'present',
		'source': source,
		'records': [{'flags': 0, 'tag': tag, 'value': value} for tag, value in records],
	})


def testCaaFieldsNameAuthoritiesAndAcme():
	fields = asmira.caaFields(caaResult(
		('issue', 'letsencrypt.org; validationmethods=dns-01'),
		('issue', 'ca.example.net'),
		('issuewild', ';'),
		('iodef', 'mailto:pki@example.com'),
	))

	assert fields['issue'] == ['ca.example.net', 'letsencrypt.org']
	assert fields['authorized_ca'] == ["Let's Encrypt", 'ca.example.net']
	assert fields['issuewild'] == [asmira.CAA_DENY_ALL]
	assert fields['acme_available'] is True
	assert fields['acme_parameters'] is True
	assert fields['deny_all'] is False


def testCaaFieldsWithoutRecordsAndDenyAll():
	assert asmira.caaFields({'status': 'absent', 'source': None, 'records': []})['authorized_ca'] == []
	denied = asmira.caaFields(caaResult(('issue', ';')))
	assert denied['deny_all'] is True
	assert denied['acme_available'] is None
	assert asmira.caaFields(None) is None


@pytest.mark.parametrize('issuers, expected', [
	(['GlobalSign nv-sa'], True),
	(['COMODO CA Limited'], True),
	(['DigiCert Inc'], False),
	([], None),
])
def testIssuerAuthorizedByCaa(issuers, expected):
	caa = asmira.caaFields(caaResult(('issue', 'globalsign.com'), ('issue', 'sectigo.com')))

	assert asmira.issuerAuthorizedByCaa(caa, issuers) is expected


def testExposureEventsCarryCaaAndFlagUnauthorizedIssuer():
	items = asmira.attachDnsContext(
		[gradedItem(issuer_organization='DigiCert Inc')],
		[{'name': 'www.example.com', 'caa': caaResult(('issue', 'letsencrypt.org'))}],
	)

	event = asmira.buildExposureEvents(items, '20260731T200000Z-12345678')[0]
	exposure = event['asmira']['exposure']

	assert exposure['dns']['caa']['authorized_ca'] == ["Let's Encrypt"]
	assert exposure['tls']['certificate_issuer_authorized'] is False
	assert 'CAA_ISSUER_NOT_AUTHORIZED' in exposure['tls']['findings']
	assert 'high' in exposure['tls']['findings_severity']


HYBRID = {'pqc_kex_supported': True, 'pqc_kex_groups': ['X25519MLKEM768'], 'pqc_kex_hybrid': True}
PURE = {'pqc_kex_supported': True, 'pqc_kex_groups': ['MLKEM1024'], 'pqc_kex_hybrid': False}
NONE = {'pqc_kex_supported': False, 'pqc_kex_groups': [], 'pqc_kex_hybrid': False}
UNKNOWN = {'pqc_kex_supported': None}


@pytest.mark.parametrize('probes, tls13, expected', [
	([HYBRID, HYBRID], True, 'hybrid'),
	([PURE], True, 'pure'),
	([HYBRID, PURE], True, 'partial'),
	([HYBRID, NONE], True, 'partial'),
	([NONE, NONE], True, 'classical'),
	([NONE], False, 'no_tls13'),
	([NONE, UNKNOWN], True, 'unknown'),
])
def testPqcKexStatus(probes, tls13, expected):
	items = [
		gradedItem(**probe, **({} if tls13 else {'TLSv1.3': [], 'negotiated_protocol': 'TLSv1.2'}))
		for probe in probes
	]

	assert asmira.pqcKexStatus(items) == expected


def testLegacyObservationWithSingleGroupIsClassified():
	assert asmira.pqcKexStatus([gradedItem(pqc_kex_supported=True, pqc_kex_group='SecP384r1MLKEM1024')]) == 'hybrid'
	assert asmira.pqcKexStatus([gradedItem(pqc_kex_supported=True, pqc_kex_group='MLKEM768')]) == 'pure'


@pytest.mark.parametrize('kex, certificate, level', [
	('hybrid', ['hybrid'], 'complete'),
	('hybrid', ['classical'], 'key_exchange'),
	('classical', ['hybrid'], 'signature'),
	('pure', ['pqc'], 'none'),
	('hybrid', [], 'key_exchange'),
])
def testPqcHybridLevel(kex, certificate, level):
	assert asmira.pqcHybridLevel(kex, certificate) == level


def testExposureEventsFlagHybridAdoptionAndAcceptedGroups():
	event = asmira.buildExposureEvents([gradedItem(
		negotiated_group='X25519MLKEM768',
		pqc_kex_supported=True,
		pqc_kex_hybrid=True,
		pqc_kex_groups=['X25519MLKEM768', 'MLKEM1024'],
		hsts_max_age=31536000,
	)], '20260731T200000Z-12345678')[0]
	tls = event['asmira']['exposure']['tls']

	assert tls['pqc_kex_status'] == 'hybrid'
	assert tls['pqc_kex_groups'] == ['MLKEM1024', 'X25519MLKEM768']
	assert tls['pqc_kex_preferred'] is True
	assert tls['pqc_hybrid'] is True
	assert tls['pqc_hybrid_level'] == 'key_exchange'
	assert tls['grade'] == 'A+'


def testExposureEventsCarryPqcKexAndFinding():
	event = asmira.buildExposureEvents(
		[gradedItem(negotiated_group='secp384r1', pqc_kex_supported=False)],
		'20260731T200000Z-12345678',
	)[0]
	tls = event['asmira']['exposure']['tls']

	assert tls['pqc_kex_status'] == 'classical'
	assert tls['negotiated_group'] == ['secp384r1']
	assert 'NO_PQC_KEX' in tls['findings']
	assert tls['grade'] == 'A'


def testFindingsKeepTheirOpeningDateAndReportFixes():
	first = asmira.buildExposureEvents(
		[gradedItem(**{'TLSv1.0': ['TLS_RSA_WITH_AES_128_CBC_SHA']})],
		'20260731T200000Z-12345678',
	)
	firstTls = first[0]['asmira']['exposure']['tls']
	assert set(firstTls['findings_opened']) == set(firstTls['findings'])
	assert 'TLS10_ENABLED@2026-07-31T20:00:00+00:00' in firstTls['findings_since']

	second = asmira.buildExposureEvents(
		[gradedItem(observed_at='2026-08-07T20:00:00+00:00', **{'TLSv1.0': ['TLS_RSA_WITH_AES_128_CBC_SHA']})],
		'20260807T200000Z-12345678',
		previousEvents=first,
	)
	secondTls = second[0]['asmira']['exposure']['tls']
	assert secondTls['findings_opened'] == []
	assert 'TLS10_ENABLED@2026-07-31T20:00:00+00:00' in secondTls['findings_since']

	third = asmira.buildExposureEvents(
		[gradedItem(observed_at='2026-08-14T20:00:00+00:00')],
		'20260814T200000Z-12345678',
		previousEvents=second,
	)
	thirdTls = third[0]['asmira']['exposure']['tls']
	assert thirdTls['findings_resolved'] == ['TLS10_ENABLED']
	assert not any(value.startswith('TLS10_ENABLED@') for value in thirdTls['findings_since'])


def testFindingsAlreadyOpenBeforeTrackingUsePreviousRunDate():
	tls = {'findings': ['NO_TLS13']}

	asmira.trackFindings(tls, ['NO_TLS13'], {}, '2026-07-31T20:00:00+00:00', '2026-08-07T20:00:00+00:00')

	assert tls['findings_since'] == ['NO_TLS13@2026-07-31T20:00:00+00:00']
	assert tls['findings_opened'] == []


def testExposureEventsSummarisePortsAndFlagCleartextAndRdp():
	event = asmira.buildExposureEvents([gradedItem(
		port22='open', port80='open', port3389='open', port25='open',
		tls_port22='ssh', tls_port80='clear', tls_port3389='tls', tls_port25='clear', tls_port443='tls',
	)], '20260731T200000Z-12345678')[0]
	exposure = event['asmira']['exposure']

	assert exposure['open_ports'] == [22, 25, 80, 443, 3389]
	assert exposure['cleartext_ports'] == [25]
	assert '25:clear' in exposure['services']
	assert exposure['port']['3389'] == {'state': ['open'], 'tls': ['tls']}
	assert {'CLEARTEXT_SERVICE', 'RDP_EXPOSED'} <= set(exposure['tls']['findings'])
	assert exposure['tls']['max_severity'] == 'high'


def testExposureFindingsApplyWithoutHttps():
	event = asmira.buildExposureEvents([gradedItem(
		port443='filtered', certificate_sha256=None, port3389='open', tls_port3389='clear',
	)], '20260731T200000Z-12345678')[0]
	tls = event['asmira']['exposure']['tls']

	assert 'grade' not in tls
	assert tls['findings'] == ['CLEARTEXT_SERVICE', 'RDP_EXPOSED']
	assert tls['findings_opened'] == ['CLEARTEXT_SERVICE', 'RDP_EXPOSED']


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
state_dir = {tmp_path / "state"}
retention_days = 14
''')
	config = asmiraCommon.loadConfig(configFile)

	def fakeDiscovery(hosts, **kwargs):
		assert kwargs['stateDir'] == tmp_path / 'state'
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


@pytest.mark.parametrize('writer, payload', [
	(asmiraCommon.atomicWriteJson, {'a': 1}),
	(asmiraCommon.atomicWriteNdjson, [{'a': 1}]),
])
def testAtomicWritesHonourProcessUmask(tmp_path, monkeypatch, writer, payload):
	monkeypatch.setattr(asmiraCommon, 'PROCESS_UMASK', 0o027)
	output = tmp_path / 'out.json'

	writer(output, payload)

	assert output.stat().st_mode & 0o777 == 0o640
