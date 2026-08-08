import json
import subprocess
from pathlib import Path
from types import SimpleNamespace

import dns.resolver
import pytest
import requests

import fqdnCollect


class FakeResponse:
	def __init__(self, payload, error=None):
		self.payload = payload
		self.error = error

	def raise_for_status(self):
		if self.error:
			raise self.error

	def json(self):
		return self.payload


class QueueSession:
	def __init__(self, responses):
		self.responses = list(responses)
		self.calls = []

	def get(self, url, **kwargs):
		self.calls.append((url, kwargs))
		return self.responses.pop(0)


class FakeCollector(fqdnCollect.Collector):
	def __init__(self, name, findings=None, error=None, availability=(True, None)):
		self.name = name
		self.findings = [] if findings is None else findings
		self.error = error
		self.available = availability

	def availability(self):
		return self.available

	def collect(self, domain):
		if self.error:
			raise self.error
		return self.findings


class FakeDnsValidator:
	def __init__(self, results=None, wildcardAddress=None):
		self.results = {} if results is None else results
		self.wildcardAddress = wildcardAddress
		self.queries = []

	def resolveHost(self, host):
		self.queries.append(host)
		if host.startswith('fqdncollect-') and self.wildcardAddress:
			return dnsResult(a=[self.wildcardAddress])
		return self.results.get(host, dnsResult(status='NXDOMAIN'))


class FakeAnswer(list):
	def __init__(self, values, ttl=300, canonicalName=None):
		super().__init__(values)
		self.rrset = SimpleNamespace(ttl=ttl) if values else None
		self.canonical_name = canonicalName


class FakeResolver:
	def __init__(self, answers):
		self.answers = answers

	def resolve(self, host, recordType, raise_on_no_answer=False):
		answer = self.answers.get((host, recordType), dns.resolver.NoAnswer())
		if isinstance(answer, Exception):
			raise answer
		return answer


def dnsResult(status='NOERROR', a=None, aaaa=None, cname=None):
	records = {
		'A': [] if a is None else a,
		'AAAA': [] if aaaa is None else aaaa,
		'CNAME': [] if cname is None else cname,
	}
	return {
		'status': status,
		'resolvable': any(records.values()),
		'records': records,
		'ttl': {},
		'errors': {},
	}


def testExtractDomainNormalizesUrlsAndPublicSuffixes():
	assert fqdnCollect.extractDomain('https://WWW.Example.CO.UK:443/path') == 'example.co.uk'
	assert fqdnCollect.extractDomain('api.example.com.') == 'example.com'


@pytest.mark.parametrize(
	'host',
	['', 'localhost', '127.0.0.1', 'bad_host.example.com', '*.api.example.com'],
)
def testExtractDomainRejectsInvalidOrWildcardHosts(host):
	with pytest.raises((TypeError, ValueError)):
		fqdnCollect.extractDomain(host)


def testNormalizeDiscoveredNamePreservesWildcardAsEvidence():
	name, wildcardPattern = fqdnCollect.normalizeDiscoveredName('*.API.Example.com.')

	assert name == '*.api.example.com'
	assert wildcardPattern is True


def testExtractListDomainsAcceptsStringsAndRows(tmp_path):
	outputFile = tmp_path / 'domains.json'

	domains = fqdnCollect.extractListDomains(
		['www.example.com', ['api.example.co.uk', 'perimeter'], ('shop.example.com',)],
		outputFile=outputFile,
	)

	assert domains == ['example.co.uk', 'example.com']
	assert json.loads(outputFile.read_text()) == [
		{'domain': 'example.co.uk'},
		{'domain': 'example.com'},
	]


def testShodanCtlCollectorPreservesWildcardAndScope():
	session = QueueSession([
		FakeResponse(['www.example.com', '*.api.example.com', 'outside.test']),
	])
	collector = fqdnCollect.ShodanCtlCollector(session=session, timeout=30)

	findings = collector.collect('example.com')

	assert [(item.name, item.wildcardPattern) for item in findings] == [
		('www.example.com', False),
		('*.api.example.com', True),
	]
	assert session.calls[0][0].endswith('/example.com/hostnames')


def testShodanCtlMalformedResponseFailsCollector():
	collector = fqdnCollect.ShodanCtlCollector(
		session=QueueSession([FakeResponse({'error': 'invalid'})]),
	)

	findings, report = fqdnCollect.runCollector(collector, 'example.com')

	assert findings == []
	assert report['status'] == 'failed'
	assert 'liste JSON' in report['error']


def testHttpRateLimitFailureIsIsolated():
	collector = fqdnCollect.ShodanCtlCollector(
		session=QueueSession([
			FakeResponse(None, error=requests.HTTPError('429 Too Many Requests')),
		]),
	)

	findings, report = fqdnCollect.runCollector(collector, 'example.com')

	assert findings == []
	assert report['status'] == 'failed'
	assert '429' in report['error']


def testSubfinderCollectorParsesJsonlProvenance(tmp_path, monkeypatch):
	executable = tmp_path / 'subfinder'
	executable.touch(mode=0o700)

	def fakeRun(cmd, **kwargs):
		outputFile = Path(cmd[cmd.index('-o') + 1])
		outputFile.write_text(
			'\n'.join([
				json.dumps({
					'host': 'api.example.com',
					'sources': ['crtsh', 'commoncrawl'],
				}),
				json.dumps({'host': '*.wild.example.com', 'source': 'certspotter'}),
				'{invalid',
			])
		)
		return SimpleNamespace(returncode=0, stderr='')

	monkeypatch.setattr(fqdnCollect.subprocess, 'run', fakeRun)
	collector = fqdnCollect.SubfinderCollector(
		path=executable,
		timeout=60,
		workDir=tmp_path,
	)

	findings = collector.collect('example.com')

	assert {(item.name, item.source) for item in findings} == {
		('api.example.com', 'subfinder:commoncrawl'),
		('api.example.com', 'subfinder:crtsh'),
		('*.wild.example.com', 'subfinder:certspotter'),
	}
	assert not list(tmp_path.glob('*.jsonl'))


def testSubfinderTimeoutIsReportedAndTemporaryFileRemoved(tmp_path, monkeypatch):
	executable = tmp_path / 'subfinder'
	executable.touch(mode=0o700)

	def fakeRun(cmd, **kwargs):
		raise subprocess.TimeoutExpired(cmd, kwargs['timeout'])

	monkeypatch.setattr(fqdnCollect.subprocess, 'run', fakeRun)
	collector = fqdnCollect.SubfinderCollector(
		path=executable,
		timeout=10,
		workDir=tmp_path,
	)

	findings, report = fqdnCollect.runCollector(collector, 'example.com')

	assert findings == []
	assert report['status'] == 'failed'
	assert 'dépassé' in report['error']
	assert not list(tmp_path.glob('*.jsonl'))


def testMissingOptionalToolIsSkipped(tmp_path):
	collector = fqdnCollect.SubfinderCollector(path=tmp_path / 'absent')

	findings, report = fqdnCollect.runCollector(collector, 'example.com')

	assert findings == []
	assert report['status'] == 'skipped'
	assert 'indisponible' in report['error']


def testCollectorFailuresDoNotDiscardOtherSources():
	success = FakeCollector('success', [
		fqdnCollect.createFinding('api.example.com', 'example.com', 'success'),
	])
	failure = FakeCollector('failure', error=RuntimeError('service indisponible'))

	findings, reports = fqdnCollect.collectFindings(
		['example.com'],
		[success, failure],
		workers=2,
	)

	assert {item.name for item in findings} == {'example.com', 'api.example.com'}
	assert {item['source']: item['status'] for item in reports} == {
		'failure': 'failed',
		'success': 'success',
	}


def testCandidateAggregationDeduplicatesAndPreservesSources():
	findings = [
		fqdnCollect.createFinding('api.example.com', 'example.com', 'shodan-ctl'),
		fqdnCollect.createFinding('api.example.com', 'example.com', 'subfinder:crtsh'),
		fqdnCollect.createFinding('api.example.com', 'example.com', 'shodan-ctl'),
	]

	records = fqdnCollect.buildCandidateRecords(
		findings,
		collectedAt='2026-07-30T00:00:00+00:00',
	)

	assert records == [{
		'name': 'api.example.com',
		'domain': 'example.com',
		'wildcard_pattern': False,
		'sources': ['shodan-ctl', 'subfinder:crtsh'],
		'evidence': [
			{'source': 'shodan-ctl'},
			{'source': 'subfinder:crtsh'},
		],
		'collected_at': '2026-07-30T00:00:00+00:00',
	}]


def testShodanDnsCollectorHandlesPaginationAndHistory():
	session = QueueSession([
		FakeResponse({
			'data': [{
				'subdomain': 'api',
				'type': 'A',
				'value': '192.0.2.10',
				'last_seen': '2026-07-01T00:00:00Z',
				'ttl': 300,
			}],
			'subdomains': ['api', '*.wild'],
			'more': True,
		}),
		FakeResponse({
			'data': [],
			'subdomains': ['shop.example.com'],
			'more': False,
		}),
	])
	collector = fqdnCollect.ShodanDnsCollector(
		apiKey='test-key',
		session=session,
		history=True,
	)

	findings = collector.collect('example.com')

	assert {item.name for item in findings} == {
		'api.example.com',
		'*.wild.example.com',
		'shop.example.com',
	}
	assert session.calls[0][1]['params']['history'] == 'true'
	assert session.calls[0][1]['params']['page'] == 1
	assert session.calls[1][1]['params']['page'] == 2


def testShodanDnsWithoutCredentialIsSkipped():
	collector = fqdnCollect.ShodanDnsCollector(apiKey=None)

	findings, report = fqdnCollect.runCollector(collector, 'example.com')

	assert findings == []
	assert report['status'] == 'skipped'
	assert 'SHODAN_API_KEY' in report['error']


def testCollectorReportNeverStoresApiKey(monkeypatch):
	secret = 'secret-value-that-must-not-leak'
	monkeypatch.setenv('SHODAN_API_KEY', secret)
	error = requests.HTTPError(
		f'401 Client Error for url: https://api.shodan.io/dns/domain/example.com?key={secret}'
	)
	collector = FakeCollector('shodan-dns', error=error)

	findings, report = fqdnCollect.runCollector(collector, 'example.com')

	assert findings == []
	assert secret not in report['error']
	assert '[REDACTED]' in report['error']


def testCertSpotterCollectorHandlesPaginationAndBearerToken():
	session = QueueSession([
		FakeResponse([{
			'id': '42',
			'dns_names': ['api.example.com', '*.example.com'],
			'not_before': '2026-01-01T00:00:00Z',
			'not_after': '2027-01-01T00:00:00Z',
			'cert_sha256': 'abc',
		}]),
		FakeResponse([]),
	])
	collector = fqdnCollect.CertSpotterCollector(
		apiKey='test-token',
		session=session,
	)

	findings = collector.collect('example.com')

	assert {(item.name, item.wildcardPattern) for item in findings} == {
		('api.example.com', False),
		('*.example.com', True),
	}
	assert session.calls[0][1]['headers'] == {'Authorization': 'Bearer test-token'}
	assert ('after', '42') in session.calls[1][1]['params']


def testCertSpotterRejectsBrokenPagination():
	session = QueueSession([
		FakeResponse([{'id': None, 'dns_names': ['api.example.com']}]),
	])
	collector = fqdnCollect.CertSpotterCollector(session=session)

	findings, report = fqdnCollect.runCollector(collector, 'example.com')

	assert findings == []
	assert report['status'] == 'failed'
	assert 'Pagination' in report['error']


def testAmassCollectorUsesExplicitActiveMode(tmp_path, monkeypatch):
	executable = tmp_path / 'amass'
	executable.touch(mode=0o700)
	commands = []

	def fakeRun(cmd, **kwargs):
		commands.append(cmd)
		if 'subs' in cmd:
			outputFile = Path(cmd[cmd.index('-o') + 1])
			outputFile.write_text('vpn.example.com\n')
		return SimpleNamespace(returncode=0, stderr='')

	monkeypatch.setattr(fqdnCollect.subprocess, 'run', fakeRun)
	collector = fqdnCollect.AmassCollector(
		path=executable,
		timeout=60,
		workDir=tmp_path,
	)

	findings = collector.collect('example.com')

	assert '-active' in commands[0]
	assert '-brute' in commands[0]
	assert commands[1][1] == 'subs'
	assert '-names' in commands[1]
	assert [(item.name, item.source) for item in findings] == [
		('vpn.example.com', 'amass'),
	]


def testParseSourcesRequiresDedicatedAmassFlag():
	with pytest.raises(ValueError, match='--enable-amass'):
		fqdnCollect.parseSourceNames('shodan-ctl,amass')


def testDnsValidatorCollectsRecordsAndCanonicalName():
	resolver = FakeResolver({
		('api.example.com', 'A'): FakeAnswer(
			['192.0.2.10'],
			ttl=60,
			canonicalName='backend.example.net.',
		),
		('api.example.com', 'AAAA'): FakeAnswer(['2001:db8::10'], ttl=120),
		('api.example.com', 'CNAME'): dns.resolver.NoAnswer(),
	})
	validator = fqdnCollect.DnsValidator(resolver=resolver)

	result = validator.resolveHost('api.example.com')

	assert result['status'] == 'NOERROR'
	assert result['resolvable'] is True
	assert result['records'] == {
		'A': ['192.0.2.10'],
		'AAAA': ['2001:db8::10'],
		'CNAME': ['backend.example.net'],
	}
	assert result['ttl'] == {'A': 60, 'AAAA': 120}


def testDnsValidatorClassifiesNxDomain():
	validator = fqdnCollect.DnsValidator(resolver=FakeResolver({
		('absent.example.com', 'A'): dns.resolver.NXDOMAIN(),
	}))

	result = validator.resolveHost('absent.example.com')

	assert result['status'] == 'NXDOMAIN'
	assert result['resolvable'] is False


def testWildcardPatternsAreNotMaterializedAndDnsWildcardIsFlagged():
	findings = [
		fqdnCollect.createFinding('example.com', 'example.com', 'seed'),
		fqdnCollect.createFinding('api.example.com', 'example.com', 'shodan-ctl'),
		fqdnCollect.createFinding('old.example.com', 'example.com', 'shodan-ctl'),
		fqdnCollect.createFinding('*.example.com', 'example.com', 'certspotter'),
	]
	candidates = fqdnCollect.buildCandidateRecords(findings)
	validator = FakeDnsValidator(
		results={
			'example.com': dnsResult(a=['192.0.2.1']),
			'api.example.com': dnsResult(a=['192.0.2.50']),
			'old.example.com': dnsResult(status='NXDOMAIN'),
		},
		wildcardAddress='192.0.2.50',
	)

	inventory, wildcardReports = fqdnCollect.resolveCandidateHosts(
		candidates,
		dnsValidator=validator,
		workers=1,
		wildcardSamples=2,
	)

	assert '*.example.com' not in {item['name'] for item in inventory}
	api = next(item for item in inventory if item['name'] == 'api.example.com')
	assert api['dns_wildcard_zone'] is True
	assert api['dns_wildcard_match'] is True
	assert api['related_wildcard_patterns'] == ['*.example.com']
	assert wildcardReports[0]['detected'] is True


def testHostCartographyWritesThreeOutputsAndWebTlsSchema(tmp_path):
	findings = [
		fqdnCollect.createFinding('api.example.com', 'example.com', 'fake'),
		fqdnCollect.createFinding('old.example.com', 'example.com', 'fake'),
		fqdnCollect.createFinding('*.example.com', 'example.com', 'fake'),
	]
	collector = FakeCollector('fake', findings)
	validator = FakeDnsValidator(results={
		'example.com': dnsResult(a=['192.0.2.1']),
		'api.example.com': dnsResult(a=['192.0.2.2']),
		'old.example.com': dnsResult(status='NXDOMAIN'),
	})

	result = fqdnCollect.hostCartography(
		['www.example.com'],
		collectors=[collector],
		dnsValidator=validator,
		dataDir=tmp_path,
		txtdnsDir=tmp_path / 'txtdns',
		collectorWorkers=1,
		dnsWorkers=1,
		wildcardSamples=1,
	)

	candidatesFile = tmp_path / f'{fqdnCollect.now}_hosts_candidates.json'
	inventoryFile = tmp_path / f'{fqdnCollect.now}_hosts_inventory.json'
	hostsFile = tmp_path / f'{fqdnCollect.now}_hosts_list.json'
	assert candidatesFile.is_file()
	assert inventoryFile.is_file()
	assert hostsFile.is_file()
	assert result['hosts'] == ['api.example.com', 'example.com']
	assert json.loads(hostsFile.read_text()) == [
		{'host': 'api.example.com'},
		{'host': 'example.com'},
	]
	assert any(
		record['name'] == '*.example.com' and record['wildcard_pattern']
		for record in json.loads(candidatesFile.read_text())
	)
	assert all(
		not record['wildcard_pattern']
		for record in json.loads(inventoryFile.read_text())
	)


def testMainRejectsInvalidWorkerCount():
	assert fqdnCollect.main(['--dns-workers', '0']) == 2
