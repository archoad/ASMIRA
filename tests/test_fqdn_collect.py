import json
import subprocess
from pathlib import Path
from types import SimpleNamespace

import dns.resolver
import pytest
import requests

import fqdnCollect


class FakeResponse:
	def __init__(self, payload, error=None, statusCode=200, headers=None):
		self.payload = payload
		self.error = error
		self.status_code = statusCode
		self.headers = {} if headers is None else headers

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


def shodanApiInfo(credits, limit=100):
	return FakeResponse({
		'plan': 'dev',
		'query_credits': credits,
		'usage_limits': {'query_credits': limit},
	})


def testShodanDnsIsSkippedWhenQueryCreditsAreExhausted():
	session = QueueSession([shodanApiInfo(0)])
	collector = fqdnCollect.ShodanDnsCollector(apiKey='test-key', session=session)
	collector.prepare(['example.com'])

	findings, report = fqdnCollect.runCollector(collector, 'example.com')

	assert findings == []
	assert report['status'] == 'skipped'
	assert 'épuisés (0/100)' in report['error']
	assert [call[0] for call in session.calls] == [fqdnCollect.SHODAN_API_INFO_URL]


def testShodanDnsSplitsQueryCreditsAcrossDomains():
	session = QueueSession([shodanApiInfo(3)])
	collector = fqdnCollect.ShodanDnsCollector(apiKey='test-key', session=session)
	collector.prepare(['example.net', 'example.com'])

	assert collector.quotas == {'example.com': 2, 'example.net': 1}


def testShodanDnsKeepsPagesCollectedBeforeBudgetExhaustion():
	session = QueueSession([
		shodanApiInfo(2),
		FakeResponse({'data': [], 'subdomains': ['api'], 'more': True}),
		FakeResponse({'data': [], 'subdomains': ['shop'], 'more': True}),
	])
	collector = fqdnCollect.ShodanDnsCollector(apiKey='test-key', session=session)
	collector.prepare(['example.com'])

	findings, report = fqdnCollect.runCollector(collector, 'example.com')

	assert {item.name for item in findings} == {'api.example.com', 'shop.example.com'}
	assert report['status'] == 'failed'
	assert report['count'] == 2
	assert 'budget de crédits Shodan épuisé après 2 page(s)' in report['error']
	assert len(session.calls) == 3


def testShodanDnsReusesCreditsLeftByFinishedDomains():
	session = QueueSession([
		shodanApiInfo(4),
		FakeResponse({'data': [], 'subdomains': ['api'], 'more': False}),
		FakeResponse({'data': [], 'subdomains': ['a'], 'more': True}),
		FakeResponse({'data': [], 'subdomains': ['b'], 'more': True}),
		FakeResponse({'data': [], 'subdomains': ['c'], 'more': False}),
	])
	collector = fqdnCollect.ShodanDnsCollector(apiKey='test-key', session=session)
	collector.prepare(['example.com', 'example.net'])

	collector.collect('example.com')
	findings = collector.collect('example.net')

	assert {item.name for item in findings} == {'a.example.net', 'b.example.net', 'c.example.net'}


def testShodanDnsReportsShodanErrorMessage():
	error = requests.HTTPError('401 Client Error: Unauthorized')
	session = QueueSession([
		FakeResponse(
			{'error': 'Insufficient query credits, please upgrade your API plan'},
			error=error,
			statusCode=401,
		),
	])
	collector = fqdnCollect.ShodanDnsCollector(apiKey='test-key', session=session)

	findings, report = fqdnCollect.runCollector(collector, 'example.com')

	assert findings == []
	assert report['status'] == 'failed'
	assert 'HTTP 401: Insufficient query credits' in report['error']


def testShodanDnsCollectsWithoutBudgetWhenApiInfoFails():
	session = QueueSession([
		FakeResponse({'error': 'boom'}, error=requests.HTTPError('500'), statusCode=500),
		FakeResponse({'data': [], 'subdomains': ['api'], 'more': False}),
	])
	collector = fqdnCollect.ShodanDnsCollector(apiKey='test-key', session=session)
	collector.prepare(['example.com'])

	findings, report = fqdnCollect.runCollector(collector, 'example.com')

	assert report['status'] == 'success'
	assert {item.name for item in findings} == {'api.example.com'}


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


def certIssuance(issuanceId, *names):
	return {
		'id': issuanceId,
		'dns_names': list(names),
		'not_before': '2026-01-01T00:00:00Z',
		'not_after': '2027-01-01T00:00:00Z',
		'cert_sha256': f'sha-{issuanceId}',
	}


def rateLimited(retryAfter):
	return FakeResponse(
		None,
		error=requests.HTTPError('429 Client Error'),
		statusCode=429,
		headers={'Retry-After': str(retryAfter)},
	)


def testCertSpotterResumesFromPersistedCursor(tmp_path):
	stateFile = tmp_path / 'state' / 'certspotter.json'
	stateFile.parent.mkdir()
	stateFile.write_text(json.dumps({
		'version': 1,
		'domains': {
			'example.com': {
				'after': '41',
				'complete': True,
				'names': {'old.example.com': {'issuance_id': '41'}},
			},
		},
	}))
	session = QueueSession([
		FakeResponse([certIssuance('42', 'new.example.com')]),
		FakeResponse([]),
	])
	collector = fqdnCollect.CertSpotterCollector(session=session, stateFile=stateFile)

	findings = collector.collect('example.com')

	assert {item.name for item in findings} == {'old.example.com', 'new.example.com'}
	assert ('after', '41') in session.calls[0][1]['params']
	assert ('after', '42') in session.calls[1][1]['params']
	saved = json.loads(stateFile.read_text())['domains']['example.com']
	assert saved['after'] == '42'
	assert saved['complete'] is True
	assert set(saved['names']) == {'old.example.com', 'new.example.com'}


def testCertSpotterKeepsProgressWhenRateLimited(tmp_path):
	stateFile = tmp_path / 'certspotter.json'
	session = QueueSession([
		FakeResponse([certIssuance('10', 'api.example.com')]),
		rateLimited(3600),
	])
	sleeps = []
	collector = fqdnCollect.CertSpotterCollector(
		session=session,
		stateFile=stateFile,
		maxWait=600,
		sleep=sleeps.append,
	)

	findings, report = fqdnCollect.runCollector(collector, 'example.com')

	assert {item.name for item in findings} == {'api.example.com'}
	assert report['status'] == 'failed'
	assert 'quota Cert Spotter atteint' in report['error']
	assert sleeps == []
	saved = json.loads(stateFile.read_text())['domains']['example.com']
	assert saved['after'] == '10'
	assert saved['complete'] is False


def testCertSpotterWaitsForShortRetryAfter(tmp_path):
	session = QueueSession([
		rateLimited(30),
		FakeResponse([]),
	])
	sleeps = []
	collector = fqdnCollect.CertSpotterCollector(
		session=session,
		stateFile=tmp_path / 'certspotter.json',
		sleep=sleeps.append,
	)

	findings, report = fqdnCollect.runCollector(collector, 'example.com')

	assert report['status'] == 'success'
	assert sleeps == [30]
	assert len(session.calls) == 2


def testCertSpotterWaitBudgetIsSharedAcrossDomains(tmp_path):
	session = QueueSession([
		rateLimited(400),
		FakeResponse([]),
		rateLimited(400),
	])
	sleeps = []
	collector = fqdnCollect.CertSpotterCollector(
		session=session,
		stateFile=tmp_path / 'certspotter.json',
		maxWait=600,
		sleep=sleeps.append,
	)

	unused, first = fqdnCollect.runCollector(collector, 'example.com')
	unused, second = fqdnCollect.runCollector(collector, 'example.net')

	assert first['status'] == 'success'
	assert second['status'] == 'failed'
	assert sleeps == [400]


def testCertSpotterDoesNotStoreOutOfScopeNames(tmp_path):
	stateFile = tmp_path / 'certspotter.json'
	session = QueueSession([
		FakeResponse([certIssuance('7', 'api.example.com', 'other.example.org')]),
		FakeResponse([]),
	])
	collector = fqdnCollect.CertSpotterCollector(session=session, stateFile=stateFile)

	collector.collect('example.com')

	saved = json.loads(stateFile.read_text())['domains']['example.com']
	assert set(saved['names']) == {'api.example.com'}


def testCertSpotterRestartsFromScratchOnCorruptState(tmp_path):
	stateFile = tmp_path / 'certspotter.json'
	stateFile.write_text('{pas du json')
	session = QueueSession([FakeResponse([])])
	collector = fqdnCollect.CertSpotterCollector(session=session, stateFile=stateFile)

	findings = collector.collect('example.com')

	assert findings == []
	assert not any(key == 'after' for key, unused in session.calls[0][1]['params'])
	assert json.loads(stateFile.read_text())['domains']['example.com']['complete'] is True


def amassExecutable(tmp_path):
	executable = tmp_path / 'amass'
	executable.touch(mode=0o700)
	return(executable)


def testAmassCollectorParsesV4RelationsWithinScope(tmp_path, monkeypatch):
	commands = []

	def fakeRun(cmd, **kwargs):
		commands.append(cmd)
		outputFile = Path(cmd[cmd.index('-o') + 1])
		outputFile.write_text(
			'example.com (FQDN) --> ns_record --> ns1.dns-provider.net (FQDN)\n'
			'vpn.example.com (FQDN) --> a_record --> 192.0.2.10 (IPAddress)\n'
			'WWW.Example.com (FQDN) --> cname_record --> edge.cdn.example.net (FQDN)\n'
			'vpn.example.com (FQDN) --> aaaa_record --> 2001:db8::1 (IPAddress)\n'
			'64496 (ASN) --> announces --> 192.0.2.0/24 (Netblock)\n'
		)
		return SimpleNamespace(returncode=0, stderr='')

	monkeypatch.setattr(fqdnCollect.subprocess, 'run', fakeRun)
	collector = fqdnCollect.AmassCollector(path=amassExecutable(tmp_path), timeout=60, workDir=tmp_path)

	findings = collector.collect('example.com')

	assert commands[0][1] == 'enum'
	assert {'-active', '-brute', '-o'} <= set(commands[0])
	assert len(commands) == 1
	assert sorted(item.name for item in findings) == ['example.com', 'vpn.example.com', 'www.example.com']
	assert {item.source for item in findings} == {'amass'}


@pytest.mark.parametrize('versionOutput, available', [
	('v4.2.0\n', True),
	('v5.1.1\n', False),
	('erreur', False),
])
def testAmassAvailabilityRequiresVersion4(tmp_path, monkeypatch, versionOutput, available):
	monkeypatch.setattr(
		fqdnCollect.subprocess, 'run',
		lambda cmd, **kwargs: SimpleNamespace(returncode=0, stdout=versionOutput),
	)
	collector = fqdnCollect.AmassCollector(path=amassExecutable(tmp_path), timeout=60, workDir=tmp_path)

	ok, reason = collector.availability()

	assert ok is available
	if not available:
		assert 'v4.2.0' in reason


def testParseSourcesRequiresDedicatedAmassFlag():
	with pytest.raises(ValueError, match='--enable-amass'):
		fqdnCollect.parseSourceNames('shodan-ctl,amass')


def dnsxCollector(tmp_path, **kwargs):
	executable = tmp_path / 'dnsx'
	executable.touch(mode=0o700)
	wordlist = tmp_path / 'words.txt'
	wordlist.write_text('# commentaire\nwww\nAPI\n\nvpn\n', encoding='utf-8')
	options = {
		'path': executable,
		'wordlist': wordlist,
		'resolvers': ['192.0.2.53'],
		'timeout': 60,
		'workDir': tmp_path,
		'labelFactory': iter(['probe-1', 'probe-2']).__next__,
	}
	options.update(kwargs)
	return(fqdnCollect.DnsxCollector(**options))


def dnsxLine(host, status='NOERROR', **records):
	return(json.dumps({'host': host, 'status_code': status, **records}) + '\n')


def fakeDnsxRun(commands, axfrOutput='', bruteOutput='', bruteTimeout=False):
	def fakeRun(cmd, **kwargs):
		commands.append((cmd, Path(cmd[cmd.index('-w') + 1]).read_text() if '-w' in cmd else None))
		outputFile = Path(cmd[cmd.index('-o') + 1])
		if '-axfr' in cmd:
			outputFile.write_text(axfrOutput)
		else:
			outputFile.write_text(bruteOutput)
			if bruteTimeout:
				raise subprocess.TimeoutExpired(cmd, kwargs['timeout'])
		return SimpleNamespace(returncode=0, stderr='')
	return(fakeRun)


def testDnsxCollectorKeepsResolvedBruteforceNamesOnly(tmp_path, monkeypatch):
	commands = []
	monkeypatch.setattr(fqdnCollect.subprocess, 'run', fakeDnsxRun(commands, bruteOutput=(
		dnsxLine('www.example.com', a=['192.0.2.10'])
		+ dnsxLine('api.example.com', cname=['edge.cdn.example.net'])
		+ dnsxLine('vpn.example.com', status='NXDOMAIN')
		+ dnsxLine('ftp.example.com', status='REFUSED', a=['198.51.100.1'])
		+ dnsxLine('mail.example.com', soa=[{'name': 'example.com'}])
		+ '{"host": "tronqué'
	)))
	collector = dnsxCollector(tmp_path)

	findings = collector.collect('example.com')

	assert sorted(item.name for item in findings) == ['api.example.com', 'www.example.com']
	assert {item.source for item in findings} == {'dnsx'}
	assert {item.evidence['method'] for item in findings} == {'bruteforce'}
	axfrCommand, bruteCommand = commands[0][0], commands[1][0]
	assert '-axfr' in axfrCommand
	assert bruteCommand[bruteCommand.index('-d') + 1] == 'example.com'
	# Jamais les résolveurs intégrés de dnsx ni la vérification de mise à jour.
	assert bruteCommand[bruteCommand.index('-r') + 1] == '192.0.2.53'
	assert '-duc' in bruteCommand and '-duc' in axfrCommand
	assert commands[1][1].split() == ['www', 'api', 'vpn', 'probe-1', 'probe-2']
	assert not list(tmp_path.glob('.dnsx_*'))


def testDnsxCollectorDiscardsWildcardAnswers(tmp_path, monkeypatch):
	monkeypatch.setattr(fqdnCollect.subprocess, 'run', fakeDnsxRun([], bruteOutput=(
		dnsxLine('probe-1.example.com', a=['203.0.113.7'])
		+ dnsxLine('probe-2.example.com', a=['203.0.113.7'])
		+ dnsxLine('www.example.com', a=['203.0.113.7'])
		+ dnsxLine('vpn.example.com', a=['192.0.2.20'])
	)))

	findings = dnsxCollector(tmp_path).collect('example.com')

	assert [item.name for item in findings] == ['vpn.example.com']


def testDnsxCollectorAggregatesCompleteWildcardSignature(tmp_path, monkeypatch):
	monkeypatch.setattr(fqdnCollect.subprocess, 'run', fakeDnsxRun([], bruteOutput=(
		dnsxLine('probe-1.example.com', a=['203.0.113.7'])
		+ dnsxLine('probe-1.example.com', aaaa=['2001:db8::7'])
		+ dnsxLine('probe-2.example.com', a=['203.0.113.7'])
		+ dnsxLine('probe-2.example.com', aaaa=['2001:db8::7'])
		+ dnsxLine('www.example.com', a=['203.0.113.7'])
		+ dnsxLine('www.example.com', aaaa=['2001:db8::7'])
	)))

	assert dnsxCollector(tmp_path).collect('example.com') == []


def testDnsxCollectorKeepsHostWithAdditionalRecordsBeyondWildcard(tmp_path, monkeypatch):
	monkeypatch.setattr(fqdnCollect.subprocess, 'run', fakeDnsxRun([], bruteOutput=(
		dnsxLine('probe-1.example.com', a=['203.0.113.7'])
		+ dnsxLine('probe-2.example.com', a=['203.0.113.7'])
		+ dnsxLine('www.example.com', a=['203.0.113.7', '192.0.2.42'])
	)))

	findings = dnsxCollector(tmp_path).collect('example.com')

	assert [item.name for item in findings] == ['www.example.com']


def testDnsxCollectorSharesOneTimeoutBudget(tmp_path, monkeypatch):
	timeouts = []
	clock = iter([0, 0, 150])
	monkeypatch.setattr(fqdnCollect.time, 'monotonic', lambda: next(clock))

	def fakeRun(cmd, **kwargs):
		timeouts.append(kwargs['timeout'])
		Path(cmd[cmd.index('-o') + 1]).write_text('', encoding='utf-8')
		return(SimpleNamespace(returncode=0, stderr=''))

	monkeypatch.setattr(fqdnCollect.subprocess, 'run', fakeRun)

	dnsxCollector(tmp_path, timeout=600).collect('example.com')

	assert timeouts == [120, 450]


def testDnsxCollectorExtractsNamesFromZoneTransfer(tmp_path, monkeypatch):
	axfr = json.dumps({'host': 'example.com', 'axfr': {'host': 'example.com', 'chain': [{
		'host': 'example.com',
		'all': [
			'example.com.\t7200\tIN\tSOA\tns1.dns-provider.net. hostmaster.example.com. 1 2 3 4 5',
			'example.com.\t7200\tIN\tNS\tns1.example.com.',
			'example.com.\t7200\tIN\tMX\t10 mx.dns-provider.net.',
			'intranet.example.com.\t300\tIN\tA\t10.0.0.5',
			'portal.example.com.\t300\tIN\tCNAME\tbackend.example.com.',
			'_sip._tcp.example.com.\t300\tIN\tSRV\t0 0 5060 voip.example.com.',
			'*.dev.example.com.\t300\tIN\tA\t192.0.2.30',
		],
	}]}}) + '\n'
	monkeypatch.setattr(fqdnCollect.subprocess, 'run', fakeDnsxRun([], axfrOutput=axfr))

	findings = dnsxCollector(tmp_path).collect('example.com')

	assert sorted(item.name for item in findings) == [
		'*.dev.example.com', 'backend.example.com', 'example.com', 'intranet.example.com',
		'ns1.example.com', 'portal.example.com', 'voip.example.com',
	]
	assert {item.evidence['method'] for item in findings} == {'axfr'}


def testDnsxRefusedZoneTransferYieldsNothing(tmp_path, monkeypatch):
	refused = json.dumps({'host': 'example.com', 'axfr': {'host': 'example.com'}}) + '\n'
	monkeypatch.setattr(fqdnCollect.subprocess, 'run', fakeDnsxRun([], axfrOutput=refused))

	assert dnsxCollector(tmp_path).collect('example.com') == []


def testDnsxTimeoutKeepsPartialResultsAndFailsSource(tmp_path, monkeypatch):
	monkeypatch.setattr(fqdnCollect.subprocess, 'run', fakeDnsxRun(
		[],
		bruteOutput=dnsxLine('www.example.com', a=['192.0.2.10']),
		bruteTimeout=True,
	))

	findings, report = fqdnCollect.runCollector(dnsxCollector(tmp_path), 'example.com')

	assert report['status'] == 'failed'
	assert [item.name for item in findings] == ['www.example.com']


def testDnsxFailureIsReported(tmp_path, monkeypatch):
	monkeypatch.setattr(
		fqdnCollect.subprocess, 'run',
		lambda cmd, **kwargs: SimpleNamespace(returncode=1, stderr='flag provided but not defined'),
	)

	findings, report = fqdnCollect.runCollector(dnsxCollector(tmp_path), 'example.com')

	assert findings == []
	assert report['status'] == 'failed'
	assert 'flag provided' in report['error']


def testDnsxAvailabilityRequiresWordlist(tmp_path):
	ok, reason = dnsxCollector(tmp_path, wordlist=None).availability()
	assert ok is False and 'liste de mots' in reason

	ok, reason = dnsxCollector(tmp_path, wordlist=tmp_path / 'absente.txt').availability()
	assert ok is False and 'illisible' in reason


def testDnsxFallsBackToSystemResolvers(tmp_path, monkeypatch):
	monkeypatch.setattr(
		fqdnCollect.dns.resolver, 'Resolver',
		lambda configure=True: SimpleNamespace(nameservers=['192.0.2.1', '2001:db8::53']),
	)
	collector = dnsxCollector(tmp_path, resolvers=None)

	assert collector.availability() == (True, None)
	assert collector.resolvers == ['192.0.2.1', '[2001:db8::53]:53']


def testParseDnsxResolversRejectsHostnames():
	assert fqdnCollect.parseDnsxResolvers('192.0.2.1, 192.0.2.1,2001:db8::1') == [
		'192.0.2.1', '[2001:db8::1]:53',
	]
	with pytest.raises(ValueError):
		fqdnCollect.parseDnsxResolvers('resolver.example.net')


def testParseSourcesRequiresDedicatedDnsxFlag():
	with pytest.raises(ValueError, match='--enable-dnsx'):
		fqdnCollect.parseSourceNames('subfinder,dnsx')


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


@pytest.mark.parametrize('activeFlag', ['--enable-amass', '--enable-dnsx'])
def testMainRequiresExplicitTargetForActiveSources(activeFlag, monkeypatch, capsys):
	monkeypatch.setattr(
		fqdnCollect,
		'hostCartography',
		lambda *args, **kwargs: pytest.fail('la collecte ne doit pas démarrer'),
	)

	assert fqdnCollect.main(['--sources', '', activeFlag]) == 1
	assert 'cible explicite est obligatoire' in capsys.readouterr().err


def testMainKeepsDefaultTargetForPassiveCollection(monkeypatch):
	captured = {}
	monkeypatch.setattr(
		fqdnCollect,
		'hostCartography',
		lambda hosts, **kwargs: captured.setdefault('hosts', hosts),
	)

	assert fqdnCollect.main(['--sources', '']) == 0
	assert captured['hosts'] == list(fqdnCollect.DEFAULT_HOSTS)


@pytest.mark.parametrize('wordlist', [None, '/definitely/missing/asmira-words.txt'])
def testMainRequiresReadableDnsxWordlist(wordlist, monkeypatch, capsys):
	monkeypatch.setattr(
		fqdnCollect,
		'hostCartography',
		lambda *args, **kwargs: pytest.fail('la collecte ne doit pas démarrer'),
	)
	arguments = ['--sources', '', '--enable-dnsx']
	if wordlist is not None:
		arguments += ['--dnsx-wordlist', wordlist]
	arguments.append('example.com')

	assert fqdnCollect.main(arguments) == 1
	assert '--dnsx-wordlist' in capsys.readouterr().err


class CaaResolver:
	def __init__(self, records, failing=()):
		self.records = records
		self.failing = set(failing)
		self.queries = []

	def resolve(self, name, recordType, raise_on_no_answer=True):
		self.queries.append((name, recordType))
		if name in self.failing:
			raise dns.exception.Timeout()
		values = self.records.get(name)
		if values is None:
			raise dns.resolver.NXDOMAIN()
		rrset = [
			SimpleNamespace(flags=0, tag=tag.encode(), value=value.encode())
			for tag, value in values
		]
		return(SimpleNamespace(rrset=rrset))


def testEffectiveCaaClimbsToFirstParentWithRecords():
	resolver = CaaResolver({
		'api.shop.example.com': [],
		'shop.example.com': [('issue', 'letsencrypt.org'), ('iodef', 'mailto:pki@example.com')],
		'example.com': [('issue', 'digicert.com')],
	})
	validator = fqdnCollect.DnsValidator(resolver=resolver)

	result = validator.effectiveCaa('api.shop.example.com', 'example.com')

	assert result['status'] == 'present'
	assert result['source'] == 'shop.example.com'
	assert {record['tag'] for record in result['records']} == {'issue', 'iodef'}


def testEffectiveCaaIsAbsentWhenNoLevelPublishesOne():
	validator = fqdnCollect.DnsValidator(resolver=CaaResolver({'www.example.com': [], 'example.com': []}))

	assert validator.effectiveCaa('www.example.com', 'example.com') == {
		'status': 'absent', 'source': None, 'records': [],
	}


def testEffectiveCaaReportsDnsErrorsInsteadOfAbsence():
	resolver = CaaResolver({'example.com': [('issue', 'letsencrypt.org')]}, failing={'www.example.com'})
	validator = fqdnCollect.DnsValidator(resolver=resolver)

	assert validator.effectiveCaa('www.example.com', 'example.com')['status'] == 'error'


def testCaaLookupsAreCachedAcrossHosts():
	resolver = CaaResolver({'a.example.com': [], 'b.example.com': [], 'example.com': [('issue', 'pki.goog')]})
	validator = fqdnCollect.DnsValidator(resolver=resolver)

	validator.effectiveCaa('a.example.com', 'example.com')
	validator.effectiveCaa('b.example.com', 'example.com')

	assert resolver.queries.count(('example.com', 'CAA')) == 1


def testCertSpotterSessionLeavesRateLimitsToTheCollector():
	collector = fqdnCollect.CertSpotterCollector()
	retry = collector.session.get_adapter('https://api.certspotter.com').max_retries

	assert retry.respect_retry_after_header is False
	assert 429 not in retry.status_forcelist


@pytest.mark.parametrize('host', ['https://admin.example.com/path', 'admin.example.com'])
def testActiveSourcesRefuseTargetsBroaderThanAuthorised(host, capsys):
	assert fqdnCollect.main(['--sources', 'shodan-ctl', '--enable-amass', host]) == 1
	assert 'n’est pas un domaine enregistré' in capsys.readouterr().err


def testRequireRegisteredDomainAcceptsExactDomain():
	assert fqdnCollect.requireRegisteredDomain('Example.COM') == 'example.com'
