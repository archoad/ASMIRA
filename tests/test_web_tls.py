from datetime import datetime, timedelta, timezone
import subprocess
from types import SimpleNamespace

import pandas as pd
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa
from cryptography.x509.oid import NameOID

import webTLS


def testGetDomainInfoUsesInstalledQueryApi(monkeypatch):
	creationDate = datetime(2020, 1, 2)
	expirationDate = datetime.now() + timedelta(days=31)
	calls = []

	def fakeQuery(domain, timeout):
		calls.append((domain, timeout))
		return(SimpleNamespace(
			creation_date=[creationDate],
			expiration_date=expirationDate,
			registrar='Example Registrar',
			dnssec='signedDelegation',
		))

	monkeypatch.setattr(webTLS, 'whois', SimpleNamespace(query=fakeQuery))

	result = webTLS.getDomainInfo('example.com')

	assert calls == [('example.com', 15)]
	assert result['domain_create'] == '02-01-2020'
	assert result['domain_expire'] == expirationDate.strftime('%d-%m-%Y')
	assert 29 <= result['domain_remain'] <= 31
	assert result['domain_expired'] is False
	assert result['domain_registrar'] == 'Example Registrar'
	assert result['domain_dnssec'] == 'signedDelegation'


def testGetDomainInfoSupportsPythonWhoisApi(monkeypatch):
	def fakeWhois(domain):
		assert domain == 'example.net'
		return(SimpleNamespace(
			creation_date=None,
			expiration_date=None,
			registrar=None,
			dnssec=None,
		))

	monkeypatch.setattr(webTLS, 'whois', SimpleNamespace(whois=fakeWhois))

	result = webTLS.getDomainInfo('example.net')

	assert result == {
		'domain_create': 'Unknown',
		'domain_expire': 'Unknown',
		'domain_remain': 'Unknown',
		'domain_expired': 'Unknown',
		'domain_registrar': 'Unknown',
		'domain_dnssec': 'Unknown',
	}


def testGetDomainInfoSupportsTimezoneAwareDates(monkeypatch):
	expirationDate = datetime.now(timezone.utc) - timedelta(days=1)

	def fakeQuery(domain, timeout):
		return(SimpleNamespace(
			creation_date=None,
			expiration_date=[None, expirationDate],
			registrar='Registrar',
			dnssec=False,
		))

	monkeypatch.setattr(webTLS, 'whois', SimpleNamespace(query=fakeQuery))

	result = webTLS.getDomainInfo('expired.example')

	assert result['domain_expired'] is True
	assert result['domain_remain'] <= -1
	assert result['domain_dnssec'] is False


def testGetDomainInfoDoesNotStopCartographyOnWhoisError(monkeypatch, capsys):
	def fakeQuery(domain, timeout):
		raise RuntimeError('service indisponible')

	monkeypatch.setattr(webTLS, 'whois', SimpleNamespace(query=fakeQuery))

	result = webTLS.getDomainInfo('example.org')

	assert result == webTLS.getUnknownDomainInfo()
	assert 'WHOIS indisponible pour example.org' in capsys.readouterr().err


def testGetDomainInfoSupportsDictionariesAndDoesNotExpireEarly(monkeypatch):
	expirationDate = datetime.now() + timedelta(hours=12)
	monkeypatch.setattr(
		webTLS,
		'queryWhois',
		lambda domain: {
			'creation_date': datetime(2020, 1, 2),
			'expiration_date': expirationDate,
			'registrar': 'Registrar',
			'dnssec': 'unsigned',
		},
	)

	result = webTLS.getDomainInfo('example.com')

	assert result['domain_remain'] == 0
	assert result['domain_expired'] is False
	assert result['domain_registrar'] == 'Registrar'


def buildCertificate(
	subjectMaterial,
	subjectOrganization='Service',
	issuerName=None,
	issuerMaterial=None,
):
	current = datetime.now(timezone.utc)
	subject = x509.Name([
		x509.NameAttribute(NameOID.COUNTRY_NAME, 'FR'),
		x509.NameAttribute(NameOID.ORGANIZATION_NAME, subjectOrganization),
		x509.NameAttribute(NameOID.COMMON_NAME, 'www.example.com'),
	])
	issuer = issuerName or subject
	signingMaterial = issuerMaterial or subjectMaterial
	builder = (
		x509.CertificateBuilder()
		.subject_name(subject)
		.issuer_name(issuer)
		.public_key(subjectMaterial.public_key())
		.serial_number(x509.random_serial_number())
		.not_valid_before(current - timedelta(days=1))
		.not_valid_after(current + timedelta(days=30))
		.add_extension(
			x509.SubjectAlternativeName([
				x509.DNSName('www.example.com'),
				x509.DNSName('api.example.com'),
			]),
			critical=False,
		)
	)
	algorithm = (
		None
		if isinstance(signingMaterial, ed25519.Ed25519PrivateKey)
		else hashes.SHA256()
	)
	certificate = builder.sign(private_key=signingMaterial, algorithm=algorithm)
	return(certificate.public_bytes(serialization.Encoding.PEM))


def testNormalizeHostAndRegisteredDomain():
	assert webTLS.normalizeHost('HTTPS://WWW.Example.CO.UK:443/path') == 'www.example.co.uk'
	assert webTLS.extractDomain('www.example.co.uk') == 'example.co.uk'
	assert webTLS.normalizeHost('https://éxample.fr/') == 'xn--xample-9ua.fr'


@pytest.mark.parametrize(
	('value', 'expected'),
	[
		('192.0.2.1', True),
		('999.0.2.1', False),
		('192.0.2.1.example', False),
		('prefix-192.0.2.1', False),
	],
)
def testIsIPv4IsStrict(value, expected):
	assert webTLS.isIPv4(value) is expected


def testExtractNmapPortsUsesExactPortsAndDefaults():
	data = SimpleNamespace(stdout=b'''
Host is up (0.010s latency).
22/tcp  filtered ssh
80/tcp  open     http
443/tcp closed   https
8080/tcp open    http-proxy
''')

	ports = webTLS.extractNmapPorts(data)

	assert set(ports) == {'live'} | {f'port{port}' for port in webTLS.SCANNED_PORTS}
	assert ports['live'] == 'up'
	assert ports['port22'] == 'filtered'
	assert ports['port80'] == 'open'
	assert ports['port443'] == 'closed'
	assert ports['port8080'] == 'open'
	assert ports['port3389'] == 'closed'


def testGetIPsReturnsAllIpv4AndIpv6Addresses(monkeypatch):
	def fakeResolve(host, recordType, lifetime):
		assert host == 'www.example.com'
		assert lifetime == 5
		values = {
			'A': ['192.0.2.20', '192.0.2.10'],
			'AAAA': ['2001:db8::2', '2001:db8::1'],
		}
		return([SimpleNamespace(to_text=lambda value=value: value) for value in values[recordType]])

	monkeypatch.setattr(webTLS.dns.resolver, 'resolve', fakeResolve)

	assert webTLS.getIPs('www.example.com') == [
		'192.0.2.10',
		'192.0.2.20',
		'2001:db8::1',
		'2001:db8::2',
	]
	assert webTLS.formatHostPort('2001:db8::1', 443) == '[2001:db8::1]:443'


def testExtractNmapCipherHandlesNseOutput():
	output = '''
| ssl-enum-ciphers:
|   TLSv1.2:
|     ciphers:
|       TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 - A
|   TLSv1.3:
|     ciphers:
|       TLS_AES_256_GCM_SHA384 - A
'''

	assert webTLS.extractNmapCipher(output) == {
		'TLSv1.2': ['TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256'],
		'TLSv1.3': ['TLS_AES_256_GCM_SHA384'],
	}


def testExtractShodanDataSkipsNonHttpServices():
	response = {
		'data': [
			{'port': 22, 'data': 'SSH-2.0'},
			{
				'port': 80,
				'http': {'status': 404, 'server': 'nginx'},
				'data': 'HTTP/1.1 404 Not Found\r\nServer: nginx\r\n',
			},
		],
	}

	assert webTLS.extractShodanData(response) == {
		'http_code': 404,
		'http_reason': 'Not Found',
		'server': 'nginx',
	}


def testExtractCertificateSeparatesSubjectAndIssuer():
	caMaterial = rsa.generate_private_key(public_exponent=65537, key_size=2048)
	caName = x509.Name([
		x509.NameAttribute(NameOID.COUNTRY_NAME, 'FR'),
		x509.NameAttribute(NameOID.ORGANIZATION_NAME, 'Example CA'),
		x509.NameAttribute(NameOID.COMMON_NAME, 'Example Root CA'),
	])
	leafMaterial = rsa.generate_private_key(public_exponent=65537, key_size=2048)
	certificate = buildCertificate(
		leafMaterial,
		subjectOrganization='Application',
		issuerName=caName,
		issuerMaterial=caMaterial,
	)

	result = webTLS.extractCertificateData(certificate)

	assert result['self-signed'] is False
	assert result['issuer_organization'] == 'Example CA'
	assert result['subject_organization'] == 'Application'
	assert result['subject_alt_names'] == ['www.example.com', 'api.example.com']
	assert result['public_key'] == 'RSAPublicKey'
	assert result['key_size'] == 2048
	assert result['public_key_algorithm_oid'] == '1.2.840.113549.1.1.1'
	assert result['signature_algorithm_oid'] == '1.2.840.113549.1.1.11'
	assert result['pqc_algorithms'] == []
	assert result['pqc_status'] == 'classical'
	assert result['has_expired'] is False
	assert len(result['certificate_sha256']) == 64


def testExtractCertificateSupportsEd25519WithoutKeySize():
	privateKey = ed25519.Ed25519PrivateKey.generate()
	certificate = buildCertificate(privateKey)

	result = webTLS.extractCertificateData(certificate)

	assert result['self-signed'] is True
	assert result['public_key'] == 'Ed25519PublicKey'
	assert result['key_size'] is None
	assert result['signature_hash'] is None
	assert result['pqc_status'] == 'classical'


def testExtractCertificateKeepsPqcStatusWhenPublicKeyIsUnsupported(monkeypatch):
	current = datetime.now(timezone.utc)
	name = x509.Name([
		x509.NameAttribute(NameOID.COMMON_NAME, 'www.example.com'),
	])

	class FakeCertificate:
		public_key_algorithm_oid = SimpleNamespace(
			dotted_string='2.16.840.1.101.3.4.3.18',
		)
		signature_algorithm_oid = SimpleNamespace(
			dotted_string='1.2.840.113549.1.1.11',
		)
		issuer = name
		subject = name
		not_valid_before_utc = current - timedelta(days=1)
		not_valid_after_utc = current + timedelta(days=30)
		extensions = x509.Extensions([])
		serial_number = 1
		signature_hash_algorithm = hashes.SHA256()

		def public_key(self):
			raise webTLS.UnsupportedAlgorithm('Clé PQC non prise en charge')

		def fingerprint(self, algorithm):
			assert isinstance(algorithm, hashes.SHA256)
			return(b'\x01' * 32)

	monkeypatch.setattr(webTLS, 'isSelfSignedCert', lambda certificate: False)
	monkeypatch.setattr(
		webTLS.x509,
		'load_pem_x509_certificate',
		lambda certificate: FakeCertificate(),
	)

	result = webTLS.extractCertificateData(b'certificate')

	assert result['public_key'] == 'Unsupported'
	assert result['key_size'] is None
	assert result['pqc_status'] == 'partial'
	assert result['pqc_algorithms'] == ['ML-DSA-65']


@pytest.mark.parametrize(
	('publicKeyOid', 'signatureOid', 'expectedStatus', 'expectedAlgorithms'),
	[
		(
			'2.16.840.1.101.3.4.3.17',
			'2.16.840.1.101.3.4.3.18',
			'pqc',
			['ML-DSA-44', 'ML-DSA-65'],
		),
		(
			'2.16.840.1.101.3.4.3.20',
			'2.16.840.1.101.3.4.3.46',
			'pqc',
			['SLH-DSA-SHA2-128s', 'HashSLH-DSA-SHAKE-256f-SHAKE256'],
		),
		(
			'2.16.840.1.101.3.4.3.17',
			'1.2.840.113549.1.1.11',
			'partial',
			['ML-DSA-44'],
		),
		(
			'1.2.840.113549.1.1.1',
			'2.16.840.1.101.3.4.3.18',
			'partial',
			['ML-DSA-65'],
		),
		(
			'1.3.6.1.5.5.7.6.40',
			'1.2.840.10045.4.3.2',
			'hybrid',
			['ML-DSA-44+ECDSA-P256'],
		),
		(
			'1.2.840.113549.1.1.1',
			'1.2.840.113549.1.1.11',
			'classical',
			[],
		),
		(
			'1.2.3.4.5',
			'1.2.840.113549.1.1.11',
			'unknown',
			[],
		),
	],
)
def testClassifyCertificatePqc(
	publicKeyOid,
	signatureOid,
	expectedStatus,
	expectedAlgorithms,
):
	status, algorithms = webTLS.classifyCertificatePqc(publicKeyOid, signatureOid)

	assert status == expectedStatus
	assert algorithms == expectedAlgorithms


def testExtractTLSDataIncludesVerificationAndNegotiation():
	privateKey = rsa.generate_private_key(public_exponent=65537, key_size=2048)
	certificate = buildCertificate(privateKey).decode()
	output = f'''
{certificate}
    Protocol  : TLSv1.2
    Cipher    : ECDHE-RSA-AES128-GCM-SHA256
    Verify return code: 18 (self-signed certificate)
'''

	result = webTLS.extractTLSdata(output)

	assert result['chain_valid'] is False
	assert result['verify_code'] == 18
	assert result['verify_message'] == 'self-signed certificate'
	assert result['negotiated_protocol'] == 'TLSv1.2'
	assert result['negotiated_cipher'] == 'ECDHE-RSA-AES128-GCM-SHA256'


def testExtractTLSDataReadsTls13CipherLine():
	privateKey = rsa.generate_private_key(public_exponent=65537, key_size=2048)
	certificate = buildCertificate(privateKey).decode()
	output = f'''
{certificate}
New, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384
Protocol: TLSv1.3
Verify return code: 0 (ok)
'''

	result = webTLS.extractTLSdata(output)

	assert result['negotiated_protocol'] == 'TLSv1.3'
	assert result['negotiated_cipher'] == 'TLS_AES_256_GCM_SHA384'
	assert isinstance(result['certificate_lifetime_days'], int)


@pytest.mark.parametrize('value, expected', [
	('max-age=31536000; includeSubDomains', 31536000),
	('MAX-AGE="600"', 600),
	('includeSubDomains', None),
	(None, None),
])
def testParseHstsMaxAge(value, expected):
	assert webTLS.parseHstsMaxAge(value) == expected


@pytest.mark.parametrize('output, expected', [
	('Negotiated TLS1.3 group: X25519MLKEM768\n', 'X25519MLKEM768'),
	('Negotiated TLS1.3 group: <NULL>\n', None),
	('Peer Temp Key: ECDH, secp521r1, 521 bits\n', 'secp521r1'),
	('Server Temp Key: X25519, 253 bits\n', 'X25519'),
	('rien\n', None),
])
def testExtractNegotiatedGroup(output, expected):
	assert webTLS.extractNegotiatedGroup(output) == expected


@pytest.mark.parametrize('output, expected', [
	(b'Negotiated TLS1.3 group: X25519MLKEM768\nNew, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384\n', 'X25519MLKEM768'),
	(b'Negotiated TLS1.3 group: <NULL>\nNew, (NONE), Cipher is (NONE)\n', False),
	(b'connect:errno=111\n', None),
])
def testPqcKeyExchangeProbe(monkeypatch, output, expected):
	commands = []

	def fakeRun(command, **kwargs):
		commands.append(command)
		return(SimpleNamespace(stdout=output))

	monkeypatch.setattr(webTLS.subprocess, 'run', fakeRun)

	assert webTLS.testPqcKeyExchange('192.0.2.1', 'www.example.com') == expected
	assert '-tls1_3' in commands[0]
	assert commands[0][commands[0].index('-groups') + 1].startswith('X25519MLKEM768:')


def testPqcAnalysisWithoutTls13DoesNotProbe(monkeypatch):
	monkeypatch.setattr(webTLS, 'testPqcKeyExchange', lambda *args, **kwargs: pytest.fail('sonde inutile'))

	assert webTLS.analysePqcKeyExchange(
		{'TLSv1.2': ['x'], 'certificate_sha256': 'a'}, '192.0.2.1', 'www.example.com',
	) == {'pqc_kex_group': None, 'pqc_kex_groups': [], 'pqc_kex_supported': False, 'pqc_kex_hybrid': False}


def testPqcAnalysisEnumeratesEveryAcceptedGroup(monkeypatch):
	accepted = {'X25519MLKEM768', 'MLKEM1024'}
	probes = []

	def fakeProbe(ip, host, commandSemaphore=None, groups=webTLS.PQC_KEX_GROUPS):
		probes.append(groups)
		return(groups[0] if len(groups) == 1 and groups[0] in accepted else False)

	monkeypatch.setattr(webTLS, 'testPqcKeyExchange', fakeProbe)

	result = webTLS.analysePqcKeyExchange(
		{'negotiated_group': 'X25519MLKEM768', 'TLSv1.3': ['x']}, '192.0.2.1', 'www.example.com',
	)

	assert result == {
		'pqc_kex_group': 'X25519MLKEM768',
		'pqc_kex_groups': ['X25519MLKEM768', 'MLKEM1024'],
		'pqc_kex_supported': True,
		'pqc_kex_hybrid': True,
	}
	assert len(probes) == len(webTLS.PQC_KEX_GROUPS) - 1


def testPqcAnalysisDetectsPureMlKemOnly(monkeypatch):
	def fakeProbe(ip, host, commandSemaphore=None, groups=webTLS.PQC_KEX_GROUPS):
		if len(groups) > 1:
			return('MLKEM768')
		return('MLKEM768' if groups == ('MLKEM768',) else False)

	monkeypatch.setattr(webTLS, 'testPqcKeyExchange', fakeProbe)

	result = webTLS.analysePqcKeyExchange(
		{'negotiated_group': 'secp384r1', 'TLSv1.3': ['x']}, '192.0.2.1', 'www.example.com',
	)

	assert result['pqc_kex_groups'] == ['MLKEM768']
	assert result['pqc_kex_hybrid'] is False


def testPqcAnalysisWithoutAnyGroupCostsOneProbe(monkeypatch):
	probes = []
	monkeypatch.setattr(
		webTLS, 'testPqcKeyExchange',
		lambda *args, **kwargs: probes.append(kwargs.get('groups')) or False,
	)

	result = webTLS.analysePqcKeyExchange(
		{'negotiated_group': 'X25519', 'TLSv1.3': ['x']}, '192.0.2.1', 'www.example.com',
	)

	assert result['pqc_kex_supported'] is False
	assert len(probes) == 1


@pytest.mark.parametrize('port, output, expected', [
	(993, b'CONNECTED(00000003)\nNew, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384\n', 'tls'),
	(587, b'CONNECTED(00000003)\nNew, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384\n', 'starttls'),
	(8080, b'CONNECTED(00000003)\nerror:0A00010B:SSL routines::wrong version number\n', 'clear'),
	(465, b'connect:errno=111\n', None),
	(3389, b'| rdp-enum-encryption:\n|   Security layer\n|     CredSSP (NLA): SUCCESS\n', 'tls'),
	(3389, b'| rdp-enum-encryption:\n|   Security layer\n|     Native RDP: SUCCESS\n', 'clear'),
])
def testPortEncryptionProbe(monkeypatch, port, output, expected):
	commands = []

	def fakeRun(command, **kwargs):
		commands.append(command)
		return(SimpleNamespace(stdout=output))

	monkeypatch.setattr(webTLS.subprocess, 'run', fakeRun)

	assert webTLS.testPortEncryption('192.0.2.1', 'mail.example.com', port) == expected
	if port == 587:
		assert commands[0][-2:] == ['-starttls', 'smtp']


def testSilentEstablishedConnectionIsCleartext(monkeypatch):
	def fakeRun(command, **kwargs):
		raise subprocess.TimeoutExpired(command, 5, output=b'CONNECTED(00000003)\n')

	monkeypatch.setattr(webTLS.subprocess, 'run', fakeRun)

	assert webTLS.testPortEncryption('192.0.2.1', 'www.example.com', 8443) == 'clear'


def testUnreachablePortStaysUndetermined(monkeypatch):
	def fakeRun(command, **kwargs):
		raise subprocess.TimeoutExpired(command, 5, output=b'')

	monkeypatch.setattr(webTLS.subprocess, 'run', fakeRun)

	assert webTLS.testPortEncryption('192.0.2.1', 'www.example.com', 8443) is None


def testPortEncryptionWithoutProbeForSshAndHttp(monkeypatch):
	monkeypatch.setattr(webTLS.subprocess, 'run', lambda *args, **kwargs: pytest.fail('sonde inutile'))

	assert webTLS.testPortEncryption('192.0.2.1', 'www.example.com', 22) == 'ssh'
	assert webTLS.testPortEncryption('192.0.2.1', 'www.example.com', 80) == 'clear'


def testReqNetcatSendsBytesAndParsesAllHeaders(monkeypatch):
	def fakeRun(command, **kwargs):
		assert command[-2:] == ['www.example.com', '80']
		assert kwargs['input'] == b'GET / HTTP/1.0\r\n\r\n'
		return(SimpleNamespace(stdout=(
			b'HTTP/1.1 404 Not Found\r\n'
			b'Date: Thu, 30 Jul 2026 10:00:00 GMT\r\n'
			b'Server: nginx\r\n\r\n'
		)))

	monkeypatch.setattr(webTLS.subprocess, 'run', fakeRun)

	assert webTLS.reqNetcat('www.example.com', 80, 'GET / HTTP/1.0\r\n\r\n') == {
		'http_code': 404,
		'http_reason': 'Not Found',
		'server': 'nginx',
	}


def testGetHTTPDataPrefersLiveVirtualHostResponse(monkeypatch):
	captured = {}

	def fakeNetcat(connectHost, port, message):
		captured['connect_host'] = connectHost
		captured['message'] = message
		return({'http_code': 200, 'http_reason': 'OK', 'server': 'live'})

	monkeypatch.setattr(webTLS, 'reqNetcat', fakeNetcat)
	monkeypatch.setattr(
		webTLS,
		'testShodan',
		lambda ip: pytest.fail('Shodan ne doit pas remplacer une réponse active'),
	)

	result = webTLS.getHTTPData('www.example.com', '192.0.2.1')

	assert result['http_source'] == 'live'
	assert captured['connect_host'] == '192.0.2.1'
	assert 'Host: www.example.com\r\n' in captured['message']


def testHTTPheadersHashPinsTheSelectedIpAndSni(monkeypatch):
	captured = {}

	class FakeResponse:
		headers = {'Server': 'nginx', 'Strict-Transport-Security': 'max-age=63072000'}

		def release_conn(self):
			captured['released'] = True

	class FakePool:
		def __init__(self, host, **kwargs):
			captured['host'] = host
			captured['pool'] = kwargs

		def request(self, method, path, **kwargs):
			captured['request'] = (method, path, kwargs)
			return(FakeResponse())

		def close(self):
			captured['closed'] = True

	monkeypatch.setattr(webTLS.urllib3, 'HTTPSConnectionPool', FakePool)

	result = webTLS.getHTTPheadersHash('www.example.com', '192.0.2.10')

	assert captured['host'] == '192.0.2.10'
	assert captured['pool']['server_hostname'] == 'www.example.com'
	assert captured['request'][2]['headers']['Host'] == 'www.example.com'
	assert captured['request'][2]['redirect'] is False
	assert captured['released'] is True
	assert captured['closed'] is True
	assert result.startswith('hhh:1:')
	details = webTLS.getHTTPSHeaders('www.example.com', '192.0.2.10')
	assert details['hsts_max_age'] == 63072000


def testTestTLSChecksChainAndHostname(monkeypatch):
	privateKey = rsa.generate_private_key(public_exponent=65537, key_size=2048)
	certificate = buildCertificate(privateKey)
	captured = {}

	def fakeRun(command, **kwargs):
		captured['command'] = command
		return(SimpleNamespace(stdout=(
			certificate
			+ b'\nVerify return code: 0 (ok)\n'
		)))

	monkeypatch.setattr(webTLS.subprocess, 'run', fakeRun)

	result = webTLS.testTLS('2001:db8::1', 'www.example.com')

	assert '[2001:db8::1]:443' in captured['command']
	assert captured['command'][captured['command'].index('-verify_hostname') + 1] == 'www.example.com'
	assert captured['command'][captured['command'].index('-CAfile') + 1]
	assert result['chain_valid'] is True


def testAllCipherSuitesWaitsForEveryResult(monkeypatch):
	webTLS.cipherList = [
		{'name': f'CIPHER-{index}', 'protocol': 'TLSv1.2'}
		for index in range(70)
	]

	def fakeTest(host, hostip, suite):
		return('TLSv1.2', suite['name'])

	monkeypatch.setattr(webTLS, 'testOneCipherSuite', fakeTest)

	result = webTLS.testAllCipherSuites('www.example.com', '192.0.2.1')

	assert len(result['TLSv1.2']) == 70
	assert result['TLSv1.2'][0] == 'CIPHER-0'


def testBuildListIpsPreservesVirtualHostsSharingAnIp(monkeypatch, tmp_path):
	calls = {'ns': 0, 'ports': 0, 'whois': 0}
	monkeypatch.setattr(webTLS, 'DATA_DIR', tmp_path)
	monkeypatch.setattr(webTLS, 'now', '20260730')

	def fakeNameServers(domain):
		calls['ns'] += 1
		return(['ns1.example.com'])

	def fakePorts(ip):
		calls['ports'] += 1
		return({
			'live': 'up',
			'port22': 'closed',
			'port80': 'open',
			'port443': 'open',
		})

	def fakeWhois(domain):
		calls['whois'] += 1
		return(webTLS.getUnknownDomainInfo())

	monkeypatch.setattr(webTLS, 'getNameServer', fakeNameServers)
	monkeypatch.setattr(webTLS, 'getIPs', lambda host: ['192.0.2.1'])
	monkeypatch.setattr(webTLS, 'getPorts', fakePorts)
	monkeypatch.setattr(webTLS, 'getDomainInfo', fakeWhois)
	monkeypatch.setattr(webTLS, 'getGeoData', lambda ip: {})

	result = webTLS.buildListIps(['www.example.com', 'api.example.com'])

	assert [item['host'] for item in result] == ['www.example.com', 'api.example.com']
	assert result[0]['alias'] == 'api.example.com'
	assert result[1]['alias'] == 'www.example.com'
	assert calls == {'ns': 1, 'ports': 1, 'whois': 1}
	assert (tmp_path / '20260730_list_ip.json').is_file()


def testBuildListIpsSupportsMixedIpv4AndIpv6(monkeypatch, tmp_path):
	scannedIps = []

	monkeypatch.setattr(webTLS, 'getNameServer', lambda domain: ['ns1.example.com'])
	monkeypatch.setattr(
		webTLS,
		'getIPs',
		lambda host: ['2001:db8::1', '192.0.2.1'],
	)

	def fakePorts(ip):
		scannedIps.append(ip)
		return(webTLS.extractNmapPorts(''))

	monkeypatch.setattr(webTLS, 'getPorts', fakePorts)
	monkeypatch.setattr(webTLS, 'getDomainInfo', lambda domain: webTLS.getUnknownDomainInfo())
	monkeypatch.setattr(webTLS, 'getGeoData', lambda ip: {})

	result = webTLS.buildListIps(
		['www.example.com'],
		destinationFile=tmp_path / 'list_ip.json',
		workers=1,
	)

	assert scannedIps == ['192.0.2.1', '2001:db8::1']
	assert {item['ip'] for item in result} == {
		'192.0.2.1',
		'2001:db8::1',
	}


def testScreenShotNeverReturnsCookieValues(monkeypatch, tmp_path):
	class FakeOptions:
		def add_argument(self, argument):
			pass

	class FakeDriver:
		title = 'Example'
		quitCalled = False

		def set_window_size(self, width, height):
			pass

		def set_page_load_timeout(self, timeout):
			assert timeout == 10

		def get(self, url):
			assert url == 'https://www.example.com'

		def get_cookies(self):
			return([{'name': 'session', 'value': 'secret'}])

		def get_screenshot_as_file(self, path):
			return(True)

		def quit(self):
			self.quitCalled = True

	class FakeWebDriver:
		ChromeOptions = FakeOptions

		@staticmethod
		def Chrome(options):
			return(driver)

	class FakeWebDriverException(Exception):
		pass

	class FakeCommon:
		class exceptions:
			WebDriverException = FakeWebDriverException

	driver = FakeDriver()
	monkeypatch.setattr(webTLS, 'PICTURES_DIR', tmp_path)
	monkeypatch.setattr(webTLS, 'webdriver', FakeWebDriver)
	monkeypatch.setattr(webTLS, 'common', FakeCommon)

	result = webTLS.getScreenShot('www.example.com')

	assert result == {
		'web_page_title': 'Example',
		'cookie_count': 1,
		'screenshot': True,
	}
	assert driver.quitCalled is True


def testDfToExcelHandlesListsWithoutMutatingInput(monkeypatch, tmp_path):
	monkeypatch.setattr(webTLS, 'DATA_DIR', tmp_path)
	monkeypatch.setattr(webTLS, 'now', '20260730')
	data = pd.DataFrame([{
		'host': 'www.example.com',
		'ns': ['ns1.example.com', 'ns2.example.com'],
		'subject_alt_names': ['www.example.com', 'api.example.com'],
		'TLSv1.3': ['TLS_AES_256_GCM_SHA384'],
	}])

	destination = webTLS.dfToExcel(data)

	assert destination == tmp_path / '20260730_hosts_analyse.xlsx'
	assert destination.is_file()
	assert data.loc[0, 'ns'] == ['ns1.example.com', 'ns2.example.com']


def testMainRefusesUnconfirmedActiveScan(monkeypatch, capsys):
	monkeypatch.setattr(
		webTLS,
		'testTools',
		lambda: pytest.fail('les outils ne doivent pas être testés sans autorisation'),
	)

	assert webTLS.main([]) == 2
	assert '--authorized-active-scan' in capsys.readouterr().err


def testRemoveOldFilesOnlyDeletesManagedPictures(monkeypatch, tmp_path):
	monkeypatch.setattr(webTLS, 'PICTURES_DIR', tmp_path)
	graph = tmp_path / 'graph_old.png'
	screen = tmp_path / 'screenshot_old.png'
	userFile = tmp_path / 'notes.txt'
	graph.write_text('generated')
	screen.write_text('generated')
	userFile.write_text('keep')

	webTLS.removeOldFiles()

	assert not graph.exists()
	assert not screen.exists()
	assert userFile.read_text() == 'keep'
