from datetime import datetime, timedelta, timezone
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pandas as pd
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
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
			# Erreur réelle de cryptography 46 sur une clé ML-DSA.
			raise ValueError('Unknown key type: 2.16.840.1.101.3.4.3.18')

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


def testExtractTLSDataClassifiesChainAndHandshakeSignature():
	authorityKey = ec.generate_private_key(ec.SECP256R1())
	leafKey = rsa.generate_private_key(public_exponent=65537, key_size=2048)
	authority = buildCertificate(authorityKey, subjectOrganization='Autorité').decode()
	authorityName = x509.load_pem_x509_certificate(authority.encode()).subject
	leaf = buildCertificate(
		leafKey,
		issuerName=authorityName,
		issuerMaterial=authorityKey,
	).decode()
	output = f'''
Certificate chain
 0 s:CN=www.example.com
{leaf}
 1 s:CN=Autorité
{authority}
Peer signing digest: SHA256
Peer signature type: rsa_pss_rsae_sha256
New, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384
Verify return code: 0 (ok)
'''

	result = webTLS.extractTLSdata(output)

	assert result['certificate_pem'] == leaf.strip()
	assert result['chain_pem'] == [authority.strip()]
	assert result['chain_pqc_status'] == 'classical'
	assert result['chain_pqc_algorithms'] == []
	assert result['peer_signature_type'] == 'rsa_pss_rsae_sha256'
	assert result['peer_signature_pqc'] == 'classical'


def testExtractTLSDataWithoutChainHasNoChainStatus():
	privateKey = rsa.generate_private_key(public_exponent=65537, key_size=2048)
	certificate = buildCertificate(privateKey).decode()

	result = webTLS.extractTLSdata(f'{certificate}\nVerify return code: 0 (ok)\n')

	assert 'chain_pqc_status' not in result
	assert 'peer_signature_type' not in result


@pytest.mark.parametrize('name, expected', [
	('rsa_pss_rsae_sha256', 'classical'),
	('ecdsa_secp256r1_sha256', 'classical'),
	('RSA-PSS', 'classical'),
	('mldsa65', 'pqc'),
	('slhdsa_sha2_128s', 'pqc'),
	('mldsa44_ecdsa_secp256r1_sha256', 'hybrid'),
	('mldsa65_rsa3072_pss_sha512', 'hybrid'),
])
def testClassifyHandshakeSignature(name, expected):
	assert webTLS.classifyHandshakeSignature(name) == expected


def testClassifyChainPemReportsMixedChains(monkeypatch):
	statuses = iter([('hybrid', ['ML-DSA-65+ECDSA-P256']), ('classical', [])])
	monkeypatch.setattr(webTLS, 'classifyCertificatePqc', lambda *args: next(statuses))
	authorityKey = ec.generate_private_key(ec.SECP256R1())
	pem = buildCertificate(authorityKey).decode()

	result = webTLS.classifyChainPem([pem, pem])

	assert result['chain_pqc_status'] == 'partial'
	assert result['chain_pqc_algorithms'] == ['ML-DSA-65+ECDSA-P256']


FIXTURES_DIR = Path(__file__).resolve().parent / 'fixtures'


@pytest.mark.parametrize('fileName, status, selfSigned', [
	# Certificats ML-DSA réels produits par OpenSSL 3.5 : cryptography 46 ne sait
	# pas lire leur clé, la sonde doit quand même les classer.
	('mldsa65-leaf-signed-by-ecdsa.pem', 'partial', False),
	('mldsa65-self-signed.pem', 'pqc', True),
])
def testExtractCertificateReadsRealMlDsaCertificates(fileName, status, selfSigned):
	result = webTLS.extractCertificateData((FIXTURES_DIR / fileName).read_text())

	assert result['pqc_status'] == status
	assert result['pqc_algorithms'] == ['ML-DSA-65']
	assert result['public_key'] == 'Unsupported'
	assert result['self-signed'] is selfSigned


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
	(8080, b'CONNECTED(00000003)\nerror:0A00010B:SSL routines::wrong version number\n', 'clear'),
	(443, b'CONNECTED(00000003)\nssl/tls alert handshake failure:SSL alert number 40\n', 'tls'),
	(465, b'write:errno=104\nCONNECTED(00000003)\nNew, (NONE), Cipher is (NONE)\n', None),
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
	monkeypatch.setattr(webTLS, 'httpRedirectsToHttps', lambda *args, **kwargs: False)

	assert webTLS.testPortEncryption('192.0.2.1', 'mail.example.com', port) == expected


CLEAR_TLS_PROBE = b'CONNECTED(00000003)\nerror:0A00010B:SSL routines::wrong version number\n'


@pytest.mark.parametrize('redirect, expected', [
	(True, 'redirect'),
	(False, 'clear'),
	(None, 'clear'),
])
def testPort8080RedirectToHttpsIsNotCleartext(monkeypatch, redirect, expected):
	probes = []
	monkeypatch.setattr(
		webTLS.subprocess, 'run', lambda command, **kwargs: SimpleNamespace(stdout=CLEAR_TLS_PROBE),
	)
	monkeypatch.setattr(
		webTLS, 'httpRedirectsToHttps', lambda *args, **kwargs: probes.append(args) or redirect,
	)

	assert webTLS.testPortEncryption('192.0.2.1', 'www.example.com', 8080) == expected
	assert probes == [('192.0.2.1', 'www.example.com', 8080)]


def testRedirectProbeOnlyRunsOnHttpRedirectPorts(monkeypatch):
	monkeypatch.setattr(
		webTLS.subprocess, 'run', lambda command, **kwargs: SimpleNamespace(stdout=CLEAR_TLS_PROBE),
	)
	monkeypatch.setattr(
		webTLS, 'httpRedirectsToHttps', lambda *args, **kwargs: pytest.fail('sonde HTTP inattendue'),
	)

	assert webTLS.testPortEncryption('192.0.2.1', 'www.example.com', 8443) == 'clear'


@pytest.mark.parametrize('response, expected', [
	(b'HTTP/1.1 301 Moved Permanently\r\nLocation: https://www.example.com/\r\n\r\n', True),
	(b'HTTP/1.1 308 Permanent Redirect\r\nlocation:HTTPS://www.example.com:443/\r\n\r\n', True),
	(b'HTTP/1.0 302 Found\r\nLocation: http://www.example.com/\r\n\r\n', False),
	(b'HTTP/1.1 302 Found\r\nLocation: /login\r\n\r\n', False),
	(b'HTTP/1.1 302 Found\r\nX-Location: https://www.example.com/\r\n\r\n', False),
	(b'HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<a href="https://x">', False),
	(b'SSH-2.0-OpenSSH_9.6\r\n', None),
])
def testParseHttpRedirect(response, expected):
	assert webTLS.parseHttpRedirect(response) is expected


class FakeHttpConnection:
	def __init__(self, chunks):
		self.chunks = list(chunks)
		self.sent = b''

	def __enter__(self):
		return(self)

	def __exit__(self, *args):
		return(False)

	def sendall(self, data):
		self.sent += data

	def settimeout(self, value):
		pass

	def recv(self, size):
		return(self.chunks.pop(0) if self.chunks else b'')


def testHttpRedirectProbeSendsHostAndReadsSplitHeaders(monkeypatch):
	connection = FakeHttpConnection([
		b'HTTP/1.1 301 Moved Permanently\r\nLoca',
		b'tion: https://www.example.com/\r\n\r\nbody',
	])
	monkeypatch.setattr(webTLS.socket, 'create_connection', lambda *args, **kwargs: connection)

	assert webTLS.httpRedirectsToHttps('192.0.2.1', 'www.example.com', 8080) is True
	assert b'Host: www.example.com\r\n' in connection.sent


def testHttpRedirectProbeWithoutAnswerIsUndetermined(monkeypatch):
	def refuse(*args, **kwargs):
		raise ConnectionResetError()

	monkeypatch.setattr(webTLS.socket, 'create_connection', refuse)

	assert webTLS.httpRedirectsToHttps('192.0.2.1', 'www.example.com', 8080) is None


def testHttpRedirectProbeBoundsHeaderSize(monkeypatch):
	connection = FakeHttpConnection([b'HTTP/1.1 200 OK\r\nX: ' + b'a' * 4096] * 10)
	monkeypatch.setattr(webTLS.socket, 'create_connection', lambda *args, **kwargs: connection)

	assert webTLS.httpRedirectsToHttps('192.0.2.1', 'www.example.com', 8080) is False
	assert len(connection.chunks) < 10


def testSilentEstablishedConnectionIsUndetermined(monkeypatch):
	# Derrière un CDN, un port peut accepter la connexion TCP sans rien servir.
	def fakeRun(command, **kwargs):
		raise subprocess.TimeoutExpired(command, 5, output=b'CONNECTED(00000003)\n')

	monkeypatch.setattr(webTLS.subprocess, 'run', fakeRun)

	assert webTLS.testPortEncryption('192.0.2.1', 'www.example.com', 8443) is None


@pytest.mark.parametrize('offered, output, expected', [
	(True, b'CONNECTED(00000003)\nNew, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384\n', 'starttls'),
	(False, None, 'clear'),
	(None, None, None),
])
def testSmtpEncryptionRequiresABanner(monkeypatch, offered, output, expected):
	commands = []
	monkeypatch.setattr(webTLS, 'smtpOffersStartTls', lambda ip, port: offered)

	def fakeRun(command, **kwargs):
		commands.append(command)
		return(SimpleNamespace(stdout=output))

	monkeypatch.setattr(webTLS.subprocess, 'run', fakeRun)

	assert webTLS.testPortEncryption('192.0.2.1', 'mail.example.com', 587) == expected
	if offered:
		assert commands[0][-2:] == ['-starttls', 'smtp']
	else:
		assert commands == []


class FakeSmtpConnection:
	def __init__(self, replies):
		self.replies = replies
		self.sent = []

	def makefile(self, mode):
		import io
		return(io.BytesIO(self.replies))

	def sendall(self, data):
		self.sent.append(data)

	def settimeout(self, value):
		self.timeouts = getattr(self, 'timeouts', []) + [value]

	def __enter__(self):
		return(self)

	def __exit__(self, *args):
		return(False)


@pytest.mark.parametrize('replies, expected', [
	(b'220 mx.example.com ESMTP\r\n250-mx.example.com\r\n250-SIZE 1000\r\n250 STARTTLS\r\n', True),
	(b'220-mx.example.com\r\n220 ESMTP\r\n250-mx.example.com\r\n250 SIZE 1000\r\n', False),
	(b'220 mx.example.com ESMTP\r\n250-mx.example.com\r\n250 X-NO-STARTTLS\r\n', False),
	(b'', None),
	(b'HTTP/1.1 400 Bad Request\r\n', None),
])
def testSmtpOffersStartTls(monkeypatch, replies, expected):
	connection = FakeSmtpConnection(replies)
	monkeypatch.setattr(webTLS.socket, 'create_connection', lambda *args, **kwargs: connection)

	assert webTLS.smtpOffersStartTls('192.0.2.1', 25) is expected
	if expected is not None:
		assert connection.sent[0] == b'EHLO asmira.invalid\r\n'


@pytest.mark.parametrize('replies', [
	b'220 ' + b'x' * 5000 + b'\r\n',
	b'220-' + b'y' * 900 + b'\r\n' + (b'220-' + b'z' * 900 + b'\r\n') * 30,
])
def testSmtpProbeBoundsLineAndReplySize(monkeypatch, replies):
	monkeypatch.setattr(webTLS.socket, 'create_connection', lambda *args, **kwargs: FakeSmtpConnection(replies))

	assert webTLS.smtpOffersStartTls('192.0.2.1', 25) is None


def testSmtpProbeHonoursGlobalDeadline(monkeypatch):
	clock = iter([0.0, 0.0, 10.0])
	monkeypatch.setattr(webTLS.time, 'monotonic', lambda: next(clock, 10.0))
	connection = FakeSmtpConnection(b'220 mx.example.com ESMTP\r\n250-mx.example.com\r\n250 STARTTLS\r\n')
	monkeypatch.setattr(webTLS.socket, 'create_connection', lambda *args, **kwargs: connection)

	assert webTLS.smtpOffersStartTls('192.0.2.1', 25, timeout=5) is None
	assert connection.timeouts[0] == 5


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


@pytest.mark.parametrize('output, cause', [
	(b'CONNECTED(00000003)\nerror:0A000458:SSL routines::tlsv1 unrecognized name:SSL alert number 112\n', 'unrecognized_name'),
	(b'CONNECTED(00000003)\nssl/tls alert handshake failure:SSL alert number 40\n', 'alert:40'),
	(b'write:errno=104\n', 'reset'),
	(b'connect:errno=111\n', 'refused'),
	(b'CONNECTED(00000003)\nunexpected eof while reading\n', 'eof'),
	(b'CONNECTED(00000003)\n', 'no_certificate'),
])
def testClassifyTlsFailure(output, cause):
	assert webTLS.classifyTlsFailure(output.decode()) == cause


def testTestTLSRetriesTransientFailureOnce(monkeypatch):
	privateKey = rsa.generate_private_key(public_exponent=65537, key_size=2048)
	outputs = [b'write:errno=104\n', buildCertificate(privateKey) + b'\nVerify return code: 0 (ok)\n']
	sleeps = []
	monkeypatch.setattr(webTLS.subprocess, 'run', lambda command, **kwargs: SimpleNamespace(stdout=outputs.pop(0)))
	monkeypatch.setattr(webTLS.time, 'sleep', sleeps.append)

	result = webTLS.testTLS('192.0.2.1', 'www.example.com')

	assert result['chain_valid'] is True
	assert 'tls_failure' not in result
	assert sleeps == [webTLS.TLS_RETRY_DELAY]


def testTestTLSDoesNotRetryRefusedName(monkeypatch):
	calls = []

	def fakeRun(command, **kwargs):
		calls.append(command)
		return(SimpleNamespace(stdout=b'tlsv1 unrecognized name:SSL alert number 112\n'))

	monkeypatch.setattr(webTLS.subprocess, 'run', fakeRun)
	monkeypatch.setattr(webTLS.time, 'sleep', lambda seconds: pytest.fail('nouvelle tentative inattendue'))

	assert webTLS.testTLS('192.0.2.1', 'www.example.com') == {'tls_failure': 'unrecognized_name'}
	assert len(calls) == 1


def testTestTLSReportsPersistentFailure(monkeypatch):
	monkeypatch.setattr(webTLS.subprocess, 'run', lambda command, **kwargs: SimpleNamespace(stdout=b'write:errno=104\n'))
	monkeypatch.setattr(webTLS.time, 'sleep', lambda seconds: None)

	assert webTLS.testTLS('192.0.2.1', 'www.example.com') == {'tls_failure': 'reset'}


@pytest.mark.parametrize('verify, expected', [
	(b'Verify return code: 0 (ok)', 'expiring'),
	(b'Verify return code: 62 (hostname mismatch)', 'other_name'),
	(b'Verify return code: 21 (unable to verify the first certificate)', 'untrusted'),
])
def testPortProbeReadsCertificateWithSni(monkeypatch, verify, expected):
	privateKey = rsa.generate_private_key(public_exponent=65537, key_size=2048)
	issuerKey = rsa.generate_private_key(public_exponent=65537, key_size=2048)
	issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'Example CA')])
	certificate = buildCertificate(privateKey, issuerName=issuer, issuerMaterial=issuerKey)
	captured = {}

	def fakeRun(command, **kwargs):
		captured['command'] = command
		return(SimpleNamespace(stdout=(
			b'CONNECTED(00000003)\n' + certificate
			+ b'\nNew, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384\n' + verify + b'\n'
		)))

	monkeypatch.setattr(webTLS.subprocess, 'run', fakeRun)
	item = {'port993': 'open', 'port443': 'open', 'certificate_sha256': 'a' * 64}

	result = webTLS.analysePortEncryption(item, '192.0.2.1', 'mail.example.com')

	command = captured['command']
	assert command[command.index('-servername') + 1] == 'mail.example.com'
	assert command[command.index('-verify_hostname') + 1] == 'mail.example.com'
	assert result['tls_port993'] == 'tls'
	assert result['tls_port443'] == 'tls'
	assert result['cert_port993'] == expected
	assert 28 <= result['cert_days_port993'] <= 30
	assert 'cert_port443' not in result


def testExpiredPortCertificateIsClassified():
	assert webTLS.classifyPortCertificate({'has_expired': True, 'verify_message': 'certificate has expired'}) == 'expired'
	assert webTLS.classifyPortCertificate({'remain': 200, 'chain_valid': True, 'verify_message': 'ok'}) == 'valid'


def failedTlsItem(host, failure, **overrides):
	item = {
		'host': host, 'ip': '192.0.2.1', 'port443': 'open', 'tls_failure': failure,
		'scan_status': 'success', 'scan_duration_seconds': 9.0, 'tls_port443': None,
	}
	item.update(overrides)
	return(item)


def testSecondPassRecoversTransientTlsFailures(monkeypatch):
	completed = {
		'a': failedTlsItem('a.example.com', 'timeout'),
		'b': failedTlsItem('b.example.com', 'reset'),
		'c': failedTlsItem('c.example.com', 'unrecognized_name'),
		'd': failedTlsItem('d.example.com', 'alert:40'),
		'e': failedTlsItem('e.example.com', 'timeout', tls_second_pass=True),
	}
	analysed = []
	probed = []
	sleeps = []

	def fakeProbe(ip, host, commandSemaphore=None):
		probed.append(host)
		if host == 'a.example.com':
			return({'certificate_sha256': 'f' * 64}, None)
		return(None, 'timeout')

	def fakeAnalyse(item, *args):
		analysed.append(item)
		return({**item, 'certificate_sha256': 'f' * 64, 'scan_status': 'success'})

	monkeypatch.setattr(webTLS, 'runTlsProbe', fakeProbe)
	monkeypatch.setattr(webTLS, 'analyseEndpoint', fakeAnalyse)
	monkeypatch.setattr(webTLS.time, 'sleep', sleeps.append)

	recovered = webTLS.retryTlsFailures(completed)

	assert recovered == 1
	assert sleeps == [webTLS.TLS_SECOND_PASS_DELAY]
	assert sorted(probed) == ['a.example.com', 'b.example.com']
	assert [item['host'] for item in analysed] == ['a.example.com']
	assert all('tls_failure' not in item and 'scan_status' not in item for item in analysed)
	assert completed['a']['certificate_sha256'] == 'f' * 64
	assert completed['a']['tls_second_pass'] is True
	assert completed['b']['tls_failure'] == 'timeout'
	assert completed['b']['scan_duration_seconds'] == 9.0
	assert completed['b']['tls_second_pass'] is True
	assert 'tls_second_pass' not in completed['c']
	assert 'tls_second_pass' not in completed['d']


def testSecondPassDoesNothingWithoutTransientFailure(monkeypatch):
	monkeypatch.setattr(webTLS.time, 'sleep', lambda seconds: pytest.fail('attente inattendue'))

	assert webTLS.retryTlsFailures({'a': failedTlsItem('a.example.com', 'unrecognized_name')}) == 0


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


def buildKexinitPacket(kex, hostKeys, ciphers, macs):
	def nameList(names):
		raw = ','.join(names).encode()
		return(len(raw).to_bytes(4, 'big') + raw)

	payload = (
		bytes([webTLS.SSH_MSG_KEXINIT]) + b'\x00' * 16
		+ nameList(kex) + nameList(hostKeys)
		+ nameList(ciphers) + nameList(ciphers)
		+ nameList(macs) + nameList(macs)
		+ nameList(['none']) + nameList(['none'])
		+ nameList([]) + nameList([])
		+ b'\x00' + b'\x00' * 4
	)
	padding = 8
	body = bytes([padding]) + payload + b'\x00' * padding
	return(len(body).to_bytes(4, 'big') + body)


class FakeSshConnection:
	def __init__(self, data):
		self.data = data
		self.sent = []

	def recv(self, size):
		chunk, self.data = self.data[:size], self.data[size:]
		return(chunk)

	def sendall(self, data):
		self.sent.append(data)

	def settimeout(self, value):
		pass

	def __enter__(self):
		return(self)

	def __exit__(self, *args):
		return(False)


MODERN_SSH = buildKexinitPacket(
	['mlkem768x25519-sha256', 'sntrup761x25519-sha512', 'curve25519-sha256', 'ext-info-s', 'kex-strict-s-v00@openssh.com'],
	['rsa-sha2-512', 'ssh-ed25519'],
	['chacha20-poly1305@openssh.com', 'aes128-ctr', 'aes256-gcm@openssh.com'],
	['hmac-sha2-256-etm@openssh.com'],
)


def testProbeSshReadsBannerAndKexinitInOneSegment(monkeypatch):
	connection = FakeSshConnection(b'SSH-2.0-OpenSSH_10.0 Debian-1\r\n' + MODERN_SSH)
	monkeypatch.setattr(webTLS.socket, 'create_connection', lambda *args, **kwargs: connection)

	probe = webTLS.probeSsh('192.0.2.1')

	assert connection.sent == [webTLS.SSH_CLIENT_BANNER]
	assert probe['banner'] == 'SSH-2.0-OpenSSH_10.0 Debian-1'
	# Les marqueurs d’extension ne sont pas des échanges de clés.
	assert probe['kex_algorithms'] == ['mlkem768x25519-sha256', 'sntrup761x25519-sha512', 'curve25519-sha256']
	assert probe['host_key_algorithms'] == ['rsa-sha2-512', 'ssh-ed25519']
	assert probe['ciphers'] == ['chacha20-poly1305@openssh.com', 'aes128-ctr', 'aes256-gcm@openssh.com']


@pytest.mark.parametrize('data', [
	b'HTTP/1.1 400 Bad Request\r\n\r\n',
	b'',
	b'SSH-2.0-OpenSSH_9.6\r\n' + (999999).to_bytes(4, 'big'),
	b'x' * 2000,
])
def testProbeSshNeedsAnSshServer(monkeypatch, data):
	monkeypatch.setattr(webTLS.socket, 'create_connection', lambda *args, **kwargs: FakeSshConnection(data))

	assert webTLS.probeSsh('192.0.2.1') is None


def testClassifySshModernServer():
	probe = webTLS.parseSshKexinit(MODERN_SSH[5:-8])
	result = webTLS.classifySsh({'banner': 'SSH-2.0-OpenSSH_10.0 Debian-1', **probe})

	assert result['ssh_software'] == 'OpenSSH_10.0'
	assert result['ssh_pqc_kex_status'] == 'hybrid'
	assert result['ssh_pqc_kex_algorithms'] == ['mlkem768x25519-sha256', 'sntrup761x25519-sha512']
	assert result['ssh_host_key_pqc_status'] == 'classical'
	assert result['ssh_cipher_256'] is True
	assert result['ssh_weak_algorithms'] == []
	assert result['ssh_legacy_macs'] == []


def testClassifySshOldServer():
	result = webTLS.classifySsh({
		'banner': 'SSH-2.0-OpenSSH_7.4',
		'kex_algorithms': ['sntrup761x25519-sha512@openssh.com', 'diffie-hellman-group14-sha1'],
		'host_key_algorithms': ['ssh-rsa', 'ssh-dss'],
		'ciphers': ['aes128-ctr', 'aes128-cbc', 'arcfour'],
		'macs': ['hmac-sha1', 'umac-64@openssh.com', 'hmac-sha2-256'],
	})

	# NTRU Prime est hybride mais non normalisé : statut distinct.
	assert result['ssh_pqc_kex_status'] == 'hybrid_sntrup'
	assert result['ssh_cipher_256'] is False
	assert result['ssh_weak_algorithms'] == [
		'aes128-cbc', 'arcfour', 'diffie-hellman-group14-sha1', 'ssh-dss', 'ssh-rsa',
	]
	# MAC de la configuration par défaut d’OpenSSH : signalés à part.
	assert result['ssh_legacy_macs'] == ['hmac-sha1', 'umac-64@openssh.com']


@pytest.mark.parametrize('mac, legacy, weak', [
	('hmac-sha1-etm@openssh.com', True, False),
	('umac-64-etm@openssh.com', True, False),
	('hmac-sha1-96', True, False),
	('hmac-md5', False, True),
	('umac-128-etm@openssh.com', False, False),
	('hmac-sha2-256-etm@openssh.com', False, False),
])
def testSshLegacyMacsAreNotWeakAlgorithms(mac, legacy, weak):
	assert bool(webTLS.SSH_LEGACY_MACS.match(mac)) is legacy
	assert bool(webTLS.SSH_WEAK_ALGORITHMS.match(mac)) is weak


def testClassifySshWithoutKexinitKeepsBanner():
	assert webTLS.classifySsh({'banner': 'SSH-1.5-Ancien'}) == {
		'ssh_banner': 'SSH-1.5-Ancien',
		'ssh_software': 'Ancien',
	}


def testSshIsProbedOncePerAddressAndProvesThePort(monkeypatch):
	calls = []

	def fakeProbe(hostip, **kwargs):
		calls.append(hostip)
		return({'banner': 'SSH-2.0-OpenSSH_9.6', 'kex_algorithms': ['curve25519-sha256'],
			'host_key_algorithms': ['ssh-ed25519'], 'ciphers': ['aes256-gcm@openssh.com'], 'macs': []}
			if hostip == '192.0.2.1' else None)

	monkeypatch.setattr(webTLS, 'probeSsh', fakeProbe)
	webTLS.resetSshCache()

	first = webTLS.analysePortEncryption({'port22': 'open'}, '192.0.2.1', 'a.example.com')
	second = webTLS.analysePortEncryption({'port22': 'open'}, '192.0.2.1', 'b.example.com')
	silent = webTLS.analysePortEncryption({'port22': 'open'}, '192.0.2.2', 'c.example.com')

	assert calls == ['192.0.2.1', '192.0.2.2']
	assert first == second
	assert first['tls_port22'] == 'ssh'
	assert first['ssh_pqc_kex_status'] == 'classical'
	# Un port 22 qui accepte la connexion sans bannière SSH n’est pas compté SSH.
	assert silent == {'tls_port22': None}


@pytest.mark.parametrize('response, expected', [
	(b'HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Basic realm="intranet", charset="UTF-8"\r\n\r\n',
		{'status': 401, 'schemes': ['Basic']}),
	(b'HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Negotiate\r\nwww-authenticate: NTLM\r\n\r\n',
		{'status': 401, 'schemes': ['Negotiate', 'NTLM']}),
	(b'HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Digest realm="x", qop="auth", nonce="abc"\r\n\r\n',
		{'status': 401, 'schemes': ['Digest']}),
	(b'HTTP/1.1 200 OK\r\nServer: nginx\r\n\r\n', {'status': 200, 'schemes': []}),
	(b'SSH-2.0-OpenSSH_9.6\r\n', None),
])
def testParseHttpAuthResponse(response, expected):
	assert webTLS.parseHttpAuthResponse(response) == expected


def testProbeHttpAuthSendsSniAndReadsHeaders(monkeypatch):
	calls = {}

	class FakeTlsConnection:
		def __init__(self):
			self.chunks = [b'HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: NTLM\r\n', b'\r\nbody']

		def __enter__(self):
			return(self)

		def __exit__(self, *args):
			return(False)

		def sendall(self, data):
			calls['request'] = data

		def settimeout(self, value):
			pass

		def recv(self, size):
			return(self.chunks.pop(0) if self.chunks else b'')

	class FakeContext:
		check_hostname = True
		verify_mode = None

		def wrap_socket(self, connection, server_hostname):
			calls['sni'] = server_hostname
			return(FakeTlsConnection())

	class FakeRawConnection:
		def __enter__(self):
			return(self)

		def __exit__(self, *args):
			return(False)

	def fakeConnect(address, timeout):
		calls['address'] = address
		return(FakeRawConnection())

	monkeypatch.setattr(webTLS.socket, 'create_connection', fakeConnect)
	monkeypatch.setattr(webTLS.ssl, 'create_default_context', FakeContext)

	result = webTLS.probeHttpAuth('192.0.2.10', 'portal.example.com')

	assert result == {'status': 401, 'schemes': ['NTLM']}
	assert calls['address'] == ('192.0.2.10', 443)
	assert calls['sni'] == 'portal.example.com'
	assert b'Host: portal.example.com\r\n' in calls['request']


def testProbeHttpAuthReturnsNoneWithoutAnswer(monkeypatch):
	def refuse(address, timeout):
		raise ConnectionRefusedError()

	monkeypatch.setattr(webTLS.socket, 'create_connection', refuse)

	assert webTLS.probeHttpAuth('192.0.2.10', 'portal.example.com') is None


@pytest.mark.parametrize('url, expected', [
	('https://login.microsoftonline.com/0000-tenant/oauth2/v2.0/authorize?client_id=x', ('Microsoft Entra ID', 'login.microsoftonline.com')),
	('https://contoso.b2clogin.com/contoso.onmicrosoft.com/oauth2/v2.0/authorize', ('Microsoft Entra ID', 'contoso.b2clogin.com')),
	('https://sts.example.com/adfs/ls/?SAMLRequest=abc', ('ADFS', 'sts.example.com')),
	('https://sso.example.com/realms/staff/protocol/openid-connect/auth?client_id=x', ('Keycloak', 'sso.example.com')),
	('https://example.okta.com/app/x/sso/saml', ('Okta', 'example.okta.com')),
	('https://auth.agentconnect.gouv.fr/api/v2/authorize', ('ProConnect', 'auth.agentconnect.gouv.fr')),
	('https://idp.example.org/sso?SAMLRequest=abc', ('SAML (non identifié)', 'idp.example.org')),
	('https://id.example.org/authorize?client_id=a&response_type=code&redirect_uri=https%3A%2F%2Fx', ('OpenID Connect (non identifié)', 'id.example.org')),
	('https://www.example.com/login', (None, None)),
	(None, (None, None)),
])
def testIdentifyIdp(url, expected):
	assert webTLS.identifyIdp(url) == expected


@pytest.mark.parametrize('url, corporate, expected', [
	('https://login.microsoftonline.com/0000-tenant/oauth2/authorize', ('login.microsoftonline.com/0000-tenant',), True),
	('https://login.microsoftonline.com/common/oauth2/authorize', ('login.microsoftonline.com/0000-tenant',), False),
	('https://sts.example.com/adfs/ls/', ('sts.example.com',), True),
	# Un préfixe ne vaut que pour un segment complet.
	('https://sts.example.com.evil.test/adfs/ls/', ('sts.example.com',), False),
	('https://sts.example.com/adfs/ls/', (), None),
])
def testIdpIsCorporate(url, corporate, expected):
	assert webTLS.idpIsCorporate(url, corporate) == expected


def webPage(url='https://www.example.com/', **values):
	return({
		'url': url, 'title': 'Accueil', 'password_fields': 0, 'otp_field': False, 'webauthn_field': False,
		'passkey_text': False, 'login_links': [], 'form_actions': [], 'frames': [], 'generator': '',
		'text_length': 5000, **values,
	})


@pytest.mark.parametrize('httpAuth, pages, expected', [
	({'status': 401, 'schemes': ['Basic']}, [], {'web_auth': 'http', 'web_auth_http_schemes': ['Basic']}),
	# Bearer protège une API : pas d’authentification interactive.
	({'status': 401, 'schemes': ['Bearer']}, [], {'web_auth': 'unknown'}),
	(None, [], {'web_auth': 'unknown'}),
	(None, [webPage()], {'web_auth': 'none', 'web_auth_url': None}),
	(None, [webPage('https://login.microsoftonline.com/t/oauth2/authorize?state=secret', password_fields=1)], {
		'web_auth': 'sso', 'web_auth_idp': 'Microsoft Entra ID', 'web_auth_idp_host': 'login.microsoftonline.com',
		'web_auth_url': 'https://login.microsoftonline.com/t/oauth2/authorize',
	}),
	(None, [webPage(form_actions=['https://sts.example.com/adfs/ls/?wa=wsignin1.0'])], {
		'web_auth': 'sso', 'web_auth_idp': 'ADFS',
	}),
	(None, [webPage('https://www.example.com/login', password_fields=1, otp_field=True, passkey_text=True)], {
		'web_auth': 'local_form', 'web_auth_url': 'https://www.example.com/login',
		'web_auth_mfa_hints': ['passkey', 'otp'],
	}),
	(None, [webPage('https://vpn.example.com/remote/login?lang=fr')], {
		'web_auth': 'local_form', 'web_auth_product': 'Fortinet SSL VPN',
	}),
	(None, [webPage(), webPage('https://www.example.com/connexion', password_fields=1)], {
		'web_auth': 'local_form', 'web_auth_login_link': True,
	}),
])
def testClassifyWebAuth(httpAuth, pages, expected):
	result = webTLS.classifyWebAuth(httpAuth, pages)

	assert {key: result[key] for key in expected} == expected
	assert 'state=' not in str(result['web_auth_url'])


def testChooseLoginLinkStaysOnSiteOrKnownIdp():
	page = webPage(login_links=[
		'https://partner.test/login',
		'https://login.microsoftonline.com/t/oauth2/authorize',
		'https://espace.example.com/connexion',
	])

	assert webTLS.chooseLoginLink(page, 'example.com') == 'https://login.microsoftonline.com/t/oauth2/authorize'
	assert webTLS.chooseLoginLink(webPage(login_links=['https://partner.test/login']), 'example.com') is None


def testRenderWebAuthFollowsOneLoginLink(monkeypatch):
	class FakeDriver:
		def __init__(self):
			self.visited = []
			self.pages = [
				webPage(login_links=['https://www.example.com/connexion']),
				webPage('https://www.example.com/connexion', password_fields=1),
			]
			self.quitCalled = False

		def get(self, url):
			self.visited.append(url)

		def execute_script(self, script):
			return(self.pages.pop(0))

		def quit(self):
			self.quitCalled = True

	driver = FakeDriver()
	created = []

	def fakeCreate(host, hostip=None):
		created.append((host, hostip))
		return(driver)

	monkeypatch.setattr(webTLS, 'createWebDriver', fakeCreate)
	monkeypatch.setattr(webTLS, 'WEB_AUTH_RENDER_DELAY', 0)
	monkeypatch.setattr(webTLS, 'WEB_AUTH_SPA_DELAY', 0)

	pages = webTLS.renderWebAuth('www.example.com', '192.0.2.10', 'example.com')

	assert created == [('www.example.com', '192.0.2.10')]
	assert driver.visited == ['https://www.example.com/', 'https://www.example.com/connexion']
	assert len(pages) == 2
	assert driver.quitCalled is True


def testWebAuthObservationSkipsBrowserForHttpAuth(monkeypatch):
	monkeypatch.setattr(webTLS, 'probeHttpAuth', lambda hostip, host: {'status': 401, 'schemes': ['NTLM']})
	monkeypatch.setattr(webTLS, 'renderWebAuth', lambda *args: pytest.fail('navigateur lancé'))

	result = webTLS.webAuthObservation('owa.example.com', '192.0.2.10')

	assert result['web_auth'] == 'http'
	assert result['web_auth_ip'] == '192.0.2.10'


def testAnalyseWebAuthenticationVisitsEachFqdnOnce(monkeypatch):
	calls = []

	def fakeObservation(host, hostip, registeredDomain=None, corporateIdp=()):
		calls.append((host, hostip, registeredDomain, corporateIdp))
		return({'web_auth': 'sso', 'web_auth_idp': 'ADFS'})

	monkeypatch.setattr(webTLS, 'webAuthAvailability', lambda: None)
	monkeypatch.setattr(webTLS, 'webAuthObservation', fakeObservation)
	items = [
		{'host': 'www.example.com', 'ip': '192.0.2.20', 'port443': 'open', 'certificate_sha256': 'a', 'domain_name': 'example.com'},
		{'host': 'www.example.com', 'ip': '192.0.2.3', 'port443': 'open', 'certificate_sha256': 'a', 'domain_name': 'example.com'},
		# Sans certificat, pas de page HTTPS à analyser.
		{'host': 'mail.example.com', 'ip': '192.0.2.4', 'port443': 'open'},
		# Déjà observé avant une reprise de checkpoint.
		{'host': 'done.example.com', 'ip': '192.0.2.5', 'port443': 'open', 'certificate_sha256': 'b', 'web_auth': 'none'},
	]

	visited = webTLS.analyseWebAuthentication(items, corporateIdp=('sts.example.com',))

	assert visited == 1
	assert calls == [('www.example.com', '192.0.2.3', 'example.com', ('sts.example.com',))]
	assert [item.get('web_auth') for item in items] == ['sso', 'sso', None, 'none']


def testAnalyseWebAuthenticationNeedsChromedriver(monkeypatch):
	monkeypatch.setattr(webTLS, 'webAuthAvailability', lambda: 'chromedriver absent ou non exécutable')
	monkeypatch.setattr(webTLS, 'webAuthObservation', lambda *args: pytest.fail('analyse lancée'))
	items = [{'host': 'www.example.com', 'ip': '192.0.2.3', 'port443': 'open', 'certificate_sha256': 'a'}]

	assert webTLS.analyseWebAuthentication(items) == 0
	assert 'web_auth' not in items[0]


@pytest.mark.parametrize('url', ['https://[::1/x', 'https://h.example.com:99999/', 'https://h.example.com:abc/', None])
def testMalformedPageUrlsAreIgnored(url):
	assert webTLS.splitUrl(url) is None or url is None
	assert webTLS.cleanUrl(url) is None
	assert webTLS.identifyIdp(url) == (None, None)
	assert webTLS.idpIsCorporate(url, ('sts.example.com',)) is False
	page = webPage(form_actions=[url] if url else [], login_links=[url] if url else [])
	assert webTLS.classifyWebAuth(None, [page])['web_auth'] == 'none'
	assert webTLS.chooseLoginLink(page, 'example.com') is None


def testPublicWordPressHomeIsNotALoginPage():
	home = webPage('https://blog.example.com/', generator='WordPress 6.5', login_links=['https://blog.example.com/wp-login.php'])

	result = webTLS.classifyWebAuth(None, [home])

	assert result['web_auth'] == 'none'
	assert result['web_auth_product'] == 'WordPress'
	assert webTLS.chooseLoginLink(home, 'example.com') == 'https://blog.example.com/wp-login.php'
	assert webTLS.classifyWebAuth(None, [home, webPage('https://blog.example.com/wp-login.php', password_fields=1)])['web_auth'] == 'local_form'


def testAnalyseWebAuthenticationSurvivesAnUnexpectedError(monkeypatch):
	def failingObservation(host, hostip, registeredDomain=None, corporateIdp=()):
		if host == 'bad.example.com':
			raise ValueError('Port out of range 0-65535')
		return({'web_auth': 'none'})

	monkeypatch.setattr(webTLS, 'webAuthAvailability', lambda: None)
	monkeypatch.setattr(webTLS, 'webAuthObservation', failingObservation)
	items = [
		{'host': 'bad.example.com', 'ip': '192.0.2.1', 'port443': 'open', 'certificate_sha256': 'a'},
		{'host': 'good.example.com', 'ip': '192.0.2.2', 'port443': 'open', 'certificate_sha256': 'b'},
	]

	assert webTLS.analyseWebAuthentication(items) == 2
	assert [item['web_auth'] for item in items] == ['unknown', 'none']
	assert items[0]['web_auth_ip'] == '192.0.2.1'
