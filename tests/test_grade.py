import pytest

import asmiraGrade


MODERN = [
	'TLS_AKE_WITH_AES_256_GCM_SHA384',
	'TLS_AKE_WITH_CHACHA20_POLY1305_SHA256',
]
TLS12 = [
	'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384',
	'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256',
]


def endpoint(**overrides):
	item = {
		'port443': 'open',
		'certificate_sha256': 'abc',
		'TLSv1.3': list(MODERN),
		'TLSv1.2': list(TLS12),
		'public_key': 'RSAPublicKey',
		'key_size': 4096,
		'signature_hash': 'sha256',
		'chain_valid': True,
		'verify_message': 'ok',
		'self-signed': False,
		'has_expired': False,
		'remain': 200,
		'certificate_lifetime_days': 90,
		'hsts_max_age': 31536000,
	}
	item.update(overrides)
	return(item)


def testModernEndpointWithHstsGetsAPlus():
	result = asmiraGrade.gradeEndpoint(endpoint())

	assert result['grade'] == 'A+'
	assert result['findings'] == []
	# AES-128 et AES-256 proposés : chiffrement (80 + 100) / 2 = 90, total 96.
	assert result['score'] == 96


def testMissingHstsStaysAAndIsReported():
	result = asmiraGrade.gradeEndpoint(endpoint(hsts_max_age=None))

	assert result['grade'] == 'A'
	assert result['findings'] == ['HSTS_MISSING']


def testMissingTls13CapsAtAMinus():
	result = asmiraGrade.gradeEndpoint(endpoint(**{'TLSv1.3': []}))

	assert result['grade'] == 'A-'
	assert 'NO_TLS13' in result['findings']


def testLegacyProtocolsCapAtB():
	result = asmiraGrade.gradeEndpoint(endpoint(**{
		'TLSv1.0': ['TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA'],
		'TLSv1.1': ['TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA'],
	}))

	assert result['grade'] == 'B'
	assert {'TLS10_ENABLED', 'TLS11_ENABLED'} <= set(result['findings'])


def testTripleDesCapsAtCAndScoresAs112Bits():
	result = asmiraGrade.gradeEndpoint(endpoint(**{
		'TLSv1.2': TLS12 + ['TLS_RSA_WITH_3DES_EDE_CBC_SHA'],
	}))

	assert result['grade'] == 'C'
	assert 'WEAK_64BIT_CIPHER' in result['findings']
	assert result['cipher_score'] == 60


def testNullCipherIsF():
	result = asmiraGrade.gradeEndpoint(endpoint(**{
		'TLSv1.2': TLS12 + ['TLS_RSA_WITH_NULL_SHA256'],
	}))

	assert result['grade'] == 'F'


@pytest.mark.parametrize('overrides, grade, finding', [
	({'has_expired': True, 'chain_valid': False}, 'T', 'CERT_EXPIRED'),
	({'self-signed': True, 'chain_valid': False}, 'T', 'CERT_SELF_SIGNED'),
	(
		{'chain_valid': False, 'verify_message': 'unable to verify the first certificate'},
		'T',
		'CHAIN_UNTRUSTED',
	),
	({'chain_valid': False, 'verify_message': 'hostname mismatch'}, 'M', 'CERT_HOSTNAME_MISMATCH'),
])
def testTrustProblemsOverrideCryptoGrade(overrides, grade, finding):
	result = asmiraGrade.gradeEndpoint(endpoint(**overrides))

	assert result['grade'] == grade
	assert finding in result['findings']
	assert result['grade_if_trusted'] == 'A+'


def testHandshakeFailureIsNotGraded():
	result = asmiraGrade.gradeEndpoint({'port443': 'open'})

	assert result['grade'] == asmiraGrade.NOT_GRADED
	assert result['findings'] == ['TLS_HANDSHAKE_FAILED']


def testClosedPortIsIgnored():
	assert asmiraGrade.gradeEndpoint({'port443': 'filtered'}) is None


def testInformationalFindingsDoNotChangeGrade():
	result = asmiraGrade.gradeEndpoint(endpoint(remain=10, certificate_lifetime_days=730))

	assert result['grade'] == 'A+'
	assert {'CERT_EXPIRES_30D', 'CERT_LIFETIME_OVER_398D'} <= set(result['findings'])


def testWeakRsaKeyCapsAtB():
	result = asmiraGrade.gradeEndpoint(endpoint(key_size=1024))

	assert result['grade'] == 'B'
	assert 'WEAK_KEY_UNDER_2048' in result['findings']


@pytest.mark.parametrize('name, bits', [
	('TLS_AKE_WITH_AES_128_GCM_SHA256', 128),
	('TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256', 256),
	('ECDHE-RSA-AES256-GCM-SHA384', 256),
	('DES-CBC3-SHA', 112),
	('TLS_RSA_WITH_RC4_128_SHA', 128),
	('EXP-RC4-MD5', 40),
	('TLS_RSA_WITH_NULL_SHA', 0),
])
def testCipherBitsAcceptsIanaAndOpenSslNames(name, bits):
	assert asmiraGrade.cipherBits(name) == bits


def testOpenSslNamesAreRecognisedForForwardSecrecy():
	result = asmiraGrade.gradeEndpoint(endpoint(**{
		'TLSv1.3': [],
		'TLSv1.2': ['EDH-RSA-AES256-GCM-SHA384'],
	}))

	assert 'NO_FORWARD_SECRECY' not in result['findings']


def testFqdnTakesWorstIpAndUnionOfFindings():
	result = asmiraGrade.gradeFqdn([
		endpoint(),
		endpoint(**{'TLSv1.3': []}),
		{'port443': 'closed'},
	])

	assert result['grade'] == 'A-'
	assert result['grade_version'] == asmiraGrade.GRADE_VERSION
	assert 'NO_TLS13' in result['findings']
	assert result['findings_severity'] == ['low']


def testFqdnWithoutOpenHttpsIsNotGraded():
	assert asmiraGrade.gradeFqdn([{'port443': 'closed'}]) is None


def testEveryFindingHasKnownSeverityAndCap():
	for severity, cap, remediation in asmiraGrade.FINDINGS.values():
		assert severity in asmiraGrade.SEVERITY_ORDER
		assert cap is None or cap in asmiraGrade.GRADE_ORDER
		assert remediation
