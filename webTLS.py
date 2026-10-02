#!/usr/bin/env python3

import argparse
import contextlib
import os
import sys
import re
import requests
import urllib3
import shutil
import socket
import subprocess
import threading
import time
import json
import warnings
import dns.resolver
import dns.zone
import OpenSSL
import ipaddress
import hashlib
import numpy as np
import pandas as pd
import inspect
import tldextract
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit
from cryptography import x509
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, dsa, ec, ed25519, ed448, x25519, x448

from asmiraCommon import atomicWriteJson, createRunId, readJson, utcNow, validateRunId

try:
	import geoip2.database
	import geoip2.errors
except ImportError:
	geoip2 = None

try:
	import shodan
except ImportError:
	shodan = None

try:
	import whois
except ImportError:
	whois = None

try:
	from selenium import webdriver
	from selenium import common
except ImportError:
	webdriver = None
	common = None


debug = False
cipherList = None
now = datetime.now().date().strftime('%Y%m%d')

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / 'data'
PICTURES_DIR = BASE_DIR / 'pictures'
APP_DATA_DIR = DATA_DIR / 'app'
HOST_LABEL_PATTERN = re.compile(r'^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$')
DOMAIN_EXTRACTOR = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None)
COMMAND_TIMEOUT = 15
TLS_TIMEOUT = 8
TLS_VERSIONS = ('TLSv1.3', 'TLSv1.2', 'TLSv1.1', 'TLSv1.0', 'SSLv3')
SCANNED_PORTS = (22, 25, 80, 443, 465, 587, 993, 995, 3389, 8080, 8443)
# Ports où le client ouvre directement une session TLS.
IMPLICIT_TLS_PORTS = (443, 465, 993, 995, 8080, 8443)
# Ports où TLS s’obtient par STARTTLS, avec le protocole attendu par OpenSSL.
STARTTLS_PORTS = {25: 'smtp', 587: 'smtp'}
# Port HTTP en clair par nature : HSTS et la redirection vers HTTPS le couvrent ;
# il est affiché mais ne compte pas comme service non chiffré. Le 8080 n’en fait
# pas partie : HSTS conserve le port lors de la bascule vers HTTPS (RFC 6797,
# section 8.3), et la sonde n’y classe « clear » qu’une réponse en clair prouvée.
HTTP_CLEARTEXT_PORTS = (80,)
PORT_PROBE_TIMEOUT = 5
# Groupes d’échange de clés post-quantiques connus d’OpenSSL 3.5. Les groupes
# hybrides associent ML-KEM (FIPS 203) à un algorithme classique, comme l’exige
# l’ANSSI ; les groupes ML-KEM seuls ne satisfont pas cette exigence.
PQC_HYBRID_KEX_GROUPS = (
	'X25519MLKEM768',
	'SecP256r1MLKEM768',
	'SecP384r1MLKEM1024',
)
PQC_PURE_KEX_GROUPS = (
	'MLKEM512',
	'MLKEM768',
	'MLKEM1024',
)
PQC_KEX_GROUPS = PQC_HYBRID_KEX_GROUPS + PQC_PURE_KEX_GROUPS
MANAGED_PICTURE_PREFIXES = ('graph_', 'screenshot_')
PQC_ALGORITHMS_BY_OID = {
	**{
		f'2.16.840.1.101.3.4.3.{identifier}': name
		for identifier, name in (
			(17, 'ML-DSA-44'),
			(18, 'ML-DSA-65'),
			(19, 'ML-DSA-87'),
		)
	},
	**{
		f'2.16.840.1.101.3.4.3.{identifier}': name
		for identifier, name in (
			(20, 'SLH-DSA-SHA2-128s'),
			(21, 'SLH-DSA-SHA2-128f'),
			(22, 'SLH-DSA-SHA2-192s'),
			(23, 'SLH-DSA-SHA2-192f'),
			(24, 'SLH-DSA-SHA2-256s'),
			(25, 'SLH-DSA-SHA2-256f'),
			(26, 'SLH-DSA-SHAKE-128s'),
			(27, 'SLH-DSA-SHAKE-128f'),
			(28, 'SLH-DSA-SHAKE-192s'),
			(29, 'SLH-DSA-SHAKE-192f'),
			(30, 'SLH-DSA-SHAKE-256s'),
			(31, 'SLH-DSA-SHAKE-256f'),
			(35, 'HashSLH-DSA-SHA2-128s-SHA256'),
			(36, 'HashSLH-DSA-SHA2-128f-SHA256'),
			(37, 'HashSLH-DSA-SHA2-192s-SHA512'),
			(38, 'HashSLH-DSA-SHA2-192f-SHA512'),
			(39, 'HashSLH-DSA-SHA2-256s-SHA512'),
			(40, 'HashSLH-DSA-SHA2-256f-SHA512'),
			(41, 'HashSLH-DSA-SHAKE-128s-SHAKE128'),
			(42, 'HashSLH-DSA-SHAKE-128f-SHAKE128'),
			(43, 'HashSLH-DSA-SHAKE-192s-SHAKE256'),
			(44, 'HashSLH-DSA-SHAKE-192f-SHAKE256'),
			(45, 'HashSLH-DSA-SHAKE-256s-SHAKE256'),
			(46, 'HashSLH-DSA-SHAKE-256f-SHAKE256'),
		)
	},
}
HYBRID_PQC_ALGORITHMS_BY_OID = {
	f'1.3.6.1.5.5.7.6.{identifier}': name
	for identifier, name in (
		(37, 'ML-DSA-44+RSA-2048-PSS'),
		(38, 'ML-DSA-44+RSA-2048-PKCS1'),
		(39, 'ML-DSA-44+Ed25519'),
		(40, 'ML-DSA-44+ECDSA-P256'),
		(41, 'ML-DSA-65+RSA-3072-PSS'),
		(42, 'ML-DSA-65+RSA-3072-PKCS1'),
		(43, 'ML-DSA-65+RSA-4096-PSS'),
		(44, 'ML-DSA-65+RSA-4096-PKCS1'),
		(45, 'ML-DSA-65+ECDSA-P256'),
		(46, 'ML-DSA-65+ECDSA-P384'),
		(47, 'ML-DSA-65+ECDSA-brainpoolP256r1'),
		(48, 'ML-DSA-65+Ed25519'),
		(49, 'ML-DSA-87+ECDSA-P384'),
		(50, 'ML-DSA-87+ECDSA-brainpoolP384r1'),
		(51, 'ML-DSA-87+Ed448'),
		(52, 'ML-DSA-87+RSA-3072-PSS'),
		(53, 'ML-DSA-87+RSA-4096-PSS'),
		(54, 'ML-DSA-87+ECDSA-P521'),
	)
}
CLASSICAL_CERTIFICATE_ALGORITHM_OIDS = frozenset({
	'1.2.840.10040.4.1',
	'1.2.840.10040.4.3',
	'1.2.840.10045.2.1',
	'1.2.840.10045.4.1',
	'1.2.840.10045.4.3.1',
	'1.2.840.10045.4.3.2',
	'1.2.840.10045.4.3.3',
	'1.2.840.10045.4.3.4',
	'1.2.840.113549.1.1.1',
	'1.2.840.113549.1.1.4',
	'1.2.840.113549.1.1.5',
	'1.2.840.113549.1.1.10',
	'1.2.840.113549.1.1.11',
	'1.2.840.113549.1.1.12',
	'1.2.840.113549.1.1.13',
	'1.2.840.113549.1.1.14',
	'1.3.14.3.2.29',
	'1.3.101.110',
	'1.3.101.111',
	'1.3.101.112',
	'1.3.101.113',
	'2.16.840.1.101.3.4.3.1',
	'2.16.840.1.101.3.4.3.2',
	'2.16.840.1.101.3.4.3.9',
	'2.16.840.1.101.3.4.3.10',
	'2.16.840.1.101.3.4.3.11',
	'2.16.840.1.101.3.4.3.12',
})


dicTools = {
	'netcat': shutil.which('netcat') or shutil.which('nc'),
	'nmap': shutil.which('nmap'),
	'openssl': shutil.which('openssl'),
}


def certificateAlgorithmKind(oid):
	if oid in HYBRID_PQC_ALGORITHMS_BY_OID:
		return('hybrid')
	if oid in PQC_ALGORITHMS_BY_OID:
		return('pqc')
	if oid in CLASSICAL_CERTIFICATE_ALGORITHM_OIDS:
		return('classical')
	return('unknown')


def classifyCertificatePqc(publicKeyOid, signatureOid):
	oids = (publicKeyOid, signatureOid)
	kinds = tuple(certificateAlgorithmKind(oid) for oid in oids)
	algorithms = list(dict.fromkeys(
		algorithm
		for oid in oids
		for algorithm in (
			PQC_ALGORITHMS_BY_OID.get(oid)
			or HYBRID_PQC_ALGORITHMS_BY_OID.get(oid),
		)
		if algorithm is not None
	))
	if 'hybrid' in kinds:
		status = 'hybrid'
	elif kinds == ('pqc', 'pqc'):
		status = 'pqc'
	elif 'pqc' in kinds and 'classical' in kinds:
		status = 'partial'
	elif kinds == ('classical', 'classical'):
		status = 'classical'
	else:
		status = 'unknown'
	return(status, algorithms)


def configureTools(netcat=None, nmap=None, openssl=None):
	overrides = {
		'netcat': netcat,
		'nmap': nmap,
		'openssl': openssl,
	}
	for name, path in overrides.items():
		if path is not None:
			dicTools[name] = str(path)
	return(dict(dicTools))


@contextlib.contextmanager
def commandSlot(commandSemaphore=None):
	if commandSemaphore is None:
		yield
		return
	commandSemaphore.acquire()
	try:
		yield
	finally:
		commandSemaphore.release()




def testTools():
	missingTools = []
	for name, path in dicTools.items():
		if path is None or not Path(path).is_file() or not os.access(path, os.X_OK):
			missingTools.append(f'{name} ({path})')
	if missingTools:
		raise RuntimeError('Outils requis absents ou non exécutables : ' + ', '.join(missingTools))
	print('### All needed tools present')


def debugDisplay():
	if debug:
		frame = inspect.currentframe()
		caller = frame.f_back if frame else None
		if caller:
			print(f'[debug] Function {caller.f_code.co_name}')


def removeOldFiles():
	PICTURES_DIR.mkdir(parents=True, exist_ok=True)
	for filePath in PICTURES_DIR.iterdir():
		if filePath.is_file() and filePath.name.startswith(MANAGED_PICTURE_PREFIXES):
			filePath.unlink()
	print('### Old files removed')


def isIPv4(data):
	debugDisplay()
	try:
		return(isinstance(ipaddress.ip_address(str(data).strip()), ipaddress.IPv4Address))
	except ValueError:
		return(False)


def ipSortKey(address):
	ip = ipaddress.ip_address(address)
	return(ip.version, int(ip))


def normalizeHost(host):
	debugDisplay()
	if not isinstance(host, str):
		raise TypeError('Un hôte doit être fourni sous forme de chaîne')

	value = host.strip()
	if not value:
		raise ValueError('Le nom d’hôte est vide')
	if value.startswith('*.'):
		raise ValueError(f'Un wildcard n’est pas un hôte concret : {host!r}')

	parsed = urlsplit(value if '://' in value else f'//{value}')
	hostname = parsed.hostname
	if not hostname:
		raise ValueError(f'Nom d’hôte invalide : {host!r}')

	hostname = hostname.rstrip('.').lower()
	try:
		ipaddress.ip_address(hostname)
	except ValueError:
		pass
	else:
		raise ValueError(f'Une adresse IP n’est pas un nom de domaine : {host!r}')

	try:
		hostname = hostname.encode('idna').decode('ascii')
	except UnicodeError as error:
		raise ValueError(f'Nom d’hôte IDNA invalide : {host!r}') from error

	labels = hostname.split('.')
	if (
		len(hostname) > 253
		or len(labels) < 2
		or any(not HOST_LABEL_PATTERN.fullmatch(label) for label in labels)
	):
		raise ValueError(f'Nom d’hôte invalide : {host!r}')
	return(hostname)


def isSelfSignedCert(certPEM):
	debugDisplay()
	if isinstance(certPEM, str):
		certPEM = certPEM.encode()
	cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, certPEM)
	if cert.get_subject().get_components() != cert.get_issuer().get_components():
		return(False)
	store = OpenSSL.crypto.X509Store()
	store.add_cert(cert)
	context = OpenSSL.crypto.X509StoreContext(store, cert)
	try:
		context.verify_certificate()
		isSelfSigned = True
	except OpenSSL.crypto.X509StoreContextError:
		isSelfSigned = False
	return(isSelfSigned)


def extractListHosts(jsonFile=None):
	debugDisplay()
	jsonFile = DATA_DIR / f'{now}_hosts_list.json' if jsonFile is None else Path(jsonFile)
	with jsonFile.open('r', encoding='utf-8') as filePointer:
		data = json.load(filePointer)
	if not isinstance(data, list):
		raise ValueError(f'Format JSON invalide dans {jsonFile}: une liste est attendue')
	hosts = []
	for row in data:
		if not isinstance(row, dict) or 'host' not in row:
			raise ValueError(f'Entrée invalide dans {jsonFile}: {row!r}')
		hosts.append(normalizeHost(row['host']))
	return(np.array(sorted(set(hosts)), dtype=object))


def extractDomain(host):
	debugDisplay()
	host = normalizeHost(host)
	extracted = DOMAIN_EXTRACTOR(host)
	domain = extracted.top_domain_under_public_suffix
	if not domain:
		raise ValueError(f'Impossible de déterminer le domaine enregistré de {host!r}')
	return(domain)


def extractNmapPorts(data):
	debugDisplay()
	result = {'live': 'down'}
	result.update({f'port{port}': 'closed' for port in SCANNED_PORTS})
	rawData = data.stdout if hasattr(data, 'stdout') else data
	if isinstance(rawData, bytes):
		rawData = rawData.decode(errors='replace')
	for row in str(rawData).splitlines():
		if row.startswith('Host is up'):
			result['live'] = 'up'
		match = re.match(r'^(\d+)/tcp\s+(\S+)', row.strip())
		if match and int(match.group(1)) in SCANNED_PORTS:
			result[f'port{match.group(1)}'] = match.group(2)
	return(result)


def extractTLSdata(data):
	debugDisplay()
	if isinstance(data, bytes):
		data = data.decode(errors='replace')
	regex = r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----"
	sessionCertif = re.search(regex, data, re.DOTALL)
	if (sessionCertif):
		certData = extractCertificateData(sessionCertif.group())
	else:
		return(None)
	verifyMatch = re.search(r'Verify return code:\s*(\d+)\s*\(([^)]*)\)', data)
	if verifyMatch:
		certData['chain_valid'] = verifyMatch.group(1) == '0'
		certData['verify_code'] = int(verifyMatch.group(1))
		certData['verify_message'] = verifyMatch.group(2)
	protocolMatch = re.search(r'^\s*Protocol\s*:\s*(\S+)', data, re.MULTILINE)
	# En TLS 1.3, OpenSSL n’imprime pas de bloc SSL-Session : la suite n’apparaît
	# que dans la ligne « New, TLSv1.3, Cipher is … ».
	cipherMatch = (
		re.search(r'^\s*Cipher\s*:\s*(\S+)', data, re.MULTILINE)
		or re.search(r'^New,\s*[^,]+,\s*Cipher is\s+(\S+)', data, re.MULTILINE)
	)
	if protocolMatch:
		certData['negotiated_protocol'] = normalizeTlsVersion(protocolMatch.group(1))
	if cipherMatch and cipherMatch.group(1) not in ('0000', '(NONE)'):
		certData['negotiated_cipher'] = cipherMatch.group(1)
	group = extractNegotiatedGroup(data)
	if group:
		certData['negotiated_group'] = group
	return(certData)


def extractNegotiatedGroup(data):
	# OpenSSL 3.5 nomme le groupe TLS 1.3 (« Negotiated TLS1.3 group ») ; sinon,
	# la clé éphémère du pair donne la courbe (« Peer Temp Key: ECDH, secp521r1 »).
	if isinstance(data, bytes):
		data = data.decode(errors='replace')
	match = re.search(r'Negotiated TLS1\.3 group:\s*(\S+)', data)
	if match and match.group(1) != '<NULL>':
		return(match.group(1))
	match = re.search(r'(?:Peer|Server) Temp Key:\s*([^,\n]+)(?:,\s*([^,\n]+))?', data)
	if not match:
		return(None)
	kind, name = match.group(1).strip(), (match.group(2) or '').strip()
	if kind in ('ECDH', 'DH') and name and not name.endswith('bits'):
		return(name)
	return(kind)


def testPqcKeyExchange(hostip, host, commandSemaphore=None, groups=PQC_KEX_GROUPS):
	"""Force une négociation TLS 1.3 limitée aux groupes indiqués. Renvoie le groupe
	accepté, False si le serveur les refuse, None si la sonde n’a pas abouti."""
	cmd = [
		dicTools['openssl'],
		's_client',
		'-connect',
		formatHostPort(hostip, 443),
		'-servername',
		host,
		'-tls1_3',
		'-groups',
		':'.join(groups),
	]
	try:
		with commandSlot(commandSemaphore):
			completed = subprocess.run(
				cmd,
				input=b'',
				stderr=subprocess.STDOUT,
				stdout=subprocess.PIPE,
				timeout=TLS_TIMEOUT,
				check=False,
			)
	except (OSError, subprocess.TimeoutExpired):
		return(None)
	output = completed.stdout.decode(errors='replace')
	group = extractNegotiatedGroup(output)
	if group in PQC_KEX_GROUPS:
		return(group)
	if re.search(r'New,\s*\(NONE\)|handshake failure|alert|no protocols available', output, re.IGNORECASE):
		return(False)
	return(None)


def extractCertificateData(certPEM):
	debugDisplay()
	if isinstance(certPEM, bytes):
		certBytes = certPEM
	else:
		certBytes = certPEM.encode()
	result = {}
	result['self-signed'] = isSelfSignedCert(certBytes)
	x509cert = x509.load_pem_x509_certificate(certBytes)
	publicKeyOid = x509cert.public_key_algorithm_oid.dotted_string
	signatureOid = x509cert.signature_algorithm_oid.dotted_string
	pqcStatus, pqcAlgorithms = classifyCertificatePqc(publicKeyOid, signatureOid)
	result['public_key_algorithm_oid'] = publicKeyOid
	result['signature_algorithm_oid'] = signatureOid
	result['pqc_algorithms'] = pqcAlgorithms
	result['pqc_status'] = pqcStatus
	issuer = x509cert.issuer
	result['issuer_country'] = getAttribute(issuer, x509.OID_COUNTRY_NAME)
	result['issuer_organization'] = getAttribute(issuer, x509.OID_ORGANIZATION_NAME)
	result['issuer_common_name'] = getAttribute(issuer, x509.OID_COMMON_NAME)
	if hasattr(x509cert, 'not_valid_before_utc'):
		notBefore = x509cert.not_valid_before_utc
		notAfter = x509cert.not_valid_after_utc
	else:
		notBefore = x509cert.not_valid_before.replace(tzinfo=timezone.utc)
		notAfter = x509cert.not_valid_after.replace(tzinfo=timezone.utc)
	current = datetime.now(timezone.utc)
	delta = notAfter - current
	result['not_before'] = notBefore.strftime('%d-%m-%Y')
	result['not_after'] = notAfter.strftime('%d-%m-%Y')
	result['remain'] = delta.days
	result['has_expired'] = notAfter <= current
	result['certificate_lifetime_days'] = (notAfter - notBefore).days
	try:
		publicKey = x509cert.public_key()
		if isinstance(publicKey, rsa.RSAPublicKey):
			result['public_key'] = 'RSAPublicKey'
		elif isinstance(publicKey, dsa.DSAPublicKey):
			result['public_key'] = 'DSAPublicKey'
		elif isinstance(publicKey, ec.EllipticCurvePublicKey):
			result['public_key'] = 'EllipticCurvePublicKey'
		elif isinstance(publicKey, ed25519.Ed25519PublicKey):
			result['public_key'] = 'Ed25519PublicKey'
		elif isinstance(publicKey, ed448.Ed448PublicKey):
			result['public_key'] = 'Ed448PublicKey'
		elif isinstance(publicKey, x25519.X25519PublicKey):
			result['public_key'] = 'X25519PublicKey'
		elif isinstance(publicKey, x448.X448PublicKey):
			result['public_key'] = 'X448PublicKey'
		else:
			result['public_key'] = 'Unknown'
		result['key_size'] = getattr(publicKey, 'key_size', None)
	except UnsupportedAlgorithm:
		result['public_key'] = 'Unsupported'
		result['key_size'] = None
	subject = x509cert.subject
	result['subject_country'] = getAttribute(subject, x509.OID_COUNTRY_NAME)
	result['subject_locality'] = getAttribute(subject, x509.OID_LOCALITY_NAME)
	result['subject_organization'] = getAttribute(subject, x509.OID_ORGANIZATION_NAME)
	result['subject_common_name'] = getAttribute(subject, x509.OID_COMMON_NAME)
	try:
		sanExtension = x509cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
		result['subject_alt_names'] = sanExtension.value.get_values_for_type(x509.DNSName)
	except x509.ExtensionNotFound:
		result['subject_alt_names'] = []
	result['serial_number'] = format(x509cert.serial_number, 'x')
	result['certificate_sha256'] = x509cert.fingerprint(hashes.SHA256()).hex()
	result['signature_algorithm'] = signatureOid
	try:
		signatureHash = x509cert.signature_hash_algorithm
		result['signature_hash'] = signatureHash.name if signatureHash is not None else None
	except (AttributeError, TypeError, ValueError, UnsupportedAlgorithm):
		result['signature_hash'] = None
	return(result)


def extractNmapCipher(data):
	debugDisplay()
	result = {}
	if isinstance(data, (list, tuple)):
		data = '\n'.join(str(item) for item in data)
	if isinstance(data, bytes):
		data = data.decode(errors='replace')
	currentVersion = None
	for item in str(data).splitlines():
		item = item.lstrip('|_ ').strip()
		versionMatch = re.match(r'^(TLSv\d(?:\.\d)?|SSLv\d):$', item)
		if versionMatch:
			currentVersion = versionMatch.group(1)
			result.setdefault(currentVersion, [])
			continue
		if currentVersion and item.startswith('TLS_'):
			cipherName = item.split()[0]
			if cipherName not in result[currentVersion]:
				result[currentVersion].append(cipherName)
	return(result)


def extractShodanData(data):
	debugDisplay()
	for service in data.get('data', []):
		httpData = service.get('http') or {}
		if 'status' not in httpData:
			continue
		status = httpData.get('status')
		result = {
			'http_code': status,
			'http_reason': '',
			'server': httpData.get('server') or '',
		}
		statusLine = str(service.get('data') or '').splitlines()
		if statusLine:
			parts = statusLine[0].split(maxsplit=2)
			if len(parts) == 3 and parts[0].startswith('HTTP/'):
				result['http_reason'] = parts[2]
		return(result)
	return({})


def getGeoData(hostip):
	debugDisplay()
	result = {
		'geo_country': None,
		'geo_city': None,
		'geo_latitude': None,
		'geo_longitude': None,
		'geo_asn_number': None,
		'geo_asn_org': None,
	}
	if hostip is None or geoip2 is None:
		return(result)
	try:
		ipaddress.ip_address(hostip)
	except ValueError:
		return(result)

	try:
		with geoip2.database.Reader(APP_DATA_DIR / 'geolite2-city.mmdb') as reader:
			response = reader.city(hostip)
			result['geo_country'] = response.country.iso_code
			result['geo_city'] = response.city.name
			result['geo_latitude'] = response.location.latitude
			result['geo_longitude'] = response.location.longitude
	except (OSError, ValueError, geoip2.errors.GeoIP2Error):
		pass
	try:
		with geoip2.database.Reader(APP_DATA_DIR / 'geolite2-asn.mmdb') as reader:
			response = reader.asn(hostip)
			result['geo_asn_number'] = response.autonomous_system_number
			result['geo_asn_org'] = response.autonomous_system_organization
	except (OSError, ValueError, geoip2.errors.GeoIP2Error):
		pass
	return(result)


def getNameServer(domain):
	debugDisplay()
	try:
		answers = dns.resolver.resolve(domain, 'NS', lifetime=5)
	except dns.exception.DNSException:
		return([])
	return(sorted({rdata.to_text().rstrip('.').lower() for rdata in answers}))


def getIPs(host):
	debugDisplay()
	addresses = set()
	for recordType in ('A', 'AAAA'):
		try:
			answers = dns.resolver.resolve(host, recordType, lifetime=5)
		except dns.exception.DNSException:
			continue
		for rdata in answers:
			try:
				addresses.add(str(ipaddress.ip_address(rdata.to_text())))
			except ValueError:
				continue
	return(sorted(
		addresses,
		key=ipSortKey,
	))


def getIP(host, ns=None):
	debugDisplay()
	addresses = getIPs(host)
	return(addresses[0] if addresses else None)


def formatHostPort(hostip, port):
	ip = ipaddress.ip_address(hostip)
	return(f'[{ip}]:{port}' if ip.version == 6 else f'{ip}:{port}')


def normalizeTlsVersion(version):
	return('TLSv1.0' if version == 'TLSv1' else version)


def getNmapIpVersionArgs(hostip):
	return(
		['-6']
		if ipaddress.ip_address(hostip).version == 6
		else []
	)


def getPorts(hostip, commandSemaphore=None):
	debugDisplay()
	if hostip is None:
		return(extractNmapPorts(''))
	cmd = [
		dicTools['nmap'],
		'-n',
		'-Pn',
		*getNmapIpVersionArgs(hostip),
		'--host-timeout',
		f'{COMMAND_TIMEOUT}s',
		'-p' + ','.join(str(port) for port in SCANNED_PORTS),
		hostip,
	]
	try:
		with commandSlot(commandSemaphore):
			completed = subprocess.run(
				cmd,
				stdout=subprocess.PIPE,
				stderr=subprocess.DEVNULL,
				timeout=COMMAND_TIMEOUT + 2,
				check=False,
			)
	except (OSError, subprocess.TimeoutExpired):
		return(extractNmapPorts(''))
	return(extractNmapPorts(completed))


def getCertificate(host):
	debugDisplay()
	context = OpenSSL.SSL.Context(method=OpenSSL.SSL.TLS_METHOD)
	context.set_verify(OpenSSL.SSL.VERIFY_NONE, lambda *args: True)
	sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	sock.settimeout(TLS_TIMEOUT)
	sslsock = OpenSSL.SSL.Connection(context=context, socket=sock)
	sslsock.set_tlsext_host_name(host.encode())
	try:
		sslsock.connect((host, 443))
		sslsock.do_handshake()
		certX509 = sslsock.get_peer_certificate()
		if certX509 is None:
			return(None)
		certPEM = OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_PEM, certX509)
		return(extractCertificateData(certPEM))
	except (OSError, ValueError, OpenSSL.SSL.Error, OpenSSL.crypto.Error):
		return(None)
	finally:
		try:
			sslsock.close()
		finally:
			sock.close()


def parseHstsMaxAge(value):
	match = re.search(r'max-age\s*=\s*"?(\d+)', value or '', re.IGNORECASE)
	return(int(match.group(1)) if match else None)


def getHTTPheadersHash(host, hostip=None):
	return(getHTTPSHeaders(host, hostip)['hhhash'])


def getHTTPSHeaders(host, hostip=None):
	# https://github.com/adulau/HHHash/tree/master/hhhash
	debugDisplay()
	hhhash = ''
	hsts = None
	pool = None
	response = None
	try:
		with warnings.catch_warnings():
			warnings.simplefilter('ignore', urllib3.exceptions.InsecureRequestWarning)
			pool = urllib3.HTTPSConnectionPool(
				hostip or host,
				port=443,
				timeout=urllib3.Timeout(connect=3, read=5),
				retries=False,
				cert_reqs='CERT_NONE',
				assert_hostname=False,
				server_hostname=host,
			)
			response = pool.request(
				'GET',
				'/',
				headers={'Host': host, 'User-Agent': 'webTLS/1.0'},
				redirect=False,
				preload_content=False,
			)
		for header in response.headers.keys():
			hhhash = f"{hhhash}:{header}"
			if header.lower() == 'strict-transport-security':
				hsts = response.headers[header]
		m = hashlib.sha256()
		m.update(hhhash[1:].encode())
		digest = m.hexdigest()
		result = f'hhh:1:{digest}'
	except (OSError, urllib3.exceptions.HTTPError):
		result = 'hhh:1:none'
	finally:
		if response is not None:
			response.release_conn()
		if pool is not None:
			pool.close()
	return({
		'hhhash': result,
		'hsts': hsts,
		'hsts_max_age': parseHstsMaxAge(hsts),
	})


def getHTTPData(host, ip, commandSemaphore=None):
	debugDisplay()
	msg = (
		'GET / HTTP/1.0\r\n'
		f'Host: {host}\r\n'
		'User-Agent: webTLS/1.0\r\n'
		'Connection: close\r\n\r\n'
	)
	result = reqNetcat(
		ip,
		80,
		msg,
		**(
			{'commandSemaphore': commandSemaphore}
			if commandSemaphore is not None
			else {}
		),
	)
	if result.get('http_code') != '':
		result['http_source'] = 'live'
		return(result)
	result = testShodan(ip)
	if result:
		result['http_source'] = 'shodan'
	return(result)


def getAttribute(obj, attr):
	debugDisplay()
	try:
		value = obj.get_attributes_for_oid(attr)[0].value
		result = value.strip() if isinstance(value, str) else str(value)
	except (AttributeError, IndexError, TypeError):
		result = ''
	return(result)


def getAllCipherSuites(commandSemaphore=None):
	debugDisplay()
	output = []
	cmd = [dicTools['openssl'], 'ciphers', '-v', 'ALL:COMPLEMENTOFALL']
	try:
		with commandSlot(commandSemaphore):
			result = subprocess.run(
				cmd,
				stdout=subprocess.PIPE,
				stderr=subprocess.DEVNULL,
				timeout=COMMAND_TIMEOUT,
				check=True,
			)
	except (OSError, subprocess.SubprocessError) as error:
		raise RuntimeError(f'Impossible de lire les suites OpenSSL : {error}') from error
	for row in result.stdout.decode().split('\n'):
		fields = row.split()
		if len(fields) < 6:
			continue
		attributes = {
			name: value
			for field in fields[2:]
			if '=' in field
			for name, value in [field.split('=', 1)]
		}
		if not {'Kx', 'Au', 'Enc', 'Mac'}.issubset(attributes):
			continue
		output.append({
			'name': fields[0],
			'protocol': fields[1],
			'key_exchange': attributes['Kx'],
			'authentication': attributes['Au'],
			'encryption': attributes['Enc'],
			'integrity': attributes['Mac'],
		})
	print('### Cipher suites collected')
	return(output)


def getUnknownDomainInfo():
	return({
		'domain_create': 'Unknown',
		'domain_expire': 'Unknown',
		'domain_remain': 'Unknown',
		'domain_expired': 'Unknown',
		'domain_registrar': 'Unknown',
		'domain_dnssec': 'Unknown',
	})


def queryWhois(domain):
	debugDisplay()
	queryFunction = getattr(whois, 'query', None)
	if callable(queryFunction):
		return(queryFunction(domain, timeout=15))

	whoisFunction = getattr(whois, 'whois', None)
	if callable(whoisFunction):
		return(whoisFunction(domain))

	raise RuntimeError(
		f'API WHOIS incompatible dans {getattr(whois, "__file__", "module inconnu")}'
	)


def getFirstWhoisDate(value):
	if isinstance(value, (list, tuple)):
		return(next((item for item in value if item is not None), None))
	return(value)


def formatWhoisDate(value):
	if value is None or not hasattr(value, 'strftime'):
		return('Unknown')
	return(value.strftime('%d-%m-%Y'))


def getWhoisValue(value):
	if value is None or value == '':
		return('Unknown')
	return(value)


def getWhoisAttribute(response, name):
	if isinstance(response, dict):
		return(response.get(name))
	return(getattr(response, name, None))


def getDomainInfo(domain):
	debugDisplay()
	try:
		req = queryWhois(domain)
	except Exception as error:
		print(f'[avertissement] WHOIS indisponible pour {domain}: {error}', file=sys.stderr)
		return(getUnknownDomainInfo())

	if not req:
		return(getUnknownDomainInfo())

	creationDate = getFirstWhoisDate(getWhoisAttribute(req, 'creation_date'))
	expirationDate = getFirstWhoisDate(getWhoisAttribute(req, 'expiration_date'))
	result = {
		'domain_create': formatWhoisDate(creationDate),
		'domain_expire': formatWhoisDate(expirationDate),
		'domain_registrar': getWhoisValue(getWhoisAttribute(req, 'registrar')),
		'domain_dnssec': getWhoisValue(getWhoisAttribute(req, 'dnssec')),
	}

	if expirationDate and hasattr(expirationDate, 'tzinfo'):
		currentDate = datetime.now(expirationDate.tzinfo) if expirationDate.tzinfo else datetime.now()
		delta = expirationDate - currentDate
		result['domain_remain'] = delta.days
		result['domain_expired'] = expirationDate <= currentDate
	else:
		result['domain_remain'] = 'Unknown'
		result['domain_expired'] = 'Unknown'

	return(result)


def getScreenShot(host, hostip=None):
	debugDisplay()
	result = {
		'web_page_title': '',
		'cookie_count': 0,
		'screenshot': False,
	}
	if webdriver is None or common is None:
		return(result)
	url = 'https://' + host
	PICTURES_DIR.mkdir(parents=True, exist_ok=True)
	options = webdriver.ChromeOptions()
	options.add_argument("--headless=new")
	if hostip:
		options.add_argument(f'--host-resolver-rules=MAP {host} {hostip}')
	driver = None
	try:
		driver = webdriver.Chrome(options=options)
		driver.set_window_size(1280,720)
		driver.set_page_load_timeout(10)
		driver.get(url)
		result['web_page_title'] = driver.title
		result['cookie_count'] = len(driver.get_cookies())
		targetLabel = host if not hostip else f'{host}_{hostip}'
		fileName = (
			f'screenshot_{now}_'
			f'{re.sub(r"[^a-zA-Z0-9_-]", "_", targetLabel)}.png'
		)
		result['screenshot'] = bool(driver.get_screenshot_as_file(str(PICTURES_DIR / fileName)))
	except (common.exceptions.WebDriverException, OSError):
		pass
	finally:
		if driver is not None:
			try:
				driver.quit()
			except common.exceptions.WebDriverException:
				pass
	return(result)


def testShodan(ip):
	debugDisplay()
	key = os.environ.get('SHODAN_API_KEY')
	if shodan is None or not key or not ip:
		return({})
	api = shodan.Shodan(key)
	try:
		response = api.host(ip)
	except (shodan.APIError, OSError, requests.exceptions.RequestException):
		return({})
	if response and ip == response.get('ip_str'):
		return(extractShodanData(response))
	return({})


def testTLSold(hostip):
	debugDisplay()
	return(testTLS(hostip, hostip))


def testTLS(hostip, host, commandSemaphore=None):
	debugDisplay()
	cmd = [
		dicTools['openssl'],
		's_client',
		'-connect',
		formatHostPort(hostip, 443),
		'-servername',
		host,
		'-verify',
		'5',
		'-verify_hostname',
		host,
		'-CAfile',
		requests.certs.where(),
		'-showcerts',
	]
	try:
		with commandSlot(commandSemaphore):
			completed = subprocess.run(
				cmd,
				input=b'',
				stderr=subprocess.STDOUT,
				stdout=subprocess.PIPE,
				timeout=TLS_TIMEOUT,
				check=False,
			)
	except (OSError, subprocess.TimeoutExpired):
		return(None)
	try:
		return(extractTLSdata(completed.stdout))
	except (TypeError, ValueError, OpenSSL.crypto.Error):
		return(None)


def testOneCipherSuite(host, hostip, cipherSuite, commandSemaphore=None):
	debugDisplay()
	name = cipherSuite['name']
	if (cipherSuite['protocol'] == 'TLSv1.3'):
		args = ['-tls1_3', '-ciphersuites']
	else:
		args = ['-no_tls1_3', '-cipher']
	cmd = [
		dicTools['openssl'],
		's_client',
		'-connect',
		formatHostPort(hostip, 443),
		'-servername',
		host,
		args[0],
		args[1],
		name,
	]
	try:
		with commandSlot(commandSemaphore):
			completed = subprocess.run(
				cmd,
				input=b'',
				stderr=subprocess.STDOUT,
				stdout=subprocess.PIPE,
				timeout=TLS_TIMEOUT,
				check=False,
			)
	except (OSError, subprocess.TimeoutExpired):
		return(None)
	output = completed.stdout.decode(errors='replace')
	match = re.search(r'New,\s*([^,]+),\s*Cipher is\s+(\S+)', output)
	if not match or 'NONE' in match.group(1) or 'NONE' in match.group(2):
		return(None)
	return(normalizeTlsVersion(match.group(1).strip()), match.group(2).strip())


def testAllCipherSuites(host, hostip, commandSemaphore=None, cipherWorkers=32):
	debugDisplay()
	suites = (
		cipherList
		if cipherList is not None
		else getAllCipherSuites(commandSemaphore=commandSemaphore)
	)
	found = {}
	if suites:
		workerCount = min(cipherWorkers, len(suites))
		with ThreadPoolExecutor(max_workers=workerCount) as executor:
			futures = [
				executor.submit(
					testOneCipherSuite,
					host,
					hostip,
					cipherSuite,
					**(
						{'commandSemaphore': commandSemaphore}
						if commandSemaphore is not None
						else {}
					),
				)
				for cipherSuite in suites
			]
			for future in as_completed(futures):
				negotiated = future.result()
				if negotiated is None:
					continue
				protocol, name = negotiated
				found.setdefault(protocol, set()).add(name)
	availableCipherSuites = {
		protocol: sorted(names)
		for protocol, names in sorted(found.items())
	}
	return(availableCipherSuites)


def reqNetcat(host, port, msg, commandSemaphore=None):
	debugDisplay()
	result = {
		'http_code': '',
		'http_reason': '',
		'server': '',
	}
	if isinstance(msg, str):
		msg = msg.encode()
	cmd = [dicTools['netcat'], '-w', '5', host, str(port)]
	try:
		with commandSlot(commandSemaphore):
			completed = subprocess.run(
				cmd,
				input=msg,
				stderr=subprocess.STDOUT,
				stdout=subprocess.PIPE,
				timeout=TLS_TIMEOUT,
				check=False,
			)
	except (OSError, subprocess.TimeoutExpired):
		return(result)
	output = completed.stdout.decode(errors='replace')
	lines = output.replace('\r\n', '\n').splitlines()
	if lines:
		statusMatch = re.match(r'^HTTP/\S+\s+(\d{3})(?:\s+(.*))?$', lines[0].strip())
		if statusMatch:
			result['http_code'] = int(statusMatch.group(1))
			result['http_reason'] = statusMatch.group(2) or ''
	for line in lines[1:]:
		name, separator, value = line.partition(':')
		if separator and name.strip().lower() == 'server':
			result['server'] = value.strip()
			break
	return(result)


def reqNmap(host, hostip, commandSemaphore=None, cipherWorkers=8):
	debugDisplay()
	cmd = [
		dicTools['nmap'],
		'-n',
		'-Pn',
		*getNmapIpVersionArgs(hostip),
		'--host-timeout',
		'120s',
		'--script',
		'ssl-enum-ciphers',
		'--script-args',
		f'tls.servername={host}',
		'-p443',
		hostip,
	]
	try:
		with commandSlot(commandSemaphore):
			completed = subprocess.run(
				cmd,
				stderr=subprocess.STDOUT,
				stdout=subprocess.PIPE,
				timeout=130,
				check=False,
			)
		ciphers = extractNmapCipher(completed.stdout)
	except (OSError, subprocess.TimeoutExpired):
		ciphers = {}
	if not ciphers or not any(ciphers.values()):
		ciphers = testAllCipherSuites(
			host,
			hostip,
			commandSemaphore=commandSemaphore,
			cipherWorkers=cipherWorkers,
		)
	return(ciphers)


def buildListIps(
	hostList,
	destinationFile=None,
	workers=4,
	maxEndpoints=None,
	commandSemaphore=None,
):
	debugDisplay()
	output = []
	domainCache = {}
	nameServerCache = {}
	ipDataCache = {}
	hostsByIp = {}
	seenTargets = set()
	normalizedHosts = []
	for index, row in enumerate(hostList, start=1):
		if isinstance(row, str):
			rawHost = row
			perimeter = ''
		elif isinstance(row, (list, tuple, np.ndarray)) and len(row) >= 1:
			rawHost = row[0]
			perimeter = row[1] if len(row) >= 2 else ''
		else:
			print(f'[avertissement] Entrée hôte invalide ignorée : {row!r}', file=sys.stderr)
			continue

		try:
			host = normalizeHost(rawHost)
			domain = extractDomain(host)
		except (TypeError, ValueError) as error:
			print(f'[avertissement] Entrée hôte ignorée : {error}', file=sys.stderr)
			continue
		normalizedHosts.append((index, host, domain, perimeter))

	if maxEndpoints is not None:
		normalizedHosts = normalizedHosts[:maxEndpoints]

	for domain in sorted({item[2] for item in normalizedHosts}):
		nameServerCache[domain] = getNameServer(domain)
		domainCache[domain] = getDomainInfo(domain)

	resolvedHosts = {}
	if normalizedHosts:
		with ThreadPoolExecutor(max_workers=min(workers, len(normalizedHosts))) as executor:
			futureMap = {
				executor.submit(getIPs, host): host
				for unusedIndex, host, unusedDomain, unusedPerimeter in normalizedHosts
			}
			for future in as_completed(futureMap):
				host = futureMap[future]
				try:
					resolvedHosts[host] = future.result()
				except Exception as error:
					print(
						f'[avertissement] Résolution de {host} impossible : {error}',
						file=sys.stderr,
					)
					resolvedHosts[host] = []

	uniqueIps = sorted({
		ip
		for unusedIndex, host, unusedDomain, unusedPerimeter in normalizedHosts
		for ip in resolvedHosts.get(host, [])
	}, key=ipSortKey)
	if uniqueIps:
		with ThreadPoolExecutor(max_workers=min(workers, len(uniqueIps))) as executor:
			futureMap = {
				executor.submit(
					getPorts,
					ip,
					**(
						{'commandSemaphore': commandSemaphore}
						if commandSemaphore is not None
						else {}
					),
				): ip
				for ip in uniqueIps
			}
			for future in as_completed(futureMap):
				ip = futureMap[future]
				try:
					portData = future.result()
				except Exception as error:
					print(
						f'[avertissement] Scan de ports de {ip} impossible : {error}',
						file=sys.stderr,
					)
					portData = extractNmapPorts('')
				ipDataCache[ip] = {
					**portData,
					**getGeoData(ip),
				}

	for index, host, domain, perimeter in normalizedHosts:
		ns = nameServerCache[domain]
		ips = resolvedHosts.get(host, [])
		if not ips:
			ips = [None]
		for ip in ips:
			target = (host, ip)
			if target in seenTargets:
				continue
			seenTargets.add(target)
			print('%d %s (%s) --> %s' % (index, host, ns[0] if ns else 'NS inconnu', ip))
			result = {
				'host': host,
				'ip': ip,
				'domain_name': domain,
				'ns': ns,
				'alias': '',
			}
			if perimeter is not None and str(perimeter).strip():
				result['perimeter'] = str(perimeter).strip()
			result.update(domainCache[domain])
			if ip is None:
				result.update({
					**extractNmapPorts(''),
					**getGeoData(None),
				})
			else:
				result.update(ipDataCache[ip])
			output.append(result)
			if ip is not None:
				hostsByIp.setdefault(ip, []).append(host)
			if maxEndpoints is not None and len(output) >= maxEndpoints:
				break
		if maxEndpoints is not None and len(output) >= maxEndpoints:
			break

	for item in output:
		if item['ip'] is not None:
			item['alias'] = ' '.join(
				host for host in hostsByIp[item['ip']]
				if host != item['host']
			)
	print(pd.DataFrame(output))
	destinationFile = (
		DATA_DIR / f'{now}_list_ip.json'
		if destinationFile is None
		else Path(destinationFile)
	)
	atomicWriteJson(destinationFile, output)
	print('### IP list built')
	return(output)


def dfToExcel(df, destinationFile=None):
	debugDisplay()
	destinationFile = (
		DATA_DIR / f'{now}_hosts_analyse.xlsx'
		if destinationFile is None
		else Path(destinationFile)
	)
	destinationFile.parent.mkdir(parents=True, exist_ok=True)
	exportData = df.copy()
	for column in ('ns', 'subject_alt_names', *TLS_VERSIONS):
		if column in exportData.columns:
			exportData[column] = exportData[column].map(
				lambda value: ' '.join(str(item) for item in value)
				if isinstance(value, (list, tuple, set))
				else value
			)
	with pd.ExcelWriter(destinationFile, engine='xlsxwriter') as writer:
		exportData.to_excel(writer, sheet_name=now, na_rep='None', index=False)
		workbook = writer.book
		textwrap = workbook.add_format({'text_wrap': True, 'valign': 'vcenter'})
		worksheet = writer.sheets[now]
		if hasattr(worksheet, 'autofit'):
			worksheet.autofit()
		for column in ('ns', 'alias', 'subject_alt_names', 'web_page_title', *TLS_VERSIONS):
			if column in exportData.columns:
				index = exportData.columns.get_loc(column)
				worksheet.set_column(index, index, 48, textwrap)
	return(destinationFile)


def targetKey(item):
	return(f'{item.get("host", "")}\0{item.get("ip", "")}')


def classifyTlsProbe(output):
	"""Classe une sonde TLS sur des preuves : tls si la session aboutit ou si le
	serveur répond par une alerte TLS (il parle TLS mais refuse ce nom ou cette
	offre) ; clear si le serveur a répondu dans un autre protocole ; None sinon.
	Un silence ou une réinitialisation ne prouvent rien : derrière un CDN, de
	nombreux ports acceptent la connexion TCP sans rien servir."""
	if re.search(r'New,\s*(?:TLSv[\d.]+|SSLv3)', output):
		return('tls')
	if re.search(r'alert number|ssl/tls alert|tlsv1 alert|sslv3 alert', output, re.IGNORECASE):
		return('tls')
	if re.search(r'wrong version number|packet length too long|http request', output, re.IGNORECASE):
		return('clear')
	return(None)


# Bornes de la sonde SMTP : un serveur hostile ne doit pouvoir ni faire croître
# la mémoire ni immobiliser un worker et un slot du sémaphore.
SMTP_MAX_LINE = 1024
SMTP_MAX_REPLY = 16384


def readSmtpReply(connection, reader, deadline, maxLines=50):
	"""Lit une réponse SMTP (éventuellement multiligne) avant l’échéance absolue
	deadline (time.monotonic). Lève TimeoutError ou ValueError si le serveur
	dépasse l’échéance, la longueur de ligne ou la taille de réponse admises."""
	lines = []
	total = 0
	for unused in range(maxLines):
		remaining = deadline - time.monotonic()
		if remaining <= 0:
			raise TimeoutError('échéance de la sonde SMTP dépassée')
		connection.settimeout(remaining)
		line = reader.readline(SMTP_MAX_LINE + 1)
		if not line:
			break
		if len(line) > SMTP_MAX_LINE:
			raise ValueError('ligne SMTP trop longue')
		total += len(line)
		if total > SMTP_MAX_REPLY:
			raise ValueError('réponse SMTP trop volumineuse')
		lines.append(line)
		if len(line) < 4 or line[3:4] != b'-':
			break
	else:
		raise ValueError('réponse SMTP avec trop de lignes')
	return(lines)


def smtpReplyHasExtension(reply, extension):
	"""Détecte un mot-clé EHLO exact, sans accepter une simple sous-chaîne."""
	extension = extension.upper()
	for line in reply:
		if len(line) < 4 or line[:3] != b'250':
			continue
		payload = line[4:].strip()
		keyword = payload.split(None, 1)[0].upper() if payload else b''
		if keyword == extension:
			return(True)
	return(False)


def smtpOffersStartTls(hostip, port, timeout=None):
	"""True si le serveur SMTP annonce STARTTLS après EHLO, False s’il répond sans
	l’annoncer, None s’il n’a pas présenté de bannière 220 ou a dépassé les bornes
	de la sonde. timeout est un budget global pour tout l’échange."""
	timeout = PORT_PROBE_TIMEOUT if timeout is None else timeout
	deadline = time.monotonic() + timeout
	try:
		with socket.create_connection((hostip, port), timeout=timeout) as connection:
			reader = connection.makefile('rb')
			banner = readSmtpReply(connection, reader, deadline)
			if not banner or not banner[0].startswith(b'220'):
				return(None)
			connection.sendall(b'EHLO asmira.invalid\r\n')
			reply = readSmtpReply(connection, reader, deadline)
			with contextlib.suppress(OSError):
				connection.sendall(b'QUIT\r\n')
			if not reply or not reply[0].startswith(b'250'):
				return(None)
			return(smtpReplyHasExtension(reply, b'STARTTLS'))
	except (OSError, ValueError):
		return(None)


def testPortEncryption(hostip, host, port, commandSemaphore=None):
	"""Indique si le service d’un port ouvert est chiffré : tls (TLS direct),
	starttls, ssh, clear (le service répond sans chiffrement) ou None (aucune
	réponse probante, par exemple un port de CDN qui accepte la connexion)."""
	if port == 22:
		return('ssh')
	if port == 80:
		return('clear')
	if port in STARTTLS_PORTS:
		with commandSlot(commandSemaphore):
			offered = smtpOffersStartTls(hostip, port)
		if offered is not True:
			return(None if offered is None else 'clear')
	if port == 3389:
		cmd = [
			dicTools['nmap'], '-n', '-Pn', *getNmapIpVersionArgs(hostip),
			'--host-timeout', '60s', '--script', 'rdp-enum-encryption', '-p3389', hostip,
		]
	else:
		cmd = [
			dicTools['openssl'], 's_client',
			'-connect', formatHostPort(hostip, port),
			'-servername', host,
		]
		if port in STARTTLS_PORTS:
			cmd += ['-starttls', STARTTLS_PORTS[port]]
	try:
		with commandSlot(commandSemaphore):
			completed = subprocess.run(
				cmd,
				input=b'',
				stderr=subprocess.STDOUT,
				stdout=subprocess.PIPE,
				timeout=70 if port == 3389 else PORT_PROBE_TIMEOUT,
				check=False,
			)
	except (OSError, subprocess.TimeoutExpired):
		return(None)
	output = completed.stdout.decode(errors='replace')
	if port == 3389:
		# CredSSP (NLA) et la couche « SSL » reposent sur TLS ; « Native RDP » seul
		# signifie le chiffrement RDP historique (RC4). Sans réponse RDP, le port
		# n’est pas un service RDP identifié.
		if re.search(r'(?:CredSSP[^:]*|SSL):\s*SUCCESS', output):
			return('tls')
		if re.search(r'Native RDP:\s*SUCCESS', output):
			return('clear')
		return(None)
	result = classifyTlsProbe(output)
	if result == 'tls' and port in STARTTLS_PORTS:
		return('starttls')
	return(result)


def analysePortEncryption(item, ip, host, commandSemaphore=None):
	result = {}
	for port in SCANNED_PORTS:
		if item.get(f'port{port}') != 'open':
			continue
		if port == 443 and item.get('certificate_sha256'):
			result['tls_port443'] = 'tls'
			continue
		result[f'tls_port{port}'] = testPortEncryption(
			ip, host, port, commandSemaphore=commandSemaphore,
		)
	return(result)


def analysePqcKeyExchange(item, ip, host, commandSemaphore=None):
	"""Groupes ML-KEM acceptés par le serveur, hybrides ou non.

	Le groupe négocié par testTLS (OpenSSL 3.5 propose X25519MLKEM768 en premier)
	ou une première sonde proposant tous les groupes établit le support ; chaque
	autre groupe est alors testé seul pour dresser la liste complète. Un serveur
	sans ML-KEM ne coûte qu’une sonde.
	"""
	negotiated = item.get('negotiated_group')
	supportsTls13 = bool(item.get('TLSv1.3')) or item.get('negotiated_protocol') == 'TLSv1.3'
	if negotiated in PQC_KEX_GROUPS:
		first = negotiated
	elif not supportsTls13:
		# ML-KEM n’existe qu’en TLS 1.3 : inutile de sonder.
		return({
			'pqc_kex_group': None,
			'pqc_kex_groups': [],
			'pqc_kex_supported': False if item.get('certificate_sha256') else None,
			'pqc_kex_hybrid': False if item.get('certificate_sha256') else None,
		})
	else:
		first = testPqcKeyExchange(ip, host, commandSemaphore=commandSemaphore)
		if not first:
			return({
				'pqc_kex_group': None,
				'pqc_kex_groups': [],
				'pqc_kex_supported': None if first is None else False,
				'pqc_kex_hybrid': None if first is None else False,
			})
	accepted = {first}
	for group in PQC_KEX_GROUPS:
		if group == first:
			continue
		if testPqcKeyExchange(ip, host, commandSemaphore=commandSemaphore, groups=(group,)) == group:
			accepted.add(group)
	groups = [group for group in PQC_KEX_GROUPS if group in accepted]
	return({
		'pqc_kex_group': first,
		'pqc_kex_groups': groups,
		'pqc_kex_supported': True,
		'pqc_kex_hybrid': any(group in PQC_HYBRID_KEX_GROUPS for group in groups),
	})


def analyseEndpoint(
	item,
	captureScreenshots=True,
	commandSemaphore=None,
	cipherWorkers=8,
):
	item = dict(item)
	itemStartTime = time.monotonic()
	ip = item.get('ip')
	host = item.get('host')
	item['scan_status'] = 'success'
	item['scan_error'] = None
	try:
		if ip is not None:
			if item.get('port80') == 'open':
				httpData = getHTTPData(
					host,
					ip,
					**(
						{'commandSemaphore': commandSemaphore}
						if commandSemaphore is not None
						else {}
					),
				)
				item.update(httpData)
			if item.get('port443') == 'open':
				item.update(getHTTPSHeaders(host, ip))
				if captureScreenshots:
					item.update(getScreenShot(host, ip))
				item.update(
					testTLS(
						ip,
						host,
						**(
							{'commandSemaphore': commandSemaphore}
							if commandSemaphore is not None
							else {}
						),
					)
					or {}
				)
				ciphers = reqNmap(
					host,
					ip,
					cipherWorkers=cipherWorkers,
					**(
						{'commandSemaphore': commandSemaphore}
						if commandSemaphore is not None
						else {}
					),
				)
				for key, value in ciphers.items():
					item[key] = value
					item[f'nbr {key}'] = len(value)
				item.update(analysePqcKeyExchange(
					item,
					ip,
					host,
					**(
						{'commandSemaphore': commandSemaphore}
						if commandSemaphore is not None
						else {}
					),
				))
			item.update(analysePortEncryption(
				item,
				ip,
				host,
				**(
					{'commandSemaphore': commandSemaphore}
					if commandSemaphore is not None
					else {}
				),
			))
	except Exception as error:
		item['scan_status'] = 'failed'
		item['scan_error'] = f'{type(error).__name__}: {error}'
	item['scan_duration_seconds'] = round(time.monotonic() - itemStartTime, 3)
	item['observed_at'] = utcNow()
	return(item)


def tlsAnalyse(
	captureScreenshots=True,
	listIpFile=None,
	destinationFile=None,
	excelFile=None,
	workers=4,
	commandSemaphore=None,
	checkpointFile=None,
	checkpointEvery=25,
	generateXlsx=True,
	cipherWorkers=8,
):
	debugDisplay()
	startTime = time.monotonic()
	listIpFile = (
		DATA_DIR / f'{now}_list_ip.json'
		if listIpFile is None
		else Path(listIpFile)
	)
	destinationFile = (
		DATA_DIR / f'{now}_hosts_analyse.json'
		if destinationFile is None
		else Path(destinationFile)
	)
	checkpointFile = (
		destinationFile.with_suffix('.checkpoint.json')
		if checkpointFile is None
		else Path(checkpointFile)
	)
	output = readJson(listIpFile, default=[])
	if not isinstance(output, list):
		raise ValueError(f'Format JSON invalide dans {listIpFile}: une liste est attendue')
	checkpoint = readJson(checkpointFile, default=[])
	if not isinstance(checkpoint, list):
		raise ValueError(f'Format de checkpoint invalide dans {checkpointFile}')
	completedByKey = {
		targetKey(item): item
		for item in checkpoint
		if isinstance(item, dict) and item.get('scan_status') in ('success', 'failed')
	}
	pending = [item for item in output if targetKey(item) not in completedByKey]
	total = len(output)
	print(
		f'### Analyse de {len(pending)} endpoint(s), '
		f'{len(completedByKey)} repris du checkpoint'
	)
	sinceCheckpoint = 0
	if pending:
		with ThreadPoolExecutor(max_workers=min(workers, len(pending))) as executor:
			futureMap = {
				executor.submit(
					analyseEndpoint,
					item,
					captureScreenshots,
					commandSemaphore,
					cipherWorkers,
				): targetKey(item)
				for item in pending
			}
			for future in as_completed(futureMap):
				key = futureMap[future]
				result = future.result()
				completedByKey[key] = result
				sinceCheckpoint += 1
				print(
					f'({len(completedByKey)}/{total}) '
					f'{result.get("host")} --> {result.get("ip")} '
					f'[{result.get("scan_status")}, '
					f'{result.get("scan_duration_seconds")} s]'
				)
				if sinceCheckpoint >= checkpointEvery:
					orderedCheckpoint = [
						completedByKey[targetKey(item)]
						for item in output
						if targetKey(item) in completedByKey
					]
					atomicWriteJson(checkpointFile, orderedCheckpoint)
					sinceCheckpoint = 0

	output = [
		completedByKey[targetKey(item)]
		for item in output
		if targetKey(item) in completedByKey
	]
	atomicWriteJson(checkpointFile, output)
	df = pd.DataFrame(output)
	print(df)
	atomicWriteJson(destinationFile, output)
	if generateXlsx:
		dfToExcel(df, destinationFile=excelFile)
	gdh = time.strftime("%Hh %Mm %Ss", time.gmtime(time.monotonic() - startTime))
	print('Execution time: %s seconds' % (gdh))
	return(output)


def make_autopct(values):
	def my_autopct(pct):
		total = sum(values)
		val = int(round(pct*total/100.0))
		return '{p:.2f}%\n({v:d})'.format(p=pct,v=val)
	return my_autopct


def graphByColumn(data, head, graphType, limit):
	debugDisplay()
	if head not in data.columns:
		return(False)
	import matplotlib as mpl

	print('### graph distribution by ' + head)
	counts = data[head].dropna().value_counts()
	counts = counts[counts >= limit]
	if counts.empty:
		return(False)
	values = counts.to_dict()
	PICTURES_DIR.mkdir(parents=True, exist_ok=True)
	fig, ax = mpl.pyplot.subplots(figsize=(10, 8))
	if (graphType == 'pie'):
		ax.pie(values.values(), labels=values.keys(), autopct=make_autopct(values.values()), startangle=90)
		ax.axis('equal')
	if (graphType == 'barh'):
		labels = list(values.keys())
		ax.barh(np.arange(len(labels)), values.values(), align='center')
		ax.set_yticks(np.arange(len(labels)), labels=labels)
	ax.set_title('Distribution by '+ head)
	fileName = f'graph_{now}_{re.sub(r"[^a-zA-Z0-9_-]", "_", head)}.png'
	fig.savefig(PICTURES_DIR / fileName, transparent=True, dpi=300, bbox_inches='tight')
	mpl.pyplot.close(fig)
	return(True)


def graphGeoMap(data):
	debugDisplay()
	requiredColumns = {'host', 'geo_latitude', 'geo_longitude'}
	if not requiredColumns.issubset(data.columns):
		return(False)
	import geopandas
	import matplotlib as mpl

	print('### world map')
	df = data[['host', 'geo_latitude', 'geo_longitude']]
	df = df[df['geo_latitude'].notnull() & df['geo_longitude'].notnull()]
	if df.empty:
		return(False)
	gdf = geopandas.GeoDataFrame(df, geometry=geopandas.points_from_xy(df.geo_longitude, df.geo_latitude))
	world = geopandas.read_file(APP_DATA_DIR / 'countries.geojson')
	ax = world.plot('ISO_A3', figsize=(10,8), alpha=0.8, cmap=mpl.colormaps['cividis'])
	gdf.plot(ax=ax, color='red')
	fig = ax.get_figure()
	fig.savefig(PICTURES_DIR / f'graph_{now}_geomap.png', transparent=True, dpi=300, bbox_inches='tight')
	mpl.pyplot.close(fig)
	return(True)


def analyseCiphers(data):
	debugDisplay()
	availableVersions = [version for version in TLS_VERSIONS if version in data.columns]
	if not availableVersions:
		return(False)
	import matplotlib as mpl
	import seaborn as sns

	PICTURES_DIR.mkdir(parents=True, exist_ok=True)
	cipherSuitesCounts = {version: {} for version in availableVersions}
	for version in availableVersions:
		allCipherSuites = data[version].dropna().tolist()
		for item in allCipherSuites:
			if not isinstance(item, (list, tuple, set)):
				continue
			for cipherSuite in item:
				if cipherSuite in cipherSuitesCounts[version]:
					cipherSuitesCounts[version][cipherSuite] += 1
				else:
					cipherSuitesCounts[version][cipherSuite] = 1
	dfciphers = pd.DataFrame(cipherSuitesCounts)
	if dfciphers.empty:
		return(False)
	dfciphers = dfciphers.fillna(0)
	dfciphers['total'] = dfciphers.sum(axis=1)
	dfciphers = dfciphers.sort_values('total', ascending=False)
	dfciphers = dfciphers.drop(columns='total')
	title = 'Cipher Suite Usage Across SSL/TLS Versions'
	print('### ', title)
	ax = dfciphers.plot(kind='barh', stacked=True, cmap=mpl.colormaps['tab10'], figsize=(10, 8))
	ax.set_title(title)
	ax.tick_params(axis='y', labelsize=6)
	fig = ax.get_figure()
	fig.savefig(PICTURES_DIR / f'graph_{now}_cs_details.png', transparent=True, dpi=300, bbox_inches='tight')
	mpl.pyplot.close(fig)
	title = 'Correlation Matrix of SSL/TLS Version Usage'
	print('### ', title)
	correlation = dfciphers.corr()
	if not correlation.empty:
		fig, ax = mpl.pyplot.subplots(figsize=(10, 8))
		ax = sns.heatmap(correlation, annot=True, cmap=mpl.colormaps['YlOrRd'], fmt=".2f", linewidths=0.5)
		ax.set_title(title)
		fig.savefig(PICTURES_DIR / f'graph_{now}_cs_correlation.png', transparent=True, dpi=300, bbox_inches='tight')
		mpl.pyplot.close(fig)
	title = 'Total Usage of Each SSL/TLS Version'
	print('### ', title)
	tlsUsage = dfciphers.sum()
	if tlsUsage.sum() > 0:
		fig, ax = mpl.pyplot.subplots(figsize=(10, 8))
		ax.pie(tlsUsage, labels=tlsUsage.index, autopct='%1.1f%%', startangle=90)
		ax.axis('equal')
		ax.set_title(title)
		fig.savefig(PICTURES_DIR / f'graph_{now}_cs_usage.png', transparent=True, dpi=300, bbox_inches='tight')
		mpl.pyplot.close(fig)
	return(True)


def computeGraphs(jsonFile=None):
	debugDisplay()
	PICTURES_DIR.mkdir(parents=True, exist_ok=True)
	jsonFile = (
		DATA_DIR / f'{now}_hosts_analyse.json'
		if jsonFile is None
		else Path(jsonFile)
	)
	df = pd.read_json(jsonFile)
	analyseCiphers(df)
	graphGeoMap(df)
	graphByColumn(df, 'live', 'pie', 0)
	graphByColumn(df, 'port80', 'pie', 0)
	graphByColumn(df, 'port443', 'pie', 0)
	graphByColumn(df, 'self-signed', 'pie', 0)
	graphByColumn(df, 'domain_name', 'pie', 4)
	graphByColumn(df, 'geo_country', 'pie', 0)
	graphByColumn(df, 'geo_asn_number', 'pie', 0)
	graphByColumn(df, 'issuer_organization', 'pie', 4)
	graphByColumn(df, 'has_expired', 'pie', 0)
	graphByColumn(df, 'key_size', 'pie', 0)
	graphByColumn(df, 'server', 'pie', 0)


def tlsCartography(
	captureScreenshots=True,
	generateGraphs=True,
	generateXlsx=True,
	inputFile=None,
	dataDir=DATA_DIR,
	runId=None,
	endpointWorkers=4,
	subprocessBudget=16,
	checkpointEvery=25,
	maxEndpoints=None,
):
	global cipherList
	debugDisplay()
	dataDir = Path(dataDir)
	filePrefix = now if runId is None else validateRunId(runId)
	inputFile = (
		DATA_DIR / f'{now}_hosts_list.json'
		if inputFile is None
		else Path(inputFile)
	)
	listIpFile = dataDir / f'{filePrefix}_list_ip.json'
	analysisFile = dataDir / f'{filePrefix}_hosts_analyse.json'
	excelFile = dataDir / f'{filePrefix}_hosts_analyse.xlsx'
	checkpointFile = dataDir / f'{filePrefix}_hosts_analyse.checkpoint.json'
	commandSemaphore = threading.BoundedSemaphore(subprocessBudget)
	if cipherList is None:
		cipherList = getAllCipherSuites(commandSemaphore=commandSemaphore)
	hostList = extractListHosts(inputFile)
	targets = buildListIps(
		hostList,
		destinationFile=listIpFile,
		workers=endpointWorkers,
		maxEndpoints=maxEndpoints,
		commandSemaphore=commandSemaphore,
	)
	output = tlsAnalyse(
		captureScreenshots=captureScreenshots,
		listIpFile=listIpFile,
		destinationFile=analysisFile,
		excelFile=excelFile,
		workers=endpointWorkers,
		commandSemaphore=commandSemaphore,
		checkpointFile=checkpointFile,
		checkpointEvery=checkpointEvery,
		generateXlsx=generateXlsx,
		cipherWorkers=max(1, min(8, subprocessBudget)),
	)
	if generateGraphs:
		computeGraphs(jsonFile=analysisFile)
	return({
		'targets': targets,
		'output': output,
		'files': {
			'list_ip': str(listIpFile),
			'analysis': str(analysisFile),
			'checkpoint': str(checkpointFile),
			'xlsx': str(excelFile) if generateXlsx else None,
		},
	})


def parseArguments(argv=None):
	parser = argparse.ArgumentParser(
		description='Cartographie TLS active des FQDN validés par fqdnCollect.py.',
	)
	parser.add_argument(
		'--authorized-active-scan',
		action='store_true',
		help='confirme que la liste cible est autorisée pour les scans actifs',
	)
	parser.add_argument(
		'--keep-pictures',
		action='store_true',
		help='conserve les graphes et captures générés par les exécutions précédentes',
	)
	parser.add_argument(
		'--skip-screenshots',
		action='store_true',
		help='désactive Selenium et les captures de pages HTTPS',
	)
	parser.add_argument(
		'--skip-graphs',
		action='store_true',
		help='désactive la génération des graphes',
	)
	parser.add_argument(
		'--skip-xlsx',
		action='store_true',
		help='désactive la génération du rapport XLSX',
	)
	parser.add_argument('--input-file', type=Path, help='Fichier hosts_list JSON à analyser')
	parser.add_argument('--output-dir', type=Path, default=DATA_DIR)
	parser.add_argument('--pictures-dir', type=Path, default=PICTURES_DIR)
	parser.add_argument('--run-id', help='Identifiant UTC de l’exécution')
	parser.add_argument('--endpoint-workers', type=int, default=4)
	parser.add_argument('--subprocess-budget', type=int, default=16)
	parser.add_argument('--checkpoint-every', type=int, default=25)
	parser.add_argument('--max-endpoints', type=int)
	parser.add_argument('--netcat-path', type=Path)
	parser.add_argument('--nmap-path', type=Path)
	parser.add_argument('--openssl-path', type=Path)
	parser.add_argument('--debug', action='store_true')
	return(parser.parse_args(argv))


def main(argv=None):
	global cipherList, debug, PICTURES_DIR
	args = parseArguments(argv)
	if not args.authorized_active_scan:
		print(
			'Refus du scan actif : ajoute --authorized-active-scan après avoir vérifié la liste cible.',
			file=sys.stderr,
		)
		return(2)
	for option, value in {
		'--endpoint-workers': args.endpoint_workers,
		'--subprocess-budget': args.subprocess_budget,
		'--checkpoint-every': args.checkpoint_every,
	}.items():
		if value <= 0:
			print(f'Erreur : {option} doit être strictement positif', file=sys.stderr)
			return(2)
	if args.max_endpoints is not None and args.max_endpoints <= 0:
		print('Erreur : --max-endpoints doit être strictement positif', file=sys.stderr)
		return(2)
	debug = args.debug
	try:
		runId = createRunId() if args.run_id is None else validateRunId(args.run_id)
		configureTools(
			netcat=args.netcat_path,
			nmap=args.nmap_path,
			openssl=args.openssl_path,
		)
		PICTURES_DIR = args.pictures_dir
		testTools()
		if not args.keep_pictures:
			removeOldFiles()
		commandSemaphore = threading.BoundedSemaphore(args.subprocess_budget)
		cipherList = getAllCipherSuites(commandSemaphore=commandSemaphore)
		tlsCartography(
			captureScreenshots=not args.skip_screenshots,
			generateGraphs=not args.skip_graphs,
			generateXlsx=not args.skip_xlsx,
			inputFile=args.input_file,
			dataDir=args.output_dir,
			runId=runId,
			endpointWorkers=args.endpoint_workers,
			subprocessBudget=args.subprocess_budget,
			checkpointEvery=args.checkpoint_every,
			maxEndpoints=args.max_endpoints,
		)
	except (ImportError, OSError, RuntimeError, ValueError) as error:
		print(f'Erreur : {error}', file=sys.stderr)
		return(1)
	return(0)


if __name__ == "__main__":
	sys.exit(main())
