#!/usr/bin/env python3

import argparse
import inspect
import ipaddress
import json
import math
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from urllib.parse import quote, urlsplit

import dns.exception
import dns.resolver
import requests
import tldextract
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from asmiraCommon import atomicWriteJson, createRunId, utcNow, validateRunId


BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / 'data'
TXTDNS_DIR = DATA_DIR / 'txtdns'
DEFAULT_HOSTS = ('example.com',)
DEFAULT_SOURCES = ('shodan-ctl', 'subfinder', 'shodan-dns', 'certspotter')
AVAILABLE_SOURCES = DEFAULT_SOURCES + ('amass',)
DEFAULT_SOURCE_TIMEOUT = 600
DEFAULT_DNS_TIMEOUT = 4
DEFAULT_COLLECTOR_WORKERS = 4
DEFAULT_DNS_WORKERS = 20
DEFAULT_WILDCARD_SAMPLES = 2
DEFAULT_MAX_PAGES = 1000
DEFAULT_SUBFINDER_PATH = shutil.which('subfinder')
DEFAULT_AMASS_PATH = shutil.which('amass')
HOST_LABEL_PATTERN = re.compile(r'^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$')
DOMAIN_EXTRACTOR = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None)
SHODAN_CTL_URL = 'https://ctl.shodan.io/api/v1/domain/{domain}/hostnames'
SHODAN_DNS_URL = 'https://api.shodan.io/dns/domain/{domain}'
CERTSPOTTER_URL = 'https://api.certspotter.com/v1/issuances'
SECRET_ENV_NAMES = ('SHODAN_API_KEY', 'CERTSPOTTER_API_KEY')

debug = False
now = datetime.now().date().strftime('%Y%m%d')


@dataclass
class Finding:
	name: str
	domain: str
	source: str
	wildcardPattern: bool = False
	evidence: dict = field(default_factory=dict)


class Collector:
	name = 'collector'

	def availability(self):
		return(True, None)

	def collect(self, domain):
		raise NotImplementedError


def debugDisplay():
	if debug:
		frame = inspect.currentframe()
		caller = frame.f_back if frame else None
		if caller:
			print(f'[debug] Function {caller.f_code.co_name}')


def redactSecrets(value):
	message = str(value)
	for variableName in SECRET_ENV_NAMES:
		secret = os.environ.get(variableName)
		if secret:
			message = message.replace(secret, '[REDACTED]')
	message = re.sub(
		r'([?&](?:key|api_key|token)=)[^&\s]+',
		r'\1[REDACTED]',
		message,
		flags=re.IGNORECASE,
	)
	return(message)


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
	if not hostname:
		raise ValueError(f'Nom d’hôte invalide : {host!r}')

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

	if len(hostname) > 253:
		raise ValueError(f'Nom d’hôte trop long : {host!r}')

	labels = hostname.split('.')
	if len(labels) < 2 or any(not HOST_LABEL_PATTERN.fullmatch(label) for label in labels):
		raise ValueError(f'Nom d’hôte invalide : {host!r}')

	return(hostname)


def normalizeDiscoveredName(name):
	debugDisplay()
	if not isinstance(name, str):
		raise TypeError('Un nom découvert doit être fourni sous forme de chaîne')
	value = name.strip()
	wildcardPattern = value.startswith('*.')
	if wildcardPattern:
		value = value[2:]
	hostname = normalizeHost(value)
	return(f'*.{hostname}' if wildcardPattern else hostname, wildcardPattern)


def extractDomain(host):
	debugDisplay()
	hostname = normalizeHost(host)
	extracted = DOMAIN_EXTRACTOR(hostname)
	domain = extracted.top_domain_under_public_suffix
	if not domain:
		raise ValueError(f'Suffixe public inconnu pour {host!r}')
	return(domain)


def extractHostFromRow(row):
	if isinstance(row, str):
		return(row)
	if isinstance(row, (bytes, bytearray)):
		raise TypeError('Un hôte ne peut pas être fourni sous forme binaire')
	try:
		host = row[0]
	except (IndexError, KeyError, TypeError) as error:
		raise TypeError(f'Ligne d’hôte invalide : {row!r}') from error
	if not isinstance(host, str):
		raise TypeError(f'La première colonne doit contenir un hôte : {row!r}')
	return(host)


def hostBelongsToDomain(host, domain):
	return(host == domain or host.endswith(f'.{domain}'))


def findingBelongsToDomain(name, domain):
	host = name[2:] if name.startswith('*.') else name
	return(hostBelongsToDomain(host, domain))


def createFinding(name, domain, source, evidence=None):
	normalizedName, wildcardPattern = normalizeDiscoveredName(name)
	if not findingBelongsToDomain(normalizedName, domain):
		raise ValueError(f'{normalizedName!r} est hors du périmètre {domain!r}')
	return(Finding(
		name=normalizedName,
		domain=domain,
		source=source,
		wildcardPattern=wildcardPattern,
		evidence={} if evidence is None else evidence,
	))


def createHttpSession():
	debugDisplay()
	retry = Retry(
		total=3,
		connect=3,
		read=3,
		status=3,
		backoff_factor=1,
		status_forcelist=(429, 500, 502, 503, 504),
		allowed_methods=frozenset({'GET'}),
		respect_retry_after_header=True,
	)
	adapter = HTTPAdapter(max_retries=retry)
	session = requests.Session()
	session.headers.update({'User-Agent': 'fqdnCollect/2'})
	session.mount('https://', adapter)
	return(session)


def appendFinding(findings, name, domain, source, evidence=None):
	try:
		findings.append(createFinding(name, domain, source, evidence=evidence))
	except (TypeError, ValueError) as error:
		print(f'[avertissement] {source}: résultat ignoré ({error})', file=sys.stderr)


class ShodanCtlCollector(Collector):
	name = 'shodan-ctl'

	def __init__(self, session=None, timeout=DEFAULT_SOURCE_TIMEOUT):
		self.session = createHttpSession() if session is None else session
		self.timeout = min(timeout, 60)

	def collect(self, domain):
		url = SHODAN_CTL_URL.format(domain=quote(domain, safe=''))
		response = self.session.get(url, timeout=(5, self.timeout))
		response.raise_for_status()
		payload = response.json()
		if not isinstance(payload, list):
			raise ValueError('Réponse Shodan CTL invalide : une liste JSON était attendue')

		findings = []
		for name in payload:
			appendFinding(findings, name, domain, self.name)
		return(findings)


class SubfinderCollector(Collector):
	name = 'subfinder'

	def __init__(self, path=DEFAULT_SUBFINDER_PATH, timeout=DEFAULT_SOURCE_TIMEOUT, workDir=TXTDNS_DIR):
		self.path = Path(path) if path else None
		self.timeout = timeout
		self.workDir = Path(workDir)

	def availability(self):
		if self.path is None:
			return(False, 'exécutable subfinder absent')
		if not self.path.is_file() or not os.access(self.path, os.X_OK):
			return(False, f'exécutable subfinder indisponible : {self.path}')
		return(True, None)

	def collect(self, domain):
		self.workDir.mkdir(parents=True, exist_ok=True)
		fileDescriptor, temporaryName = tempfile.mkstemp(
			dir=self.workDir,
			prefix=f'.subfinder_{domain.replace(".", "_")}_',
			suffix='.jsonl',
		)
		os.close(fileDescriptor)
		outputFile = Path(temporaryName)
		outputFile.unlink(missing_ok=True)
		maxTimeMinutes = max(1, math.ceil(self.timeout / 60))
		cmd = [
			str(self.path),
			'-d', domain,
			'-all',
			'-oJ',
			'-cs',
			'-silent',
			'-max-time', str(maxTimeMinutes),
			'-o', str(outputFile),
		]

		try:
			try:
				completed = subprocess.run(
					cmd,
					stdout=subprocess.DEVNULL,
					stderr=subprocess.PIPE,
					text=True,
					timeout=self.timeout + 30,
					check=False,
				)
			except subprocess.TimeoutExpired as error:
				raise RuntimeError(f'Subfinder a dépassé le délai de {self.timeout + 30} s') from error
			if completed.returncode != 0:
				message = completed.stderr.strip() or 'aucun détail disponible'
				raise RuntimeError(f'Subfinder a échoué avec le code {completed.returncode}: {message}')

			findings = []
			if not outputFile.exists():
				return(findings)
			with outputFile.open('r', encoding='utf-8', errors='replace') as fileHandle:
				for lineNumber, line in enumerate(fileHandle, start=1):
					if not line.strip():
						continue
					try:
						record = json.loads(line)
					except json.JSONDecodeError as error:
						print(
							f'[avertissement] subfinder: JSONL invalide ligne {lineNumber} ({error})',
							file=sys.stderr,
						)
						continue
					host = record.get('host')
					sources = record.get('sources') or record.get('source') or [self.name]
					if isinstance(sources, str):
						sources = [sources]
					if not isinstance(sources, list):
						sources = [self.name]
					for source in sorted(set(sources)):
						appendFinding(findings, host, domain, f'subfinder:{source}')
			return(findings)
		finally:
			outputFile.unlink(missing_ok=True)


class ShodanDnsCollector(Collector):
	name = 'shodan-dns'

	def __init__(
		self,
		apiKey=None,
		session=None,
		timeout=DEFAULT_SOURCE_TIMEOUT,
		history=True,
		maxPages=DEFAULT_MAX_PAGES,
	):
		self.apiKey = apiKey
		self.session = createHttpSession() if session is None else session
		self.timeout = min(timeout, 60)
		self.history = history
		self.maxPages = maxPages

	def availability(self):
		if not self.apiKey:
			return(False, 'variable SHODAN_API_KEY absente')
		return(True, None)

	def expandSubdomain(self, subdomain, domain):
		if not isinstance(subdomain, str):
			raise TypeError('Sous-domaine Shodan invalide')
		subdomain = subdomain.strip().rstrip('.')
		if not subdomain:
			return(domain)
		concrete = subdomain[2:] if subdomain.startswith('*.') else subdomain
		if hostBelongsToDomain(concrete.lower(), domain):
			return(subdomain)
		return(f'{subdomain}.{domain}')

	def collect(self, domain):
		findings = []
		url = SHODAN_DNS_URL.format(domain=quote(domain, safe=''))
		for page in range(1, self.maxPages + 1):
			response = self.session.get(
				url,
				params={
					'key': self.apiKey,
					'history': str(self.history).lower(),
					'page': page,
				},
				timeout=(5, self.timeout),
			)
			response.raise_for_status()
			payload = response.json()
			if not isinstance(payload, dict):
				raise ValueError('Réponse Shodan DNS invalide')

			for record in payload.get('data', []):
				if not isinstance(record, dict):
					continue
				name = self.expandSubdomain(record.get('subdomain', ''), domain)
				evidence = {
					'record_type': record.get('type'),
					'value': record.get('value'),
					'last_seen': record.get('last_seen'),
					'ttl': record.get('ttl'),
				}
				appendFinding(findings, name, domain, self.name, evidence=evidence)

			for subdomain in payload.get('subdomains', []):
				name = self.expandSubdomain(subdomain, domain)
				appendFinding(findings, name, domain, self.name)

			if not payload.get('more'):
				break
		else:
			print(
				f'[avertissement] shodan-dns: limite de {self.maxPages} pages atteinte pour {domain}',
				file=sys.stderr,
			)
		return(findings)


class CertSpotterCollector(Collector):
	name = 'certspotter'

	def __init__(
		self,
		apiKey=None,
		session=None,
		timeout=DEFAULT_SOURCE_TIMEOUT,
		maxPages=DEFAULT_MAX_PAGES,
	):
		self.apiKey = apiKey
		self.session = createHttpSession() if session is None else session
		self.timeout = min(timeout, 60)
		self.maxPages = maxPages

	def collect(self, domain):
		findings = []
		after = None
		headers = {'Authorization': f'Bearer {self.apiKey}'} if self.apiKey else {}
		for page in range(1, self.maxPages + 1):
			params = [
				('domain', domain),
				('include_subdomains', 'true'),
				('expand', 'dns_names'),
			]
			if after is not None:
				params.append(('after', after))
			response = self.session.get(
				CERTSPOTTER_URL,
				params=params,
				headers=headers,
				timeout=(5, self.timeout),
			)
			response.raise_for_status()
			payload = response.json()
			if not isinstance(payload, list):
				raise ValueError('Réponse Cert Spotter invalide')
			if not payload:
				break

			for issuance in payload:
				if not isinstance(issuance, dict):
					continue
				evidence = {
					'issuance_id': issuance.get('id'),
					'not_before': issuance.get('not_before'),
					'not_after': issuance.get('not_after'),
					'cert_sha256': issuance.get('cert_sha256'),
				}
				for name in issuance.get('dns_names') or []:
					appendFinding(findings, name, domain, self.name, evidence=evidence)

			nextAfter = payload[-1].get('id') if isinstance(payload[-1], dict) else None
			if not nextAfter or nextAfter == after:
				raise ValueError('Pagination Cert Spotter invalide : identifiant after absent ou répété')
			after = nextAfter
		else:
			print(
				f'[avertissement] certspotter: limite de {self.maxPages} pages atteinte pour {domain}',
				file=sys.stderr,
			)
		return(findings)


class AmassCollector(Collector):
	name = 'amass'

	def __init__(self, path=DEFAULT_AMASS_PATH, timeout=DEFAULT_SOURCE_TIMEOUT, workDir=TXTDNS_DIR):
		self.path = Path(path) if path else None
		self.timeout = timeout
		self.workDir = Path(workDir)

	def availability(self):
		if self.path is None:
			return(False, 'exécutable Amass absent')
		if not self.path.is_file() or not os.access(self.path, os.X_OK):
			return(False, f'exécutable Amass indisponible : {self.path}')
		return(True, None)

	def collect(self, domain):
		self.workDir.mkdir(parents=True, exist_ok=True)
		with tempfile.TemporaryDirectory(
			dir=self.workDir,
			prefix=f'.amass_{domain.replace(".", "_")}_',
		) as temporaryName:
			amassDir = Path(temporaryName)
			outputFile = amassDir / 'names.txt'
			timeoutMinutes = max(1, math.ceil(self.timeout / 60))
			enumCommand = [
				str(self.path),
				'enum',
				'-active',
				'-brute',
				'-d', domain,
				'-dir', str(amassDir),
				'-timeout', str(timeoutMinutes),
				'-silent',
			]
			try:
				completed = subprocess.run(
					enumCommand,
					stdout=subprocess.DEVNULL,
					stderr=subprocess.PIPE,
					text=True,
					timeout=self.timeout + 30,
					check=False,
				)
			except subprocess.TimeoutExpired as error:
				raise RuntimeError(f'Amass a dépassé le délai de {self.timeout + 30} s') from error
			if completed.returncode != 0:
				message = completed.stderr.strip() or 'aucun détail disponible'
				raise RuntimeError(f'Amass a échoué avec le code {completed.returncode}: {message}')

			subsCommand = [
				str(self.path),
				'subs',
				'-names',
				'-d', domain,
				'-dir', str(amassDir),
				'-o', str(outputFile),
				'-nocolor',
			]
			completed = subprocess.run(
				subsCommand,
				stdout=subprocess.DEVNULL,
				stderr=subprocess.PIPE,
				text=True,
				timeout=min(self.timeout, 60),
				check=False,
			)
			if completed.returncode != 0:
				message = completed.stderr.strip() or 'aucun détail disponible'
				raise RuntimeError(
					f'Extraction des résultats Amass échouée avec le code '
					f'{completed.returncode}: {message}'
				)

			findings = []
			if not outputFile.exists():
				return(findings)
			with outputFile.open('r', encoding='utf-8', errors='replace') as fileHandle:
				for line in fileHandle:
					if line.strip():
						appendFinding(findings, line.strip(), domain, self.name)
			return(findings)


def runCollector(collector, domain):
	debugDisplay()
	started = time.monotonic()
	available, reason = collector.availability()
	if not available:
		return([], {
			'source': collector.name,
			'domain': domain,
			'status': 'skipped',
			'count': 0,
			'error': reason,
			'duration_seconds': round(time.monotonic() - started, 3),
		})
	try:
		findings = collector.collect(domain)
	except Exception as error:
		return([], {
			'source': collector.name,
			'domain': domain,
			'status': 'failed',
			'count': 0,
			'error': redactSecrets(error),
			'duration_seconds': round(time.monotonic() - started, 3),
		})
	return(findings, {
		'source': collector.name,
		'domain': domain,
		'status': 'success',
		'count': len(findings),
		'error': None,
		'duration_seconds': round(time.monotonic() - started, 3),
	})


def collectFindings(domains, collectors, workers=DEFAULT_COLLECTOR_WORKERS):
	debugDisplay()
	findings = [createFinding(domain, domain, 'seed') for domain in domains]
	reports = []
	tasks = [(collector, domain) for domain in domains for collector in collectors]
	if not tasks:
		return(findings, reports)

	with ThreadPoolExecutor(max_workers=min(workers, len(tasks))) as executor:
		futureMap = {
			executor.submit(runCollector, collector, domain): (collector.name, domain)
			for collector, domain in tasks
		}
		for future in as_completed(futureMap):
			collected, report = future.result()
			findings.extend(collected)
			reports.append(report)
			if report['status'] != 'success':
				print(
					f'[avertissement] {report["source"]} ({report["domain"]}): {report["error"]}',
					file=sys.stderr,
				)
	return(
		findings,
		sorted(reports, key=lambda item: (item['domain'], item['source'])),
	)


def buildCandidateRecords(findings, collectedAt=None):
	debugDisplay()
	collectedAt = utcNow() if collectedAt is None else collectedAt
	records = {}
	evidenceKeys = {}
	for finding in findings:
		key = (finding.domain, finding.name, finding.wildcardPattern)
		if key not in records:
			records[key] = {
				'name': finding.name,
				'domain': finding.domain,
				'wildcard_pattern': finding.wildcardPattern,
				'sources': set(),
				'evidence': [],
				'collected_at': collectedAt,
			}
			evidenceKeys[key] = set()
		record = records[key]
		record['sources'].add(finding.source)
		evidence = {'source': finding.source}
		evidence.update(finding.evidence)
		evidenceKey = json.dumps(evidence, ensure_ascii=False, sort_keys=True, default=str)
		if evidenceKey not in evidenceKeys[key]:
			record['evidence'].append(evidence)
			evidenceKeys[key].add(evidenceKey)

	output = []
	for record in records.values():
		record['sources'] = sorted(record['sources'])
		record['evidence'] = sorted(
			record['evidence'],
			key=lambda item: json.dumps(item, ensure_ascii=False, sort_keys=True, default=str),
		)
		output.append(record)
	return(sorted(output, key=lambda item: (item['domain'], item['name'], item['wildcard_pattern'])))


class DnsValidator:
	def __init__(self, resolver=None, timeout=DEFAULT_DNS_TIMEOUT):
		self.resolver = dns.resolver.Resolver(configure=True) if resolver is None else resolver
		if resolver is None:
			self.resolver.timeout = timeout
			self.resolver.lifetime = timeout

	def resolveHost(self, host):
		host = normalizeHost(host)
		records = {'A': [], 'AAAA': [], 'CNAME': []}
		ttl = {}
		errors = {}
		for recordType in records:
			try:
				answer = self.resolver.resolve(host, recordType, raise_on_no_answer=False)
			except dns.resolver.NXDOMAIN:
				return({
					'status': 'NXDOMAIN',
					'resolvable': False,
					'records': records,
					'ttl': ttl,
					'errors': errors,
				})
			except dns.resolver.NoAnswer:
				continue
			except dns.resolver.NoNameservers as error:
				errors[recordType] = f'NoNameservers: {error}'
				continue
			except dns.exception.Timeout as error:
				errors[recordType] = f'Timeout: {error}'
				continue
			except dns.exception.DNSException as error:
				errors[recordType] = f'{type(error).__name__}: {error}'
				continue

			if answer.rrset is not None:
				ttl[recordType] = answer.rrset.ttl
				records[recordType].extend(str(item).rstrip('.').lower() for item in answer)
			canonicalName = getattr(answer, 'canonical_name', None)
			if canonicalName:
				canonicalName = str(canonicalName).rstrip('.').lower()
				if canonicalName and canonicalName != host:
					records['CNAME'].append(canonicalName)

		for recordType in records:
			records[recordType] = sorted(set(records[recordType]))
		resolvable = any(records.values())
		if resolvable:
			status = 'NOERROR'
		elif errors:
			status = 'ERROR'
		else:
			status = 'NOERROR'
		return({
			'status': status,
			'resolvable': resolvable,
			'records': records,
			'ttl': ttl,
			'errors': errors,
		})


def dnsSignature(dnsResult):
	return({
		(recordType, value)
		for recordType, values in dnsResult['records'].items()
		for value in values
	})


def getParentZones(host, domain):
	debugDisplay()
	if host == domain:
		return([])
	hostLabels = host.split('.')
	domainLabels = domain.split('.')
	extraLabels = len(hostLabels) - len(domainLabels)
	return([
		'.'.join(hostLabels[index:])
		for index in range(1, extraLabels + 1)
	])


def getWildcardZones(candidateRecords):
	debugDisplay()
	zones = set()
	for record in candidateRecords:
		if record['wildcard_pattern']:
			zones.add(record['name'][2:])
			continue
		zones.update(getParentZones(record['name'], record['domain']))
	return(sorted(zones))


def detectWildcardZone(zone, dnsValidator, samples=DEFAULT_WILDCARD_SAMPLES, labelFactory=None):
	debugDisplay()
	labelFactory = (lambda: f'fqdncollect-{uuid.uuid4().hex}') if labelFactory is None else labelFactory
	sampleResults = []
	for unused in range(samples):
		host = f'{labelFactory()}.{zone}'
		result = dnsValidator.resolveHost(host)
		sampleResults.append(result)

	resolvedResults = [result for result in sampleResults if result['resolvable']]
	detected = len(resolvedResults) == samples
	signatures = [dnsSignature(result) for result in resolvedResults]
	stable = detected and bool(signatures) and all(signature == signatures[0] for signature in signatures[1:])
	answers = sorted({f'{recordType}:{value}' for signature in signatures for recordType, value in signature})
	return({
		'zone': zone,
		'detected': detected,
		'stable': stable,
		'answers': answers,
		'samples': samples,
	})


def resolveCandidateHosts(
	candidateRecords,
	dnsValidator=None,
	workers=DEFAULT_DNS_WORKERS,
	wildcardSamples=DEFAULT_WILDCARD_SAMPLES,
):
	debugDisplay()
	dnsValidator = DnsValidator() if dnsValidator is None else dnsValidator
	explicitRecords = [record for record in candidateRecords if not record['wildcard_pattern']]
	dnsResults = {}
	if explicitRecords:
		with ThreadPoolExecutor(max_workers=min(workers, len(explicitRecords))) as executor:
			futureMap = {
				executor.submit(dnsValidator.resolveHost, record['name']): record['name']
				for record in explicitRecords
			}
			for future in as_completed(futureMap):
				host = futureMap[future]
				try:
					dnsResults[host] = future.result()
				except Exception as error:
					dnsResults[host] = {
						'status': 'ERROR',
						'resolvable': False,
						'records': {'A': [], 'AAAA': [], 'CNAME': []},
						'ttl': {},
						'errors': {'resolver': f'{type(error).__name__}: {error}'},
					}

	wildcardReports = {}
	for zone in getWildcardZones(candidateRecords):
		try:
			wildcardReports[zone] = detectWildcardZone(
				zone,
				dnsValidator,
				samples=wildcardSamples,
			)
		except Exception as error:
			wildcardReports[zone] = {
				'zone': zone,
				'detected': False,
				'stable': False,
				'answers': [],
				'samples': wildcardSamples,
				'error': f'{type(error).__name__}: {error}',
			}

	wildcardPatternsByDomain = {}
	for record in candidateRecords:
		if record['wildcard_pattern']:
			wildcardPatternsByDomain.setdefault(record['domain'], []).append(record['name'])

	inventory = []
	for record in explicitRecords:
		dnsResult = dnsResults[record['name']]
		hostSignature = dnsSignature(dnsResult)
		matchingZones = []
		wildcardZones = []
		for zone, wildcardReport in wildcardReports.items():
			if not wildcardReport['detected'] or not record['name'].endswith(f'.{zone}'):
				continue
			wildcardZones.append(zone)
			wildcardSignature = {
				tuple(answer.split(':', 1))
				for answer in wildcardReport['answers']
				if ':' in answer
			}
			if hostSignature and hostSignature.intersection(wildcardSignature):
				matchingZones.append(zone)

		inventoryRecord = dict(record)
		inventoryRecord['dns'] = dnsResult
		inventoryRecord['resolvable'] = dnsResult['resolvable']
		inventoryRecord['dns_wildcard_zone'] = bool(wildcardZones)
		inventoryRecord['dns_wildcard_match'] = bool(matchingZones)
		inventoryRecord['wildcard_zones'] = sorted(wildcardZones)
		inventoryRecord['related_wildcard_patterns'] = sorted(
			wildcardPatternsByDomain.get(record['domain'], [])
		)
		inventory.append(inventoryRecord)

	return(
		sorted(inventory, key=lambda item: (item['domain'], item['name'])),
		[wildcardReports[zone] for zone in sorted(wildcardReports)],
	)


def writeJson(filePath, payload):
	debugDisplay()
	return(atomicWriteJson(filePath, payload))


def writeJsonRecords(filePath, key, values):
	writeJson(filePath, [{key: value} for value in values])


def extractListDomains(hostList, outputFile=None):
	debugDisplay()
	domains = sorted({extractDomain(extractHostFromRow(row)) for row in hostList})
	outputFile = DATA_DIR / f'{now}_domains_list.json' if outputFile is None else Path(outputFile)
	writeJsonRecords(outputFile, 'domain', domains)
	print('\n'.join(domains))
	return(domains)


def buildCollectors(
	sourceNames,
	sourceTimeout=DEFAULT_SOURCE_TIMEOUT,
	maxPages=DEFAULT_MAX_PAGES,
	subfinderPath=DEFAULT_SUBFINDER_PATH,
	amassPath=DEFAULT_AMASS_PATH,
	shodanHistory=True,
	workDir=TXTDNS_DIR,
):
	debugDisplay()
	collectors = []
	for sourceName in sourceNames:
		if sourceName == 'shodan-ctl':
			collectors.append(ShodanCtlCollector(timeout=sourceTimeout))
		elif sourceName == 'subfinder':
			collectors.append(SubfinderCollector(
				path=subfinderPath,
				timeout=sourceTimeout,
				workDir=workDir,
			))
		elif sourceName == 'shodan-dns':
			collectors.append(ShodanDnsCollector(
				apiKey=os.environ.get('SHODAN_API_KEY'),
				timeout=sourceTimeout,
				history=shodanHistory,
				maxPages=maxPages,
			))
		elif sourceName == 'certspotter':
			collectors.append(CertSpotterCollector(
				apiKey=os.environ.get('CERTSPOTTER_API_KEY'),
				timeout=sourceTimeout,
				maxPages=maxPages,
			))
		elif sourceName == 'amass':
			collectors.append(AmassCollector(
				path=amassPath,
				timeout=sourceTimeout,
				workDir=workDir,
			))
		else:
			raise ValueError(f'Source inconnue : {sourceName}')
	return(collectors)


def parseSourceNames(value):
	sourceNames = []
	for sourceName in value.split(','):
		sourceName = sourceName.strip().lower()
		if not sourceName:
			continue
		if sourceName not in AVAILABLE_SOURCES:
			raise ValueError(f'Source inconnue : {sourceName}')
		if sourceName == 'amass':
			raise ValueError('Amass doit être activé avec --enable-amass')
		if sourceName not in sourceNames:
			sourceNames.append(sourceName)
	return(sourceNames)


def hostCartography(
	hostList=None,
	collectors=None,
	dnsValidator=None,
	dataDir=DATA_DIR,
	txtdnsDir=TXTDNS_DIR,
	sourceNames=DEFAULT_SOURCES,
	sourceTimeout=DEFAULT_SOURCE_TIMEOUT,
	maxPages=DEFAULT_MAX_PAGES,
	subfinderPath=DEFAULT_SUBFINDER_PATH,
	amassPath=DEFAULT_AMASS_PATH,
	shodanHistory=True,
	collectorWorkers=DEFAULT_COLLECTOR_WORKERS,
	dnsWorkers=DEFAULT_DNS_WORKERS,
	dnsTimeout=DEFAULT_DNS_TIMEOUT,
	wildcardSamples=DEFAULT_WILDCARD_SAMPLES,
	runId=None,
	collectedAt=None,
	filePrefix=None,
):
	debugDisplay()
	startedAt = utcNow()
	startedMonotonic = time.monotonic()
	hostList = list(DEFAULT_HOSTS if hostList is None else hostList)
	dataDir = Path(dataDir)
	txtdnsDir = Path(txtdnsDir)
	if filePrefix is None:
		filePrefix = now if runId is None else validateRunId(runId)
	else:
		filePrefix = str(filePrefix)
	domainsFile = dataDir / f'{filePrefix}_domains_list.json'
	candidatesFile = dataDir / f'{filePrefix}_hosts_candidates.json'
	inventoryFile = dataDir / f'{filePrefix}_hosts_inventory.json'
	hostsFile = dataDir / f'{filePrefix}_hosts_list.json'
	reportFile = dataDir / f'{filePrefix}_collection_report.json'

	domains = extractListDomains(hostList, outputFile=domainsFile)
	if collectors is None:
		collectors = buildCollectors(
			sourceNames=sourceNames,
			sourceTimeout=sourceTimeout,
			maxPages=maxPages,
			subfinderPath=subfinderPath,
			amassPath=amassPath,
			shodanHistory=shodanHistory,
			workDir=txtdnsDir,
		)

	findings, sourceReports = collectFindings(domains, collectors, workers=collectorWorkers)
	candidateRecords = buildCandidateRecords(findings, collectedAt=collectedAt)
	writeJson(candidatesFile, candidateRecords)

	if dnsValidator is None:
		dnsValidator = DnsValidator(timeout=dnsTimeout)
	inventory, wildcardReports = resolveCandidateHosts(
		candidateRecords,
		dnsValidator=dnsValidator,
		workers=dnsWorkers,
		wildcardSamples=wildcardSamples,
	)
	writeJson(inventoryFile, inventory)

	resolvableHosts = sorted({
		record['name']
		for record in inventory
		if record['resolvable']
	})
	writeJsonRecords(hostsFile, 'host', resolvableHosts)
	finishedAt = utcNow()
	report = {
		'run_id': runId,
		'stage': 'discovery',
		'status': 'success',
		'started_at': startedAt,
		'finished_at': finishedAt,
		'duration_seconds': round(time.monotonic() - startedMonotonic, 3),
		'collected_at': collectedAt or startedAt,
		'domains': domains,
		'sources': sourceReports,
		'wildcard_dns': wildcardReports,
		'counts': {
			'candidates': len(candidateRecords),
			'explicit_candidates': len(inventory),
			'resolvable_hosts': len(resolvableHosts),
		},
	}
	writeJson(reportFile, report)

	print(
		f'Collecte terminée : {len(candidateRecords)} candidat(s), '
		f'{len(inventory)} nom(s) explicite(s), {len(resolvableHosts)} hôte(s) résolvable(s)'
	)
	return({
		'domains': domains,
		'candidates': candidateRecords,
		'inventory': inventory,
		'hosts': resolvableHosts,
		'source_reports': sourceReports,
		'wildcard_reports': wildcardReports,
		'report': report,
		'files': {
			'domains': str(domainsFile),
			'candidates': str(candidatesFile),
			'inventory': str(inventoryFile),
			'hosts': str(hostsFile),
			'report': str(reportFile),
		},
	})


def parseArgs(arguments=None):
	parser = argparse.ArgumentParser(
		description='Découvre des hôtes avec plusieurs sources puis valide leur état DNS.'
	)
	parser.add_argument(
		'hosts',
		nargs='*',
		default=list(DEFAULT_HOSTS),
		help='Noms d’hôtes ou URL autorisés à traiter',
	)
	parser.add_argument(
		'--sources',
		default=','.join(DEFAULT_SOURCES),
		help=f'Sources passives séparées par des virgules (défaut : {",".join(DEFAULT_SOURCES)})',
	)
	parser.add_argument(
		'--enable-amass',
		action='store_true',
		help=(
			'Active Amass et le brute-force sur des cibles explicitement autorisées ; '
			'Amass v5 peut démarrer son moteur local en arrière-plan'
		),
	)
	parser.add_argument(
		'--subfinder-path',
		type=Path,
		default=DEFAULT_SUBFINDER_PATH,
		help='Chemin de l’exécutable Subfinder',
	)
	parser.add_argument(
		'--amass-path',
		type=Path,
		default=DEFAULT_AMASS_PATH,
		help='Chemin de l’exécutable Amass',
	)
	parser.add_argument(
		'--source-timeout',
		type=int,
		default=DEFAULT_SOURCE_TIMEOUT,
		help=f'Délai maximal par collecteur en secondes (défaut : {DEFAULT_SOURCE_TIMEOUT})',
	)
	parser.add_argument(
		'--dns-timeout',
		type=float,
		default=DEFAULT_DNS_TIMEOUT,
		help=f'Délai DNS par requête en secondes (défaut : {DEFAULT_DNS_TIMEOUT})',
	)
	parser.add_argument(
		'--collector-workers',
		type=int,
		default=DEFAULT_COLLECTOR_WORKERS,
		help=f'Collecteurs exécutés en parallèle (défaut : {DEFAULT_COLLECTOR_WORKERS})',
	)
	parser.add_argument(
		'--dns-workers',
		type=int,
		default=DEFAULT_DNS_WORKERS,
		help=f'Résolutions DNS parallèles (défaut : {DEFAULT_DNS_WORKERS})',
	)
	parser.add_argument(
		'--wildcard-samples',
		type=int,
		default=DEFAULT_WILDCARD_SAMPLES,
		help=f'Échantillons aléatoires par zone wildcard (défaut : {DEFAULT_WILDCARD_SAMPLES})',
	)
	parser.add_argument(
		'--max-pages',
		type=int,
		default=DEFAULT_MAX_PAGES,
		help=f'Nombre maximal de pages API par domaine (défaut : {DEFAULT_MAX_PAGES})',
	)
	parser.add_argument(
		'--shodan-history',
		action=argparse.BooleanOptionalAction,
		default=True,
		help='Inclut l’historique DNS Shodan',
	)
	parser.add_argument(
		'--run-id',
		help='Identifiant UTC de l’exécution (généré automatiquement par défaut)',
	)
	parser.add_argument(
		'--output-dir',
		type=Path,
		default=DATA_DIR,
		help=f'Répertoire des rapports (défaut : {DATA_DIR})',
	)
	parser.add_argument('--debug', action='store_true', help='Active les informations de debug')
	return(parser.parse_args(arguments))


def main(arguments=None):
	global debug
	args = parseArgs(arguments)
	debug = args.debug
	numericValues = {
		'--source-timeout': args.source_timeout,
		'--dns-timeout': args.dns_timeout,
		'--collector-workers': args.collector_workers,
		'--dns-workers': args.dns_workers,
		'--wildcard-samples': args.wildcard_samples,
		'--max-pages': args.max_pages,
	}
	for option, value in numericValues.items():
		if value <= 0:
			print(f'[erreur] {option} doit être strictement positif', file=sys.stderr)
			return(2)

	try:
		runId = createRunId() if args.run_id is None else validateRunId(args.run_id)
		sourceNames = parseSourceNames(args.sources)
		if args.enable_amass:
			sourceNames.append('amass')
			print(
				'[avertissement] Amass actif et brute-force sont activés ; '
				'Amass v5 peut démarrer son moteur local sur 127.0.0.1:4000.',
				file=sys.stderr,
			)
		print(f'Cibles : {", ".join(args.hosts)}')
		print(f'Sources : {", ".join(sourceNames)}')
		print(f'Run ID : {runId}')
		hostCartography(
			args.hosts,
			dataDir=args.output_dir,
			txtdnsDir=args.output_dir / 'txtdns',
			sourceNames=sourceNames,
			sourceTimeout=args.source_timeout,
			maxPages=args.max_pages,
			subfinderPath=args.subfinder_path,
			amassPath=args.amass_path,
			shodanHistory=args.shodan_history,
			collectorWorkers=args.collector_workers,
			dnsWorkers=args.dns_workers,
			dnsTimeout=args.dns_timeout,
			wildcardSamples=args.wildcard_samples,
			runId=runId,
			filePrefix=runId if args.run_id is not None else now,
		)
	except (OSError, RuntimeError, TypeError, ValueError) as error:
		print(f'[erreur] {error}', file=sys.stderr)
		return(1)
	return(0)


if __name__ == '__main__':
	sys.exit(main())
