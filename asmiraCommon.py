#!/usr/bin/env python3

import configparser
import hashlib
import json
import os
import re
import tempfile
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path


DEFAULT_CONFIG_PATH = Path('/etc/asmira/asmira.conf')
RUN_ID_PATTERN = re.compile(r'^[0-9]{8}T[0-9]{6}Z-[0-9a-f]{8}$')
FORBIDDEN_CONFIG_NAMES = ('api_key', 'apikey', 'password', 'private_key', 'secret', 'token')
# Lu une seule fois à l’import : os.umask() modifie l’état global du processus et
# ne doit pas être appelé depuis les threads de collecte ou d’analyse.
PROCESS_UMASK = os.umask(0)
os.umask(PROCESS_UMASK)


def applyCreationMode(fileDescriptor):
	# mkstemp() force 0600 ; on rétablit le mode d’un open() classique pour que
	# l’UMask du service (0027 → 0640) et les ACL par défaut s’appliquent.
	os.fchmod(fileDescriptor, 0o666 & ~PROCESS_UMASK)


def utcNow():
	return(datetime.now(timezone.utc).isoformat())


def createRunId(current=None):
	current = datetime.now(timezone.utc) if current is None else current.astimezone(timezone.utc)
	return(f'{current.strftime("%Y%m%dT%H%M%SZ")}-{uuid.uuid4().hex[:8]}')


def validateRunId(runId):
	if not isinstance(runId, str) or not RUN_ID_PATTERN.fullmatch(runId):
		raise ValueError(
			'Identifiant d’exécution invalide ; format attendu : '
			'YYYYMMDDTHHMMSSZ-xxxxxxxx'
		)
	return(runId)


def stableId(*values):
	payload = '\0'.join('' if value is None else str(value) for value in values)
	return(hashlib.sha256(payload.encode('utf-8')).hexdigest())


def atomicWriteJson(filePath, payload):
	filePath = Path(filePath)
	filePath.parent.mkdir(parents=True, exist_ok=True)
	fileDescriptor, temporaryName = tempfile.mkstemp(
		dir=filePath.parent,
		prefix=f'.{filePath.name}.',
		suffix='.tmp',
	)
	try:
		applyCreationMode(fileDescriptor)
		with os.fdopen(fileDescriptor, 'w', encoding='utf-8') as fileHandle:
			json.dump(payload, fileHandle, ensure_ascii=False, indent=2)
			fileHandle.write('\n')
			fileHandle.flush()
			os.fsync(fileHandle.fileno())
		os.replace(temporaryName, filePath)
	except Exception:
		try:
			os.close(fileDescriptor)
		except OSError:
			pass
		Path(temporaryName).unlink(missing_ok=True)
		raise
	return(filePath)


def atomicWriteNdjson(filePath, records):
	filePath = Path(filePath)
	filePath.parent.mkdir(parents=True, exist_ok=True)
	fileDescriptor, temporaryName = tempfile.mkstemp(
		dir=filePath.parent,
		prefix=f'.{filePath.name}.',
		suffix='.tmp',
	)
	count = 0
	try:
		applyCreationMode(fileDescriptor)
		with os.fdopen(fileDescriptor, 'w', encoding='utf-8') as fileHandle:
			for record in records:
				fileHandle.write(json.dumps(record, ensure_ascii=False, separators=(',', ':')))
				fileHandle.write('\n')
				count += 1
			fileHandle.flush()
			os.fsync(fileHandle.fileno())
		os.replace(temporaryName, filePath)
	except Exception:
		try:
			os.close(fileDescriptor)
		except OSError:
			pass
		Path(temporaryName).unlink(missing_ok=True)
		raise
	return(count)


def readJson(filePath, default=None):
	filePath = Path(filePath)
	if not filePath.is_file():
		return(default)
	with filePath.open('r', encoding='utf-8') as fileHandle:
		return(json.load(fileHandle))


def splitConfigList(value):
	return([
		item.strip()
		for line in value.splitlines()
		for item in line.split(',')
		if item.strip()
	])


def getPositiveInt(parser, section, name, fallback):
	value = parser.getint(section, name, fallback=fallback)
	if value <= 0:
		raise ValueError(f'[{section}] {name} doit être strictement positif')
	return(value)


def getOptionalPositiveInt(parser, section, name, fallback=None):
	rawValue = parser.get(section, name, fallback='').strip()
	if not rawValue:
		return(fallback)
	value = int(rawValue)
	if value <= 0:
		raise ValueError(f'[{section}] {name} doit être strictement positif')
	return(value)


def validateNoSecrets(parser):
	for section in parser.sections():
		for name, value in parser.items(section):
			normalizedName = name.lower().replace('-', '_')
			if any(fragment in normalizedName for fragment in FORBIDDEN_CONFIG_NAMES):
				raise ValueError(
					f'Le paramètre [{section}] {name} est interdit dans asmira.conf ; '
					'utiliser une variable d’environnement'
				)
			if re.search(r'(?i)(bearer\s+\S+|-----BEGIN [A-Z ]+PRIVATE KEY-----)', value):
				raise ValueError(
					f'Une valeur potentiellement secrète a été détectée dans [{section}] {name}'
				)


@dataclass(frozen=True)
class AsmiraConfig:
	domains: tuple
	sources: tuple
	enableAmass: bool
	collectorWorkers: int
	dnsWorkers: int
	sourceTimeout: int
	dnsTimeout: float
	wildcardSamples: int
	maxPages: int
	shodanHistory: bool
	activeEnabled: bool
	activeAuthorized: bool
	endpointWorkers: int
	subprocessBudget: int
	checkpointEvery: int
	maxEndpoints: int | None
	captureScreenshots: bool
	generateGraphs: bool
	generateXlsx: bool
	runsDir: Path
	exportDir: Path
	picturesDir: Path
	stateDir: Path
	retentionDays: int
	subfinderPath: Path | None
	amassPath: Path | None
	nmapPath: Path | None
	opensslPath: Path | None
	netcatPath: Path | None


def optionalPath(parser, section, name):
	value = parser.get(section, name, fallback='').strip()
	return(Path(value) if value else None)


def loadConfig(filePath=DEFAULT_CONFIG_PATH):
	filePath = Path(filePath)
	parser = configparser.ConfigParser(interpolation=None)
	try:
		with filePath.open('r', encoding='utf-8') as fileHandle:
			parser.read_file(fileHandle)
	except OSError as error:
		raise ValueError(f'Impossible de lire {filePath}: {error}') from error

	validateNoSecrets(parser)
	domains = tuple(splitConfigList(parser.get('targets', 'domains', fallback='')))
	if not domains:
		raise ValueError('[targets] domains doit contenir au moins un domaine autorisé')

	sources = tuple(splitConfigList(
		parser.get(
			'discovery',
			'sources',
			fallback='shodan-ctl,subfinder,shodan-dns,certspotter',
		)
	))
	if not sources:
		raise ValueError('[discovery] sources ne peut pas être vide')

	dnsTimeout = parser.getfloat('discovery', 'dns_timeout', fallback=4.0)
	if dnsTimeout <= 0:
		raise ValueError('[discovery] dns_timeout doit être strictement positif')

	return(AsmiraConfig(
		domains=domains,
		sources=sources,
		enableAmass=parser.getboolean('discovery', 'enable_amass', fallback=False),
		collectorWorkers=getPositiveInt(parser, 'discovery', 'collector_workers', 4),
		dnsWorkers=getPositiveInt(parser, 'discovery', 'dns_workers', 20),
		sourceTimeout=getPositiveInt(parser, 'discovery', 'source_timeout', 600),
		dnsTimeout=dnsTimeout,
		wildcardSamples=getPositiveInt(parser, 'discovery', 'wildcard_samples', 2),
		maxPages=getPositiveInt(parser, 'discovery', 'max_pages', 1000),
		shodanHistory=parser.getboolean('discovery', 'shodan_history', fallback=False),
		activeEnabled=parser.getboolean('active_scan', 'enabled', fallback=False),
		activeAuthorized=parser.getboolean('active_scan', 'authorized', fallback=False),
		endpointWorkers=getPositiveInt(parser, 'active_scan', 'endpoint_workers', 4),
		subprocessBudget=getPositiveInt(parser, 'active_scan', 'subprocess_budget', 16),
		checkpointEvery=getPositiveInt(parser, 'active_scan', 'checkpoint_every', 25),
		maxEndpoints=getOptionalPositiveInt(parser, 'active_scan', 'max_endpoints'),
		captureScreenshots=parser.getboolean('active_scan', 'screenshots', fallback=False),
		generateGraphs=parser.getboolean('active_scan', 'graphs', fallback=False),
		generateXlsx=parser.getboolean('active_scan', 'xlsx', fallback=False),
		runsDir=Path(parser.get('storage', 'runs_dir', fallback='/var/lib/asmira/runs')),
		exportDir=Path(parser.get('storage', 'export_dir', fallback='/var/lib/asmira/export')),
		picturesDir=Path(parser.get('storage', 'pictures_dir', fallback='/var/lib/asmira/pictures')),
		stateDir=Path(parser.get('storage', 'state_dir', fallback='/var/lib/asmira/state')),
		retentionDays=getPositiveInt(parser, 'storage', 'retention_days', 14),
		subfinderPath=optionalPath(parser, 'tools', 'subfinder'),
		amassPath=optionalPath(parser, 'tools', 'amass'),
		nmapPath=optionalPath(parser, 'tools', 'nmap'),
		opensslPath=optionalPath(parser, 'tools', 'openssl'),
		netcatPath=optionalPath(parser, 'tools', 'netcat'),
	))
