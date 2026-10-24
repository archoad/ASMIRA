#!/usr/bin/env python3

"""Paquet de partage d’un run : les trois exports NDJSON (sans
asmira.raw.endpoints) et le bilan HTML, dans une archive tar.gz chiffrée avec
age pour les entités qui ne peuvent pas scanner elles-mêmes. Une signature
SSH (ssh-keygen -Y) du fichier chiffré en atteste l’origine. Les mêmes
fonctions servent à la sonde (construction, envoi) et à l’import
(asmiraImport.py)."""

import gzip
import hashlib
import io
import json
import shutil
import subprocess
import tarfile
from pathlib import Path


SHARE_FORMAT = 1
SHARE_DATASETS = ('discovery', 'exposure', 'run')
SIGNATURE_NAMESPACE = 'asmira-share'
MANIFEST_NAME = 'manifest.json'
REPORT_NAME = 'report.html'
TOOL_TIMEOUT = 300
# Plafond de lecture d’une archive reçue : bien au-delà d’un run réel
# (~50 Mo décompressés pour 21 domaines), il borne une archive piégée.
MAX_MEMBER_SIZE = 512 * 1024 * 1024


def datasetFileName(dataset):
	return(f'{dataset}.ndjson')


def bundleFileName(runId):
	return(f'asmira_share_{runId}.tar.gz.age')


def shareEvent(event):
	"""Copie de l’événement sans asmira.raw.endpoints : l’état brut des couples
	ne sert qu’à recalculer l’état précédent sur la sonde."""
	raw = event.get('asmira', {}).get('raw')
	if not isinstance(raw, dict) or 'endpoints' not in raw:
		return(event)
	shared = {**event, 'asmira': {**event['asmira'], 'raw': {
		key: value for key, value in raw.items() if key != 'endpoints'
	}}}
	if not shared['asmira']['raw']:
		del shared['asmira']['raw']
	return(shared)


def ndjsonBytes(events):
	return(b''.join(
		json.dumps(event, ensure_ascii=False, separators=(',', ':')).encode('utf-8') + b'\n'
		for event in events
	))


def addMember(archive, name, content):
	info = tarfile.TarInfo(name)
	info.size = len(content)
	info.mode = 0o640
	archive.addfile(info, io.BytesIO(content))


def buildBundle(runId, eventsByDataset, reportHtml=None, createdAt=None):
	"""Archive tar.gz en mémoire : manifest.json (format, run-id, empreinte et
	nombre d’événements de chaque fichier), puis les NDJSON et le bilan."""
	members = {}
	files = {}
	for dataset in SHARE_DATASETS:
		events = eventsByDataset.get(dataset)
		if events is None:
			continue
		content = ndjsonBytes(shareEvent(event) for event in events)
		name = datasetFileName(dataset)
		members[name] = content
		files[name] = {
			'dataset': dataset,
			'events': len(events),
			'sha256': hashlib.sha256(content).hexdigest(),
		}
	if reportHtml is not None:
		content = reportHtml.encode('utf-8')
		members[REPORT_NAME] = content
		files[REPORT_NAME] = {'sha256': hashlib.sha256(content).hexdigest()}
	manifest = {
		'format': SHARE_FORMAT,
		'run_id': runId,
		'created_at': createdAt,
		'files': files,
	}
	buffer = io.BytesIO()
	# mtime fixe : deux constructions identiques donnent la même archive.
	with gzip.GzipFile(fileobj=buffer, mode='wb', mtime=0) as compressed:
		with tarfile.open(fileobj=compressed, mode='w') as archive:
			addMember(archive, MANIFEST_NAME, json.dumps(manifest, ensure_ascii=False, indent=2).encode('utf-8'))
			for name, content in members.items():
				addMember(archive, name, content)
	return(buffer.getvalue())


def readMember(archive, info):
	if not info.isfile():
		raise ValueError(f'Paquet refusé : {info.name} n’est pas un fichier ordinaire')
	if info.size > MAX_MEMBER_SIZE:
		raise ValueError(f'Paquet refusé : {info.name} dépasse {MAX_MEMBER_SIZE} octets')
	return(archive.extractfile(info).read())


def readBundle(data):
	"""Manifeste, événements par dataset et bilan d’une archive déchiffrée.
	Rien n’est écrit sur disque ; un membre inattendu, une empreinte ou un
	nombre d’événements différent du manifeste font refuser le paquet."""
	expected = {MANIFEST_NAME, REPORT_NAME, *(datasetFileName(dataset) for dataset in SHARE_DATASETS)}
	contents = {}
	try:
		with tarfile.open(fileobj=io.BytesIO(data), mode='r:gz') as archive:
			for info in archive:
				if info.name not in expected or info.name in contents:
					raise ValueError(f'Paquet refusé : membre inattendu {info.name!r}')
				contents[info.name] = readMember(archive, info)
	except (tarfile.TarError, OSError, EOFError) as error:
		raise ValueError(f'Paquet illisible : {error}') from error
	if MANIFEST_NAME not in contents:
		raise ValueError('Paquet refusé : manifest.json absent')
	manifest = json.loads(contents.pop(MANIFEST_NAME))
	if manifest.get('format') != SHARE_FORMAT:
		raise ValueError(
			f'Format de paquet {manifest.get("format")!r} non pris en charge '
			f'(attendu : {SHARE_FORMAT}) : mettre ASMIRA à jour'
		)
	files = manifest.get('files') or {}
	if set(files) != set(contents):
		raise ValueError('Paquet refusé : contenu différent du manifeste')
	events = {}
	for name, content in contents.items():
		if hashlib.sha256(content).hexdigest() != files[name].get('sha256'):
			raise ValueError(f'Paquet refusé : empreinte de {name} invalide')
		if name == REPORT_NAME:
			continue
		dataset = files[name].get('dataset')
		records = [json.loads(line) for line in content.decode('utf-8').splitlines() if line.strip()]
		if dataset not in SHARE_DATASETS or len(records) != files[name].get('events'):
			raise ValueError(f'Paquet refusé : {name} ne correspond pas au manifeste')
		for record in records:
			if record.get('asmira', {}).get('run', {}).get('id') != manifest.get('run_id'):
				raise ValueError(f'Paquet refusé : {name} contient un événement d’un autre run')
			if record.get('data_stream', {}).get('dataset') != f'asmira.{dataset}':
				raise ValueError(f'Paquet refusé : {name} contient un événement d’un autre dataset')
		events[dataset] = records
	report = contents.get(REPORT_NAME)
	return(manifest, events, None if report is None else report.decode('utf-8'))


def toolPath(configured, name):
	path = str(configured) if configured else shutil.which(name)
	if not path:
		raise RuntimeError(f'{name} introuvable : l’installer ou renseigner son chemin dans [tools]')
	return(path)


def runTool(command, inputData=None, errorLabel=None):
	try:
		result = subprocess.run(
			command,
			input=inputData,
			capture_output=True,
			timeout=TOOL_TIMEOUT,
			check=False,
		)
	except (OSError, subprocess.TimeoutExpired) as error:
		raise RuntimeError(f'{errorLabel or command[0]} : {error}') from error
	if result.returncode != 0:
		message = result.stderr.decode('utf-8', errors='replace').strip()
		raise RuntimeError(f'{errorLabel or command[0]} : {message or f"code {result.returncode}"}')
	return(result.stdout)


def encryptBundle(data, recipient, agePath=None):
	"""Chiffre pour la clé publique age de la sonde : une seule clé pour tous
	les domaines surveillés, l’accès aux données se gère hors d’ASMIRA."""
	return(runTool(
		[toolPath(agePath, 'age'), '--encrypt', '--recipient', recipient],
		inputData=data,
		errorLabel='Chiffrement age',
	))


def decryptBundle(data, identityFile, agePath=None):
	return(runTool(
		[toolPath(agePath, 'age'), '--decrypt', '--identity', str(identityFile)],
		inputData=data,
		errorLabel='Déchiffrement age',
	))


def signFile(filePath, signingKey, sshKeygenPath=None):
	"""Signature SSH du fichier chiffré, écrite à côté (<fichier>.sig)."""
	runTool(
		[toolPath(sshKeygenPath, 'ssh-keygen'), '-q', '-Y', 'sign', '-f', str(signingKey),
		 '-n', SIGNATURE_NAMESPACE, str(filePath)],
		errorLabel='Signature',
	)
	return(Path(f'{filePath}.sig'))


def verifySignature(data, signatureFile, allowedSigners, sshKeygenPath=None):
	"""Signataire autorisé (principal du fichier allowed_signers) ayant signé
	le fichier chiffré ; lève une erreur si aucun ne correspond."""
	sshKeygen = toolPath(sshKeygenPath, 'ssh-keygen')
	principals = runTool(
		[sshKeygen, '-Y', 'find-principals', '-f', str(allowedSigners), '-s', str(signatureFile)],
		errorLabel='Signature non reconnue',
	).decode('utf-8').split()
	if not principals:
		raise RuntimeError('Signature non reconnue : aucun signataire autorisé')
	runTool(
		[sshKeygen, '-Y', 'verify', '-f', str(allowedSigners), '-I', principals[0],
		 '-n', SIGNATURE_NAMESPACE, '-s', str(signatureFile)],
		inputData=data,
		errorLabel='Signature invalide',
	)
	return(principals[0])


def encodedSize(size):
	"""Taille d’une pièce jointe dans le message : base64 (4 octets pour 3)
	et lignes de 76 caractères. C’est elle que le relais SMTP mesure."""
	encoded = 4 * ((size + 2) // 3)
	return(encoded + 2 * ((encoded + 75) // 76))

