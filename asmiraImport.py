#!/usr/bin/env python3

"""Import d’un paquet de partage ASMIRA (asmira_share_<run-id>.tar.gz.age)
dans l’Elasticsearch d’une entité qui ne scanne pas elle-même. Le paquet est
vérifié (signature), déchiffré (age) et contrôlé (manifeste) en mémoire, puis
ses événements sont écrits dans les data streams logs-asmira.*-default
installés par elastic/setup.py ; les transforms et le dashboard font le reste.
L’import est idempotent : chaque événement garde son event.id comme _id."""

import argparse
import json
import sys
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

import asmiraShare
import elastic.setup as elasticSetup


BULK_ACTIONS = 1000
BULK_BYTES = 8 * 1024 * 1024
# Le run en dernier : sa présence atteste un import complet, qu’un import
# interrompu ne laisse donc pas croire terminé.
IMPORT_ORDER = ('discovery', 'exposure', 'run')


def dataStreamOf(event):
	dataStream = event.get('data_stream') or {}
	return(f'{dataStream.get("type", "logs")}-{dataStream["dataset"]}-{dataStream.get("namespace", "default")}')


def bulkBodies(events):
	"""Corps _bulk successifs : create (obligatoire sur un data stream) avec
	l’event.id comme _id, pour qu’un second import ne duplique rien."""
	lines, size = [], 0
	for event in events:
		action = json.dumps({'create': {'_index': dataStreamOf(event), '_id': event['event']['id']}})
		document = json.dumps(event, ensure_ascii=False, separators=(',', ':'))
		entry = f'{action}\n{document}\n'.encode('utf-8')
		if lines and (len(lines) >= BULK_ACTIONS or size + len(entry) > BULK_BYTES):
			yield(b''.join(lines))
			lines, size = [], 0
		lines.append(entry)
		size += len(entry)
	if lines:
		yield(b''.join(lines))


def postBulk(client, body):
	request = Request(
		f'{client.baseUrl}/_bulk',
		data=body,
		headers={
			'Accept': 'application/json',
			'Authorization': client.authorization,
			'Content-Type': 'application/x-ndjson',
		},
		method='POST',
	)
	try:
		with urlopen(request, context=client.context, timeout=300) as response:
			return(json.loads(response.read()))
	except HTTPError as error:
		raise RuntimeError(f'_bulk : HTTP {error.code}: {error.read().decode(errors="replace")}') from error
	except URLError as error:
		raise RuntimeError(f'_bulk : {error}') from error


def bulkImport(client, events, post=postBulk):
	"""Nombre d’événements créés et déjà présents ; toute autre erreur
	interrompt l’import (le run, importé en dernier, reste alors absent)."""
	created = existing = 0
	for body in bulkBodies(events):
		response = post(client, body)
		for item in response.get('items', []):
			result = item.get('create', {})
			status = result.get('status')
			if status in (200, 201):
				created += 1
			elif status == 409:
				existing += 1
			else:
				reason = (result.get('error') or {}).get('reason', status)
				raise RuntimeError(f'Événement {result.get("_id")} refusé par Elasticsearch : {reason}')
	return(created, existing)


def runAlreadyImported(client, runId):
	response = client.request(
		'POST',
		'logs-asmira.run-*/_count',
		{'query': {'term': {'asmira.run.id': runId}}},
		allowedStatuses=(404,),
	)
	return(bool(response) and response.get('status') != 404 and response.get('count', 0) > 0)


def openBundle(args):
	"""Manifeste, événements et bilan du paquet, après vérification de la
	signature (sauf --allow-unsigned) et déchiffrement."""
	encrypted = args.bundle.read_bytes()
	if args.allow_unsigned:
		signer = None
	else:
		signature = args.signature or Path(f'{args.bundle}.sig')
		if not signature.is_file():
			raise ValueError(f'Signature absente : {signature} (ou --allow-unsigned)')
		signer = asmiraShare.verifySignature(encrypted, signature, args.allowed_signers, args.ssh_keygen)
	data = asmiraShare.decryptBundle(encrypted, args.identity, args.age)
	manifest, events, report = asmiraShare.readBundle(data)
	return(signer, manifest, events, report)


def parseArguments(argv=None):
	parser = argparse.ArgumentParser(
		description='Importe un paquet de partage ASMIRA dans Elasticsearch.',
	)
	parser.add_argument('bundle', type=Path, help='paquet asmira_share_<run-id>.tar.gz.age')
	parser.add_argument('--identity', type=Path, required=True, help='identité age (clé privée) de la sonde')
	parser.add_argument('--allowed-signers', type=Path, help='signataires autorisés (format allowed_signers d’OpenSSH)')
	parser.add_argument('--signature', type=Path, help='signature du paquet (défaut : <paquet>.sig)')
	parser.add_argument('--allow-unsigned', action='store_true', help='accepter un paquet sans signature')
	parser.add_argument('--elasticsearch-url', help='URL Elasticsearch (identifiants : ELASTIC_API_KEY, ou ELASTIC_USERNAME et ELASTIC_PASSWORD)')
	parser.add_argument('--ca-cert', type=Path)
	parser.add_argument('--report', type=Path, help='fichier où écrire le bilan HTML du run')
	parser.add_argument('--dry-run', action='store_true', help='vérifier et lire le paquet sans rien importer')
	parser.add_argument('--force', action='store_true', help='réimporter un run déjà présent')
	parser.add_argument('--age', type=Path, help='chemin de age (défaut : PATH)')
	parser.add_argument('--ssh-keygen', type=Path, help='chemin de ssh-keygen (défaut : PATH)')
	args = parser.parse_args(argv)
	if not args.allow_unsigned and args.allowed_signers is None:
		parser.error('--allowed-signers est requis (ou --allow-unsigned)')
	if not args.dry_run and not args.elasticsearch_url:
		parser.error('--elasticsearch-url est requis (ou --dry-run)')
	return(args)


def main(argv=None, clientFactory=elasticSetup.clientFromEnvironment, post=postBulk):
	args = parseArguments(argv)
	try:
		signer, manifest, events, report = openBundle(args)
		runId = manifest['run_id']
		counts = {dataset: len(events.get(dataset, [])) for dataset in IMPORT_ORDER}
		print(
			f'Paquet du run {runId}'
			+ (f', signé par {signer}' if signer else ', non signé')
			+ ' : ' + ', '.join(f'{count} événement(s) {dataset}' for dataset, count in counts.items())
		)
		if args.report is not None and report is not None:
			args.report.write_text(report, encoding='utf-8')
			print(f'Bilan du run : {args.report}')
		if args.dry_run:
			return(0)
		client = clientFactory(args.elasticsearch_url, 'ELASTIC', args.ca_cert)
		if not args.force and runAlreadyImported(client, runId):
			print(f'Run {runId} déjà importé : rien à faire (--force pour réimporter).')
			return(0)
		for dataset in IMPORT_ORDER:
			if dataset not in events:
				continue
			created, existing = bulkImport(client, events[dataset], post=post)
			print(f'{dataset} : {created} créé(s), {existing} déjà présent(s)')
	except (OSError, RuntimeError, ValueError, KeyError) as error:
		print(f'[erreur] {error}', file=sys.stderr)
		return(1)
	print(f'Run {runId} importé ; les transforms mettent la base courante à jour sous quelques minutes.')
	return(0)


if __name__ == '__main__':
	sys.exit(main())
