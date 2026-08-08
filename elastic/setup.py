#!/usr/bin/env python3

import argparse
import base64
import json
import os
import ssl
import sys
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


BASE_DIR = Path(__file__).resolve().parent
DATA_STREAMS = ('discovery', 'exposure', 'run')
TRANSFORM_UPDATE_FIELDS = (
	'_meta',
	'description',
	'dest',
	'frequency',
	'retention_policy',
	'settings',
	'source',
	'sync',
)


class ApiClient:
	def __init__(self, baseUrl, apiKey=None, username=None, password=None, caCert=None):
		self.baseUrl = baseUrl.rstrip('/')
		self.context = ssl.create_default_context(cafile=str(caCert) if caCert else None)
		if apiKey:
			self.authorization = f'ApiKey {apiKey}'
		elif username is not None and password is not None:
			encoded = base64.b64encode(f'{username}:{password}'.encode()).decode()
			self.authorization = f'Basic {encoded}'
		else:
			raise ValueError('Authentification absente dans les variables d’environnement')

	def request(self, method, path, payload=None, allowedStatuses=()):
		body = None if payload is None else json.dumps(payload).encode('utf-8')
		headers = {
			'Accept': 'application/json',
			'Authorization': self.authorization,
		}
		if body is not None:
			headers['Content-Type'] = 'application/json'
			headers['kbn-xsrf'] = 'asmira-setup'
		request = Request(
			f'{self.baseUrl}/{path.lstrip("/")}',
			data=body,
			headers=headers,
			method=method,
		)
		try:
			with urlopen(request, context=self.context, timeout=60) as response:
				content = response.read()
				return(None if not content else json.loads(content))
		except HTTPError as error:
			content = error.read().decode(errors='replace')
			if error.code in allowedStatuses:
				return({'status': error.code, 'body': content})
			raise RuntimeError(
				f'{method} {path}: HTTP {error.code}: {content}'
			) from error
		except URLError as error:
			raise RuntimeError(f'{method} {path}: {error}') from error


def loadJson(relativePath):
	with (BASE_DIR / relativePath).open('r', encoding='utf-8') as fileHandle:
		return(json.load(fileHandle))


def buildIndexTemplate(dataset, retentionDays):
	return({
		'index_patterns': [f'logs-asmira.{dataset}-*'],
		'priority': 550,
		'data_stream': {},
		'composed_of': ['asmira-mappings'],
		'template': {
			'lifecycle': {
				'data_retention': f'{retentionDays}d',
			},
		},
		'_meta': {
			'description': f'Data stream Asmira {dataset}',
			'managed_by': 'asmira',
		},
	})


def ensureTransform(client, transformId, definition):
	existing = client.request(
		'GET',
		f'_transform/{transformId}',
		allowedStatuses=(404,),
	)
	if existing and existing.get('status') == 404:
		client.request('PUT', f'_transform/{transformId}', definition)
	else:
		updateDefinition = {
			fieldName: definition[fieldName]
			for fieldName in TRANSFORM_UPDATE_FIELDS
			if fieldName in definition
		}
		client.request('POST', f'_transform/{transformId}/_update', updateDefinition)
	client.request(
		'POST',
		f'_transform/{transformId}/_start',
		allowedStatuses=(409,),
	)


def configureElasticsearch(client, retentionDays):
	mappingAsset = loadJson('elasticsearch/asmira-mappings.json')
	client.request(
		'PUT',
		'_component_template/asmira-mappings',
		mappingAsset,
	)
	for dataset in DATA_STREAMS:
		client.request(
			'PUT',
			f'_index_template/asmira-{dataset}',
			buildIndexTemplate(dataset, retentionDays),
		)
		dataStream = f'logs-asmira.{dataset}-default'
		existing = client.request(
			'GET',
			f'_data_stream/{dataStream}',
			allowedStatuses=(404,),
		)
		if existing and existing.get('status') == 404:
			client.request('PUT', f'_data_stream/{dataStream}')
	serverProperties = mappingAsset['template']['mappings']['properties']['server']['properties']
	tlsProperties = (
		mappingAsset['template']['mappings']['properties']['asmira']['properties']
		['exposure']['properties']['tls']['properties']
	)
	pqcFieldNames = (
		'certificate_sha256',
		'certificate_public_key_algorithm_oid',
		'certificate_signature_algorithm_oid',
		'certificate_pqc_algorithms',
		'certificate_pqc_status',
	)
	exposureMapping = {
		'properties': {
			'server': {
				'properties': {
					fieldName: serverProperties[fieldName]
					for fieldName in ('domain', 'registered_domain')
				},
			},
			'asmira': {
				'properties': {
					'exposure': {
						'properties': {
							'tls': {
								'properties': {
									fieldName: tlsProperties[fieldName]
									for fieldName in pqcFieldNames
								},
							},
						},
					},
				},
			},
		},
	}
	client.request(
		'PUT',
		'logs-asmira.exposure-default/_mapping',
		exposureMapping,
	)
	client.request('PUT', '_index_template/asmira-latest', {
		'index_patterns': ['asmira-*-latest'],
		'priority': 550,
		'composed_of': ['asmira-mappings'],
		'_meta': {
			'description': 'Index entity-centric latest Asmira',
			'managed_by': 'asmira',
		},
	})
	exposureLatest = client.request(
		'GET',
		'asmira-exposure-latest',
		allowedStatuses=(404,),
	)
	if exposureLatest and exposureLatest.get('status') == 404:
		client.request('PUT', 'asmira-exposure-latest')
	client.request(
		'PUT',
		'asmira-exposure-latest/_mapping',
		exposureMapping,
	)
	discoveryLatest = client.request(
		'GET',
		'asmira-discovery-latest',
		allowedStatuses=(404,),
	)
	if discoveryLatest and discoveryLatest.get('status') == 404:
		client.request('PUT', 'asmira-discovery-latest')
	ensureTransform(
		client,
		'asmira-exposure-latest',
		loadJson('elasticsearch/asmira-exposure-latest-transform.json'),
	)
	ensureTransform(
		client,
		'asmira-discovery-latest',
		loadJson('elasticsearch/asmira-discovery-latest-transform.json'),
	)
	client.request('POST', '_aliases', {
		'actions': [{
			'add': {
				'index': 'asmira-exposure-latest',
				'alias': 'asmira-exposure-current',
				'filter': {'term': {'asmira.exposure.present': True}},
			},
		}],
	})


def configureKibana(client):
	dataViews = (
		('asmira-exposure-current', 'Asmira — Exposition actuelle'),
		('asmira-discovery-latest', 'Asmira — Découverte actuelle'),
		('logs-asmira.*-*', 'Asmira — Historique'),
	)
	for dataViewId, name in dataViews:
		client.request('POST', 'api/data_views/data_view', {
			'override': True,
			'data_view': {
				'id': dataViewId,
				'name': name,
				'title': dataViewId,
				'timeFieldName': '@timestamp',
				'allowNoIndex': True,
			},
		})
	client.request(
		'PUT',
		'api/dashboards/asmira-global',
		loadJson('kibana/asmira-global-dashboard.json'),
	)


def parseArguments(argv=None):
	parser = argparse.ArgumentParser(
		description='Installe les templates, data streams, transforms et le dashboard Asmira.',
	)
	parser.add_argument('--elasticsearch-url', required=True)
	parser.add_argument('--kibana-url')
	parser.add_argument('--ca-cert', type=Path)
	parser.add_argument('--retention-days', type=int, required=True)
	parser.add_argument('--skip-kibana', action='store_true')
	return(parser.parse_args(argv))


def clientFromEnvironment(baseUrl, prefix, caCert):
	return(ApiClient(
		baseUrl,
		apiKey=os.environ.get(f'{prefix}_API_KEY'),
		username=os.environ.get(f'{prefix}_USERNAME'),
		password=os.environ.get(f'{prefix}_PASSWORD'),
		caCert=caCert,
	))


def main(argv=None):
	args = parseArguments(argv)
	if args.retention_days <= 0:
		print('--retention-days doit être strictement positif', file=sys.stderr)
		return(2)
	try:
		elasticsearch = clientFromEnvironment(
			args.elasticsearch_url,
			'ELASTIC',
			args.ca_cert,
		)
		configureElasticsearch(elasticsearch, args.retention_days)
		if not args.skip_kibana:
			if not args.kibana_url:
				raise ValueError('--kibana-url est requis sans --skip-kibana')
			kibana = clientFromEnvironment(args.kibana_url, 'KIBANA', args.ca_cert)
			configureKibana(kibana)
	except (OSError, RuntimeError, ValueError) as error:
		print(f'[erreur] {error}', file=sys.stderr)
		return(1)
	print('Assets Elasticsearch et Kibana Asmira installés.')
	return(0)


if __name__ == '__main__':
	sys.exit(main())
