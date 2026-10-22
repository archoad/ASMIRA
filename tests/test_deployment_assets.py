import json
from pathlib import Path

import pytest

import asmiraCommon
import elastic.setup as elasticSetup


BASE_DIR = Path(__file__).resolve().parents[1]


def testExampleConfigurationIsValidAndSafe():
	config = asmiraCommon.loadConfig(BASE_DIR / 'config' / 'asmira.conf.example')

	assert config.domains == ('example.org', 'example.net')
	assert config.activeEnabled is True
	assert config.activeAuthorized is False
	assert config.captureScreenshots is False
	assert config.generateGraphs is False
	assert config.generateXlsx is False


def testSystemdTimerRunsMondayEveningInParis():
	timer = (BASE_DIR / 'deploy' / 'systemd' / 'asmira.timer').read_text()

	assert 'OnCalendar=Mon *-*-* 20:00:00 Europe/Paris' in timer
	assert 'RandomizedDelaySec=30m' in timer
	assert 'Persistent=true' in timer


def testDeploymentGuideIsOptionalAndSystemdUsesPublicDocumentation():
	installScript = (BASE_DIR / 'deploy' / 'install.sh').read_text()
	service = (BASE_DIR / 'deploy' / 'systemd' / 'asmira.service').read_text()

	assert 'if [ -f "$SOURCE_DIR/DEPLOYMENT.md" ]; then' in installScript
	assert 'Documentation=https://github.com/archoad/ASMIRA#readme' in service
	assert 'Documentation=file:///opt/asmira/DEPLOYMENT.md' not in service


def testElasticJsonAssetsAreValidAndDashboardIsGlobal():
	jsonFiles = sorted((BASE_DIR / 'elastic').glob('**/*.json'))

	assert len(jsonFiles) >= 4
	payloads = {
		filePath.name: json.loads(filePath.read_text())
		for filePath in jsonFiles
	}
	dashboard = payloads['asmira-global-dashboard.json']
	fqdnTransform = payloads['asmira-fqdn-latest-transform.json']
	assert fqdnTransform['latest']['unique_key'] == ['server.domain']
	assert fqdnTransform['dest']['index'] == 'asmira-fqdn-latest'
	assert 'retention_policy' not in fqdnTransform
	assert dashboard['title'] == '[archoad] Asmira — Surface d’exposition globale'
	assert len(dashboard['panels']) == 50
	controls = dashboard['pinned_panels']
	assert [control['config']['title'] for control in controls] == ['Domaine', 'FQDN']
	assert [control['config']['field_name'] for control in controls] == [
		'server.registered_domain',
		'server.domain',
	]
	assert all(control['type'] == 'options_list_control' for control in controls)
	assert all(
		control['config']['data_view_id'] == 'asmira-exposure-current'
		for control in controls
	)
	dashboardContent = json.dumps(dashboard)
	assert 'server.domain' in dashboardContent
	assert 'server.registered_domain' in dashboardContent
	assert 'host.name' not in dashboardContent
	assert {
		panel['config'].get('title')
		for panel in dashboard['panels']
		if panel['config'].get('title')
	} >= {
		'Versions TLS supportées',
		'Certificats expirés ou proches de l’expiration',
		'Changements observés sur la période',
		'Statut PQC des certificats TLS par FQDN',
		'Suites cryptographiques TLS négociées',
		'Changements récents de certificat ou de statut PQC',
		'Santé du dernier run',
		'État DNS des candidats',
		'Résolution DNS des candidats',
		'Motifs wildcard conservés',
		'Sources des candidats',
		'Notes TLS des FQDN',
		'Notes TLS par domaine',
		'Évolution des notes TLS',
		'FQDN à corriger',
		'Constats les plus fréquents',
		'Évolutions de note',
		'Durée de vie des certificats',
		'Autorités de certification',
		'CAA des FQDN',
		'FQDN avec et sans CAA par domaine',
		'CAA et certificat actuel',
		'Échange de clés post-quantique (ML-KEM)',
		'Échange de clés post-quantique par domaine',
		'Groupes d’échange de clés négociés',
		'Constats corrigés et nouveaux par run',
		'Constats ouverts les plus anciens',
		'Corrections récentes',
		'Ports ouverts',
		'Chiffrement des services exposés',
		'Services exposés sans chiffrement',
		'Approche hybride post-quantique (ANSSI)',
		'Groupes ML-KEM acceptés',
	}
	assert not {
		'Erreurs récentes de cartographie',
		'État du port HTTPS',
		'État des scans d’endpoints',
	} & {
		panel['config'].get('title')
		for panel in dashboard['panels']
	}
	markdownPanels = [
		panel
		for panel in dashboard['panels']
		if panel['type'] == 'markdown'
	]
	assert len(markdownPanels) == 8
	markdownContent = '\n'.join(
		panel['config']['content']
		for panel in markdownPanels
	)
	for heading in (
		'Synthèse',
		'Conformité TLS et corrections',
		'Certificats et ACME',
		'Cryptographie et PQC',
		'Surface d’exposition',
		'Santé du pipeline',
		'Découverte DNS',
		'Graphe des domaines',
	):
		assert heading in markdownContent
	xyPanels = [
		panel
		for panel in dashboard['panels']
		if panel['config'].get('type') == 'xy'
	]
	assert xyPanels
	assert all(
		panel['config']['axis']['x']['title']['visible'] is False
		and panel['config']['axis']['y']['title']['visible'] is False
		for panel in xyPanels
	)
	mappings = payloads['asmira-mappings.json']['template']['mappings']['properties']
	assert mappings['server']['properties']['domain']['type'] == 'keyword'
	assert mappings['server']['properties']['registered_domain']['type'] == 'keyword'
	tlsMappings = (
		mappings['asmira']['properties']['exposure']['properties']['tls']['properties']
	)
	for fieldName in (
		'certificate_sha256',
		'certificate_public_key_algorithm_oid',
		'certificate_signature_algorithm_oid',
		'certificate_pqc_algorithms',
		'certificate_pqc_status',
		'previous_certificate_sha256',
		'previous_certificate_pqc_status',
	):
		assert tlsMappings[fieldName]['type'] == 'keyword'
	assert tlsMappings['certificate_changed']['type'] == 'boolean'
	assert tlsMappings['pqc_status_changed']['type'] == 'boolean'
	runCountMappings = (
		mappings['asmira']['properties']['run']['properties']['counts']['properties']
	)
	for fieldName in ('fqdns', 'failed_fqdns', 'disappeared_fqdns'):
		assert runCountMappings[fieldName]['type'] == 'integer'
	pqcPanel = next(
		panel
		for panel in dashboard['panels']
		if panel['config'].get('title') == 'Statut PQC des certificats TLS par FQDN'
	)
	pqcLayer = pqcPanel['config']['layers'][0]
	assert pqcLayer['type'] == 'bar_horizontal'
	assert pqcLayer['data_source']['query'].startswith(
		'FROM asmira-exposure-certificates-current '
	)
	assert 'asmira.exposure.tls.certificate_pqc_status' in pqcLayer['data_source']['query']
	assert '"classical", "Classique' in pqcLayer['data_source']['query']
	assert pqcLayer['breakdown_by'] == {'column': 'Statut post-quantique'}
	cryptoPanel = next(
		panel
		for panel in dashboard['panels']
		if panel['config'].get('title') == (
			'Suites cryptographiques TLS négociées'
		)
	)
	cryptoLayer = cryptoPanel['config']['layers'][0]
	assert cryptoLayer['type'] == 'bar_horizontal'
	assert 'MV_EXPAND asmira.exposure.tls.negotiated_cipher' in (
		cryptoLayer['data_source']['query']
	)
	assert cryptoLayer['x'] == {'column': 'Suite'}
	assert cryptoLayer['breakdown_by'] == {'column': 'Évaluation'}
	# Kibana masque la légende des XY par défaut : la forcer dès qu’il y a plusieurs séries.
	for panel in xyPanels:
		layer = panel['config']['layers'][0]
		if 'breakdown_by' in layer or len(layer['y']) > 1:
			assert panel['config']['legend'] == {'visibility': 'visible'}
	for title, expected in (
		('Certificats auto-signés', {
			'Émis par une autorité': '#2E8B57',
			'Auto-signé': '#BD271E',
		}),
		('Validation des chaînes TLS', {
			'Chaîne valide': '#2E8B57',
			'Chaîne invalide': '#BD271E',
		}),
	):
		booleanPanel = next(
			panel
			for panel in dashboard['panels']
			if panel['config'].get('title') == title
		)
		assert booleanPanel['config']['data_source']['type'] == 'esql'
		assert {
			value: rule['color']['value']
			for rule in booleanPanel['config']['group_by'][0]['color']['mapping']
			for value in rule['values']
		} == expected
	changePanel = next(
		panel
		for panel in dashboard['panels']
		if panel['config'].get('title') == (
			'Changements récents de certificat ou de statut PQC'
		)
	)
	changeQuery = changePanel['config']['data_source']['query']
	assert 'certificate_changed == true' in changeQuery
	assert 'pqc_status_changed == true' in changeQuery
	healthPanel = next(
		panel
		for panel in dashboard['panels']
		if panel['config'].get('title') == 'Santé du dernier run'
	)
	assert healthPanel['config']['ignore_global_filters'] is True
	assert 'SORT @timestamp DESC' in healthPanel['config']['data_source']['query']
	assert 'asmira.run.counts.fqdns' in healthPanel['config']['data_source']['query']
	assert healthPanel['config']['data_source']['query'].endswith('LIMIT 1')
	historyPanel = next(
		panel
		for panel in dashboard['panels']
		if panel['config'].get('title') == 'FQDN observés par exécution'
	)
	historyLayer = historyPanel['config']['layers'][0]
	assert historyLayer['ignore_global_filters'] is True
	assert historyLayer['data_source']['index_pattern'] == 'logs-asmira.run-*'
	assert historyLayer['y'][0]['field'] == 'asmira.run.counts.fqdns'
	discoveryPanels = [
		panel
		for panel in dashboard['panels']
		if 'asmira-discovery-latest' in json.dumps(panel)
	]
	assert len(discoveryPanels) == 5
	assert all(
		panel['config'].get('ignore_global_filters') is True
		or all(
			layer.get('ignore_global_filters') is True
			for layer in panel['config'].get('layers', [])
		)
		for panel in discoveryPanels
	)


def testFleetInputsUseDistinctDatasetsAndNdjson():
	content = (BASE_DIR / 'elastic' / 'fleet' / 'custom-logs.yml').read_text()

	for dataset in ('asmira.discovery', 'asmira.exposure', 'asmira.run'):
		assert f'dataset: {dataset}' in content
	assert content.count('- ndjson:') == 3
	assert content.count('target_field: "@metadata._id"') == 3


def mappedFieldNames(properties, prefix=''):
	names = set()
	for name, definition in properties.items():
		path = f'{prefix}{name}'
		if 'properties' in definition:
			names |= mappedFieldNames(definition['properties'], f'{path}.')
		else:
			names.add(path)
	return(names)


def testDashboardOnlyUsesMappedFields():
	import re
	dashboard = json.loads((BASE_DIR / 'elastic/kibana/asmira-global-dashboard.json').read_text())
	mapping = json.loads((BASE_DIR / 'elastic/elasticsearch/asmira-mappings.json').read_text())
	known = mappedFieldNames(mapping['template']['mappings']['properties'])
	# Le lookbehind écarte les noms d’index et de data views (logs-asmira.exposure-*).
	used = set(re.findall(
		r'(?<![-\w])(?:asmira|server|dns)\.[a-z0-9_.]+[a-z0-9_]',
		json.dumps([panel['config'] for panel in dashboard['panels']]),
	))

	assert used - known == set()


def testDashboardGridHasNoOverlap():
	dashboard = json.loads((BASE_DIR / 'elastic/kibana/asmira-global-dashboard.json').read_text())
	cells = set()
	for panel in dashboard['panels']:
		grid = panel['grid']
		assert grid['x'] + grid['w'] <= 48
		for x in range(grid['x'], grid['x'] + grid['w']):
			for y in range(grid['y'], grid['y'] + grid['h']):
				assert (x, y) not in cells
				cells.add((x, y))


def testElasticSetupUpdatesExistingExposureMappings():
	class FakeClient:
		def __init__(self):
			self.calls = []

		def request(self, method, path, payload=None, allowedStatuses=()):
			self.calls.append((method, path, payload))
			if method == 'GET':
				return({'status': 404})
			return({})

	client = FakeClient()
	elasticSetup.configureElasticsearch(client, 180)
	putPayloads = {
		path: payload
		for method, path, payload in client.calls
		if method == 'PUT'
	}

	for path in (
		'logs-asmira.exposure-default/_mapping',
		'asmira-fqdn-latest/_mapping',
	):
		serverProperties = putPayloads[path]['properties']['server']['properties']
		assert serverProperties['domain']['type'] == 'keyword'
		assert serverProperties['registered_domain']['type'] == 'keyword'
		tlsProperties = (
			putPayloads[path]['properties']['asmira']['properties']['exposure']
			['properties']['tls']['properties']
		)
		assert tlsProperties['certificate_pqc_status']['type'] == 'keyword'
		assert tlsProperties['certificate_pqc_algorithms']['type'] == 'keyword'
		assert tlsProperties['certificate_changed']['type'] == 'boolean'
		assert tlsProperties['pqc_status_changed']['type'] == 'boolean'
	mapping = json.loads((BASE_DIR / 'elastic/elasticsearch/asmira-mappings.json').read_text())
	expectedExposure = (
		mapping['template']['mappings']['properties']['asmira']['properties']['exposure']['properties']
	)
	for path in ('logs-asmira.exposure-default/_mapping', 'asmira-fqdn-latest/_mapping'):
		pushedExposure = (
			putPayloads[path]['properties']['asmira']['properties']['exposure']['properties']
		)
		assert pushedExposure == expectedExposure
	runMapping = putPayloads['logs-asmira.run-default/_mapping']
	runCounts = (
		runMapping['properties']['asmira']['properties']['run']['properties']
		['counts']['properties']
	)
	assert set(runCounts) == {'fqdns', 'failed_fqdns', 'disappeared_fqdns'}
	aliasesPayload = next(
		payload
		for method, path, payload in client.calls
		if method == 'POST' and path == '_aliases'
	)
	aliases = {
		action['add']['alias']: action['add']
		for action in aliasesPayload['actions']
		if 'add' in action
	}
	assert aliases['asmira-exposure-current'] == {
		'index': 'asmira-fqdn-latest',
		'alias': 'asmira-exposure-current',
		'filter': {'term': {'asmira.exposure.present': True}},
	}
	assert aliases['asmira-exposure-certificates-current'] == {
		'index': 'asmira-fqdn-latest',
		'alias': 'asmira-exposure-certificates-current',
		'filter': {'bool': {
			'filter': [
				{'term': {'asmira.exposure.present': True}},
				{'exists': {
					'field': 'asmira.exposure.tls.certificate_sha256',
				}},
			],
		}},
	}


@pytest.mark.parametrize('legacyExists', [True, False])
def testElasticSetupRemovesLegacyExposureLatest(legacyExists):
	class FakeClient:
		def __init__(self):
			self.calls = []

		def request(self, method, path, payload=None, allowedStatuses=()):
			self.calls.append((method, path))
			if method == 'GET' and path == '_transform/asmira-exposure-latest' and legacyExists:
				return({'count': 1})
			if method == 'GET':
				return({'status': 404})
			return({})

	client = FakeClient()
	elasticSetup.configureElasticsearch(client, 180)

	legacyCalls = [call for call in client.calls if 'asmira-exposure-latest' in call[1]]
	expected = [('GET', '_transform/asmira-exposure-latest')]
	if legacyExists:
		expected += [
			('POST', '_transform/asmira-exposure-latest/_stop?wait_for_completion=true'),
			('DELETE', '_transform/asmira-exposure-latest'),
		]
	expected.append(('DELETE', 'asmira-exposure-latest'))
	assert legacyCalls == expected
	assert client.calls.index(('POST', '_aliases')) < client.calls.index(expected[0])


def testKibanaSetupCreatesCertificateDataViewAndPrefixedDashboard():
	class FakeClient:
		def __init__(self):
			self.calls = []

		def request(self, method, path, payload=None, allowedStatuses=()):
			self.calls.append((method, path, payload))
			if method == 'GET':
				# Panneaux laissés par le PUT, dont un graphe d’un déploiement antérieur.
				return({'attributes': {'panelsJSON': json.dumps([
					{'panelIndex': 'a', 'gridData': {'x': 0, 'y': 0, 'w': 48, 'h': 4}},
					{'panelIndex': 'b', 'gridData': {'x': 0, 'y': 4, 'w': 24, 'h': 10}},
					{
						'panelIndex': 'asmira-domain-graph',
						'gridData': {'x': 0, 'y': 14, 'w': 48, 'h': 30},
					},
				])}})
			return({})

	client = FakeClient()
	elasticSetup.configureKibana(client)
	putPaths = [path for method, path, payload in client.calls if method == 'PUT']
	assert putPaths == [
		'api/dashboards/asmira-global',
		'api/saved_objects/dashboard/asmira-global',
	]
	savedPanels = json.loads(
		client.calls[-1][2]['attributes']['panelsJSON']
	)
	graphPanels = [
		panel
		for panel in savedPanels
		if panel['panelIndex'] == 'asmira-domain-graph'
	]
	assert len(savedPanels) == 3 and len(graphPanels) == 1
	graphPanel = graphPanels[0]
	assert graphPanel['type'] == 'legacy_vis'
	assert graphPanel['gridData']['y'] == 14
	savedVis = graphPanel['embeddableConfig']['savedVis']
	assert savedVis['type'] == 'vega'
	spec = json.loads(savedVis['params']['spec'])
	fqdnData = next(data for data in spec['data'] if data['name'] == 'fqdn')
	# Le contexte du dashboard (contrôle Domaine, filtres) pilote le graphe :
	# aucun domaine réel n’est écrit dans la spec.
	assert fqdnData['url']['%context%'] is True
	assert fqdnData['url']['index'] == 'asmira-exposure-current'
	assert 'query' not in fqdnData['url']['body']
	assert 'archoad' not in savedVis['params']['spec']
	dataViewIds = {
		payload['data_view']['id']
		for method, path, payload in client.calls
		if method == 'POST' and path == 'api/data_views/data_view'
	}
	assert 'asmira-exposure-certificates-current' in dataViewIds
	dashboardPayload = next(
		payload
		for method, path, payload in client.calls
		if method == 'PUT' and path == 'api/dashboards/asmira-global'
	)
	assert dashboardPayload['title'] == (
		'[archoad] Asmira — Surface d’exposition globale'
	)


def testEnsureTransformOnlyUpdatesMutableFields():
	class FakeClient:
		def __init__(self):
			self.calls = []

		def request(self, method, path, payload=None, allowedStatuses=()):
			self.calls.append((method, path, payload))
			if method == 'GET':
				return({'count': 1, 'transforms': [{'id': 'asmira-fqdn-latest'}]})
			return({})

	definition = elasticSetup.loadJson(
		'elasticsearch/asmira-fqdn-latest-transform.json'
	)
	client = FakeClient()

	elasticSetup.ensureTransform(client, 'asmira-fqdn-latest', definition)

	updatePayload = next(
		payload
		for method, path, payload in client.calls
		if method == 'POST' and path.endswith('/_update')
	)
	assert 'latest' not in updatePayload
	assert updatePayload['source'] == definition['source']
	assert updatePayload['dest'] == definition['dest']
	assert updatePayload['frequency'] == definition['frequency']
	assert updatePayload['sync'] == definition['sync']
	assert 'retention_policy' not in updatePayload
