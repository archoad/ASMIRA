import json
from pathlib import Path

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
	assert dashboard['title'] == 'Asmira — Surface d’exposition globale'
	assert len(dashboard['panels']) >= 10
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
		'État du port HTTPS',
		'Versions TLS supportées',
		'Certificats expirés ou proches de l’expiration',
		'Erreurs récentes de cartographie',
		'Changements du dernier cycle',
		'Statut PQC des certificats TLS par endpoint',
	}
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
	):
		assert tlsMappings[fieldName]['type'] == 'keyword'
	pqcPanel = next(
		panel
		for panel in dashboard['panels']
		if panel['config'].get('title') == 'Statut PQC des certificats TLS par endpoint'
	)
	assert pqcPanel['config']['group_by'][0]['fields'] == [
		'asmira.exposure.tls.certificate_pqc_status',
	]
	assert pqcPanel['config']['styling']['donut_hole'] == 'm'
	assert pqcPanel['config']['styling']['values']['mode'] == 'percentage'


def testFleetInputsUseDistinctDatasetsAndNdjson():
	content = (BASE_DIR / 'elastic' / 'fleet' / 'custom-logs.yml').read_text()

	for dataset in ('asmira.discovery', 'asmira.exposure', 'asmira.run'):
		assert f'dataset: {dataset}' in content
	assert content.count('- ndjson:') == 3
	assert content.count('target_field: "@metadata._id"') == 3


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
		'asmira-exposure-latest/_mapping',
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


def testEnsureTransformOnlyUpdatesMutableFields():
	class FakeClient:
		def __init__(self):
			self.calls = []

		def request(self, method, path, payload=None, allowedStatuses=()):
			self.calls.append((method, path, payload))
			if method == 'GET':
				return({'count': 1, 'transforms': [{'id': 'asmira-exposure-latest'}]})
			return({})

	definition = elasticSetup.loadJson(
		'elasticsearch/asmira-exposure-latest-transform.json'
	)
	client = FakeClient()

	elasticSetup.ensureTransform(client, 'asmira-exposure-latest', definition)

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
	assert updatePayload['retention_policy'] == definition['retention_policy']
