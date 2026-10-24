import base64
import gzip
import io
import json
import shutil
import subprocess
import tarfile
from types import SimpleNamespace

import pytest

import asmira
import asmiraCommon
import asmiraImport
import asmiraReport
import asmiraShare


RUN_ID = '20261023T102517Z-61398e2b'


def shareEventOf(dataset, eventId, **asmiraFields):
	return({
		'@timestamp': '2026-10-23T12:00:00+00:00',
		'data_stream': {'type': 'logs', 'dataset': f'asmira.{dataset}', 'namespace': 'default'},
		'event': {'id': eventId, 'dataset': f'asmira.{dataset}'},
		'asmira': {'run': {'id': RUN_ID}, **asmiraFields},
	})


def sampleEvents():
	return({
		'discovery': [shareEventOf('discovery', 'd1', raw={'candidate': {'name': 'www.example.com'}})],
		'exposure': [
			shareEventOf('exposure', 'e1', exposure={'present': True}, raw={'endpoints': [{'ip': '192.0.2.1'}]}),
			shareEventOf('exposure', 'e2', exposure={'present': False}, raw={'previous_event_id': 'old'}),
		],
		'run': [shareEventOf('run', 'r1')],
	})


def rebuildArchive(data, transform):
	"""Archive modifiée par transform(name, content) → (name, content) ou None."""
	source = tarfile.open(fileobj=io.BytesIO(data), mode='r:gz')
	buffer = io.BytesIO()
	with gzip.GzipFile(fileobj=buffer, mode='wb', mtime=0) as compressed:
		with tarfile.open(fileobj=compressed, mode='w') as archive:
			for info in source:
				member = transform(info.name, source.extractfile(info).read())
				if member is not None:
					asmiraShare.addMember(archive, *member)
	return(buffer.getvalue())


def testShareEventDropsOnlyRawEndpoints():
	events = sampleEvents()

	exposure = [asmiraShare.shareEvent(event) for event in events['exposure']]

	assert 'raw' not in exposure[0]['asmira']
	assert exposure[0]['asmira']['exposure'] == {'present': True}
	assert exposure[1]['asmira']['raw'] == {'previous_event_id': 'old'}
	assert asmiraShare.shareEvent(events['discovery'][0]) is events['discovery'][0]
	# L’événement d’origine reste intact : il est aussi écrit dans l’export local.
	assert events['exposure'][0]['asmira']['raw'] == {'endpoints': [{'ip': '192.0.2.1'}]}


def testBundleRoundTripIsDeterministicAndChecked():
	data = asmiraShare.buildBundle(RUN_ID, sampleEvents(), reportHtml='<!doctype html>bilan', createdAt='2026-10-23T18:26:30+00:00')

	assert data == asmiraShare.buildBundle(RUN_ID, sampleEvents(), reportHtml='<!doctype html>bilan', createdAt='2026-10-23T18:26:30+00:00')
	manifest, events, report = asmiraShare.readBundle(data)
	assert manifest['format'] == asmiraShare.SHARE_FORMAT
	assert manifest['run_id'] == RUN_ID
	assert {name: entry.get('events') for name, entry in manifest['files'].items()} == {
		'discovery.ndjson': 1, 'exposure.ndjson': 2, 'run.ndjson': 1, 'report.html': None,
	}
	assert [event['event']['id'] for event in events['exposure']] == ['e1', 'e2']
	assert 'raw' not in events['exposure'][0]['asmira']
	assert report == '<!doctype html>bilan'


def testBundleWithoutExposureKeepsOtherDatasets():
	events = sampleEvents()
	events['exposure'] = None

	manifest, readEvents, report = asmiraShare.readBundle(asmiraShare.buildBundle(RUN_ID, events))

	assert set(readEvents) == {'discovery', 'run'}
	assert report is None


@pytest.mark.parametrize('transform, message', [
	(lambda name, content: (name, content + b'{}\n') if name == 'exposure.ndjson' else (name, content), 'empreinte'),
	(lambda name, content: (name, content) if name != 'run.ndjson' else ('../run.ndjson', content), 'membre inattendu'),
	(lambda name, content: None if name == 'run.ndjson' else (name, content), 'différent du manifeste'),
	(
		lambda name, content: (name, content.replace(b'"format": 1', b'"format": 99')) if name == 'manifest.json' else (name, content),
		'non pris en charge',
	),
])
def testReadBundleRejectsTamperedArchives(transform, message):
	data = rebuildArchive(asmiraShare.buildBundle(RUN_ID, sampleEvents()), transform)

	with pytest.raises(ValueError, match=message):
		asmiraShare.readBundle(data)


def testReadBundleRejectsEventsOfAnotherRun():
	events = sampleEvents()
	events['run'][0]['asmira']['run']['id'] = '20261019T180259Z-6cb45b2b'

	with pytest.raises(ValueError, match='autre run'):
		asmiraShare.readBundle(asmiraShare.buildBundle(RUN_ID, events))


def testReadBundleRejectsGarbage():
	with pytest.raises(ValueError, match='illisible'):
		asmiraShare.readBundle(b'pas une archive')


@pytest.mark.parametrize('size', [0, 1, 56, 57, 58, 1_000_000])
def testEncodedSizeCoversTheBase64Attachment(size):
	encoded = base64.encodebytes(b'x' * size)

	# encodebytes termine ses lignes par « \n » ; le message SMTP par « \r\n ».
	assert asmiraShare.encodedSize(size) >= len(encoded) + encoded.count(b'\n')
	assert asmiraShare.encodedSize(size) <= len(encoded) + encoded.count(b'\n') + 2


def testAgeCommandsUseRecipientAndIdentity(monkeypatch):
	calls = []

	def fakeRunTool(command, inputData=None, errorLabel=None):
		calls.append((command, inputData))
		return(b'chiffre')

	monkeypatch.setattr(asmiraShare, 'runTool', fakeRunTool)

	assert asmiraShare.encryptBundle(b'clair', AGE_RECIPIENT, agePath='/usr/bin/age') == b'chiffre'
	asmiraShare.decryptBundle(b'chiffre', '/home/soc/asmira.key', agePath='/usr/bin/age')

	assert calls == [
		(['/usr/bin/age', '--encrypt', '--recipient', AGE_RECIPIENT], b'clair'),
		(['/usr/bin/age', '--decrypt', '--identity', '/home/soc/asmira.key'], b'chiffre'),
	]


def testMissingToolIsReported(monkeypatch):
	monkeypatch.setattr(asmiraShare.shutil, 'which', lambda name: None)

	with pytest.raises(RuntimeError, match='age introuvable'):
		asmiraShare.encryptBundle(b'clair', AGE_RECIPIENT)


@pytest.mark.skipif(shutil.which('ssh-keygen') is None, reason='ssh-keygen absent')
def testSshSignatureRoundTrip(tmp_path):
	key = tmp_path / 'signing_ed25519'
	subprocess.run(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-C', 'asmira', '-f', str(key)], check=True)
	bundle = tmp_path / asmiraShare.bundleFileName(RUN_ID)
	bundle.write_bytes(b'paquet chiffre')
	allowedSigners = tmp_path / 'allowed_signers'
	allowedSigners.write_text(f'asmira-sonde {(tmp_path / "signing_ed25519.pub").read_text()}')

	signature = asmiraShare.signFile(bundle, key)

	assert signature.name == f'{bundle.name}.sig'
	assert asmiraShare.verifySignature(bundle.read_bytes(), signature, allowedSigners) == 'asmira-sonde'
	with pytest.raises(RuntimeError, match='Signature invalide'):
		asmiraShare.verifySignature(b'paquet modifie', signature, allowedSigners)
	otherKey = tmp_path / 'other_ed25519'
	subprocess.run(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', str(otherKey)], check=True)
	allowedSigners.write_text(f'autre {(tmp_path / "other_ed25519.pub").read_text()}')
	with pytest.raises(RuntimeError, match='Signature non reconnue'):
		asmiraShare.verifySignature(bundle.read_bytes(), signature, allowedSigners)


AGE_RECIPIENT = 'age1' + 'qpzry9x8gf2tvdw0s3jn54khce6mua7l' * 2
AGE_RECIPIENT = AGE_RECIPIENT[:62]

SHARE_CONFIG = f'''
[share]
enabled = true
email_to = soc@example.org, cert@example.net
recipient = {AGE_RECIPIENT}
signing_key = /etc/asmira/share/signing_ed25519
max_attachment_mb = 8

[tools]
age = /usr/bin/age
'''


def writeShareConfig(filePath, extra):
	filePath.write_text('''
[targets]
domains = example.com
''' + extra, encoding='utf-8')


def testShareConfiguration(tmp_path):
	configFile = tmp_path / 'asmira.conf'
	writeShareConfig(configFile, SHARE_CONFIG)

	config = asmiraCommon.loadConfig(configFile)

	assert config.shareEnabled is True
	assert config.shareEmailTo == ('soc@example.org', 'cert@example.net')
	assert config.shareRecipient == AGE_RECIPIENT
	assert str(config.shareSigningKey) == '/etc/asmira/share/signing_ed25519'
	assert config.shareMaxAttachmentMb == 8
	assert str(config.agePath) == '/usr/bin/age'
	assert config.sshKeygenPath is None


@pytest.mark.parametrize('extra, message', [
	(f'[share]\nenabled = true\nrecipient = {AGE_RECIPIENT}\n', 'email_to'),
	('[share]\nenabled = true\nemail_to = soc@example.org\n', 'recipient'),
	(f'[share]\nenabled = true\nemail_to = soc@example.org\nrecipient = {AGE_RECIPIENT}, {AGE_RECIPIENT}\n', 'une seule clé'),
	('[share]\nenabled = true\nemail_to = soc@example.org\nrecipient = /etc/asmira/share/recipients.txt\n', 'une seule clé'),
	('[share]\nemail_to = soc@example.org\nmax_attachment_mb = 0\n', 'max_attachment_mb'),
])
def testShareConfigurationIsValidated(tmp_path, extra, message):
	configFile = tmp_path / 'asmira.conf'
	writeShareConfig(configFile, extra)

	with pytest.raises(ValueError, match=message):
		asmiraCommon.loadConfig(configFile)


def testShareIsDisabledByDefault():
	config = asmiraCommon.loadConfig('config/asmira.conf.example')

	assert config.shareEnabled is False
	assert config.shareMaxAttachmentMb == 10


def testValidateConfigScopeRequiresReadableSigningKey(tmp_path):
	configFile = tmp_path / 'asmira.conf'
	signingKey = tmp_path / 'signing_ed25519'
	writeShareConfig(configFile, f'[share]\nenabled = true\nemail_to = soc@example.org\nrecipient = {AGE_RECIPIENT}\nsigning_key = {signingKey}\n')
	config = asmiraCommon.loadConfig(configFile)

	with pytest.raises(ValueError, match=r'\[share\] signing_key est illisible'):
		asmira.validateConfigScope(config)
	signingKey.write_text('clé\n')
	assert asmira.validateConfigScope(config) is True


def shareConfig(**overrides):
	values = {
		'shareEnabled': True,
		'shareEmailTo': ('soc@example.org',),
		'shareRecipient': AGE_RECIPIENT,
		'shareSigningKey': None,
		'shareMaxAttachmentMb': 10,
		'agePath': None,
		'sshKeygenPath': None,
		'reportEmailFrom': 'asmira@example.org',
		'reportSmtpHost': 'localhost',
		'reportSmtpPort': 25,
		'reportSmtpStartTls': False,
		'reportSmtpUsername': None,
		'reportSmtpTimeout': 30,
	}
	values.update(overrides)
	return(SimpleNamespace(**values))


def runEventOf():
	event = shareEventOf('run', 'r1')
	event['asmira']['run'].update({
		'status': 'success', 'partial': False,
		'started_at': '2026-10-23T10:25:17+00:00', 'finished_at': '2026-10-23T18:26:30+00:00',
	})
	return(event)


class FakeSmtp:
	instances = []

	def __init__(self, host, port, timeout=None):
		self.messages = []
		FakeSmtp.instances.append(self)

	def __enter__(self):
		return(self)

	def __exit__(self, *args):
		return(False)

	def send_message(self, message):
		self.messages.append(message)


def testShareEmailAttachesBundleAndSignature(tmp_path):
	FakeSmtp.instances = []
	bundle = tmp_path / asmiraShare.bundleFileName(RUN_ID)
	bundle.write_bytes(b'x' * 1000)
	signature = tmp_path / f'{bundle.name}.sig'
	signature.write_bytes(b'signature')

	attached = asmiraReport.sendShareBundle(runEventOf(), bundle, signature, shareConfig(), smtpFactory=FakeSmtp, environ={})

	assert attached is True
	message = FakeSmtp.instances[0].messages[0]
	assert message['To'] == 'soc@example.org'
	assert message['Subject'] == f'[ASMIRA] Données du run {RUN_ID}'
	assert [part.get_filename() for part in message.iter_attachments()] == [bundle.name, signature.name]
	assert next(message.iter_attachments()).get_content() == b'x' * 1000
	body = message.get_body(('plain',)).get_content()
	assert 'asmiraImport.py' in body
	assert 'SHA-256 : ' in body


def testShareEmailOverTheLimitIsSentWithoutAttachment(tmp_path):
	FakeSmtp.instances = []
	bundle = tmp_path / asmiraShare.bundleFileName(RUN_ID)
	# 800 ko bruts dépassent 1 Mo une fois encodés en base64.
	bundle.write_bytes(b'x' * 800_000)

	attached = asmiraReport.sendShareBundle(
		runEventOf(), bundle, None, shareConfig(shareMaxAttachmentMb=1), smtpFactory=FakeSmtp, environ={},
	)

	assert attached is False
	message = FakeSmtp.instances[0].messages[0]
	assert list(message.iter_attachments()) == []
	assert 'non joint' in message['Subject']
	body = message.get_body(('plain',)).get_content()
	assert str(bundle) in body
	assert 'paquet non signé' in body


def testWriteShareBundleEncryptsSignsAndSends(tmp_path, monkeypatch):
	sent = []
	monkeypatch.setattr(asmiraShare, 'encryptBundle', lambda data, recipient, agePath: b'AGE' + data)

	def fakeSign(filePath, signingKey, sshKeygenPath):
		signature = tmp_path / f'{filePath.name}.sig'
		signature.write_bytes(b'sig')
		return(signature)

	monkeypatch.setattr(asmiraShare, 'signFile', fakeSign)
	monkeypatch.setattr(asmiraReport, 'sendShareBundle', lambda *args: sent.append(args) or True)
	reportFile = tmp_path / f'{RUN_ID}_report.html'
	reportFile.write_text('<!doctype html>bilan', encoding='utf-8')
	events = sampleEvents()

	bundleFile = asmira.writeShareBundle(
		shareConfig(shareSigningKey='/etc/asmira/share/signing_ed25519'),
		tmp_path, runEventOf(), events['discovery'], events['exposure'], reportFile,
	)

	assert bundleFile == tmp_path / asmiraShare.bundleFileName(RUN_ID)
	content = bundleFile.read_bytes()
	assert content.startswith(b'AGE')
	manifest, readEvents, report = asmiraShare.readBundle(content[3:])
	assert manifest['run_id'] == RUN_ID
	assert len(readEvents['exposure']) == 2
	assert report == '<!doctype html>bilan'
	assert sent[0][2] == tmp_path / f'{bundleFile.name}.sig'


def testShareFailureDoesNotFailTheRun(tmp_path, monkeypatch, capsys):
	def refuse(data, recipient, agePath):
		raise RuntimeError('Chiffrement age : clé invalide')

	monkeypatch.setattr(asmiraShare, 'encryptBundle', refuse)
	events = sampleEvents()

	assert asmira.writeShareBundle(
		shareConfig(), tmp_path, runEventOf(), events['discovery'], events['exposure'], tmp_path / 'absent.html',
	) is None
	assert 'paquet de partage non produit' in capsys.readouterr().err
	assert list(tmp_path.iterdir()) == []


def testShareIsSkippedWhenDisabled(tmp_path):
	assert asmira.writeShareBundle(shareConfig(shareEnabled=False), tmp_path, runEventOf(), [], [], tmp_path / 'r.html') is None
	assert list(tmp_path.iterdir()) == []


def testBulkBodiesUseCreateWithEventIds(monkeypatch):
	monkeypatch.setattr(asmiraImport, 'BULK_ACTIONS', 2)
	events = sampleEvents()['exposure'] + [shareEventOf('exposure', 'e3')]

	bodies = list(asmiraImport.bulkBodies(events))

	assert len(bodies) == 2
	lines = [json.loads(line) for line in bodies[0].decode('utf-8').splitlines()]
	assert lines[0] == {'create': {'_index': 'logs-asmira.exposure-default', '_id': 'e1'}}
	assert lines[1]['event']['id'] == 'e1'
	assert bodies[0].endswith(b'\n')


def bulkResponse(*statuses):
	return({'items': [
		{'create': {'_id': str(index), 'status': status, **({'error': {'reason': 'mapping'}} if status == 400 else {})}}
		for index, status in enumerate(statuses)
	]})


def testBulkImportCountsCreatedAndExistingEvents():
	assert asmiraImport.bulkImport(None, sampleEvents()['exposure'], post=lambda client, body: bulkResponse(201, 409)) == (1, 1)
	with pytest.raises(RuntimeError, match='mapping'):
		asmiraImport.bulkImport(None, sampleEvents()['exposure'], post=lambda client, body: bulkResponse(201, 400))


class FakeClient:
	def __init__(self, runCount=0):
		self.runCount = runCount
		self.requests = []

	def request(self, method, path, payload=None, allowedStatuses=()):
		self.requests.append((method, path, payload))
		return({'count': self.runCount})


def importMain(monkeypatch, tmp_path, client, extraArgs=()):
	posted = []
	data = asmiraShare.buildBundle(RUN_ID, sampleEvents(), reportHtml='<!doctype html>bilan')
	bundle = tmp_path / asmiraShare.bundleFileName(RUN_ID)
	bundle.write_bytes(b'AGE' + data)
	(tmp_path / f'{bundle.name}.sig').write_bytes(b'sig')
	monkeypatch.setattr(asmiraShare, 'verifySignature', lambda data, signature, allowed, sshKeygen: 'asmira-sonde')
	monkeypatch.setattr(asmiraShare, 'decryptBundle', lambda data, identity, agePath: data[3:])

	def post(client, body):
		lines = body.decode('utf-8').splitlines()
		posted.extend(json.loads(line)['create']['_index'] for line in lines[::2])
		return(bulkResponse(*([201] * (len(lines) // 2))))

	code = asmiraImport.main(
		[str(bundle), '--identity', 'id.key', '--allowed-signers', 'allowed', '--elasticsearch-url', 'https://es.example.org:9200', *extraArgs],
		clientFactory=lambda url, prefix, caCert: client,
		post=post,
	)
	return(code, posted)


def testImportWritesDatasetsWithTheRunLast(monkeypatch, tmp_path, capsys):
	client = FakeClient()
	reportFile = tmp_path / 'bilan.html'

	code, posted = importMain(monkeypatch, tmp_path, client, ['--report', str(reportFile)])

	assert code == 0
	assert posted == [
		'logs-asmira.discovery-default',
		'logs-asmira.exposure-default', 'logs-asmira.exposure-default',
		'logs-asmira.run-default',
	]
	assert client.requests == [('POST', 'logs-asmira.run-*/_count', {'query': {'term': {'asmira.run.id': RUN_ID}}})]
	assert reportFile.read_text(encoding='utf-8') == '<!doctype html>bilan'
	output = capsys.readouterr().out
	assert 'signé par asmira-sonde' in output
	assert 'exposure : 2 créé(s), 0 déjà présent(s)' in output


def testImportSkipsARunAlreadyImported(monkeypatch, tmp_path, capsys):
	code, posted = importMain(monkeypatch, tmp_path, FakeClient(runCount=1))

	assert code == 0
	assert posted == []
	assert 'déjà importé' in capsys.readouterr().out
	code, posted = importMain(monkeypatch, tmp_path, FakeClient(runCount=1), ['--force'])
	assert len(posted) == 4


def testImportRequiresSignatureUnlessAllowed(monkeypatch, tmp_path, capsys):
	bundle = tmp_path / asmiraShare.bundleFileName(RUN_ID)
	bundle.write_bytes(b'AGE')

	code = asmiraImport.main([str(bundle), '--identity', 'id.key', '--allowed-signers', 'allowed', '--dry-run'])

	assert code == 1
	assert 'Signature absente' in capsys.readouterr().err
	with pytest.raises(SystemExit):
		asmiraImport.main([str(bundle), '--identity', 'id.key', '--dry-run'])
