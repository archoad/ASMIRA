from types import SimpleNamespace

import pytest

import asmira
import asmiraReport


def runEvent(status='success', partial=True, error=None):
	return({
		'observer': {'hostname': 'probe'},
		'asmira': {'run': {
			'id': '20261002T180634Z-b82f430f',
			'status': status,
			'partial': partial,
			'coverage_reasons': ['example.com:amass:failed'] if partial else [],
			'started_at': '2026-10-02T18:06:34+00:00',
			'finished_at': '2026-10-02T21:24:17+00:00',
			'duration_seconds': 11863.0,
			'counts': {'domains': 1, 'fqdns': 2, 'endpoints': 3, 'resolvable_hosts': 2},
			'failed_sources': ['example.com:amass'] if partial else [],
			'error': error,
		}},
	})


def discoveryResult():
	return({
		'report': {'duration_seconds': 3336.0},
		'source_reports': [
			{'domain': 'example.com', 'source': 'subfinder', 'status': 'success', 'count': 3, 'duration_seconds': 4},
			{'domain': 'example.com', 'source': 'dnsx', 'status': 'success', 'count': 2, 'duration_seconds': 50},
			{
				'domain': 'example.com', 'source': 'amass', 'status': 'failed', 'count': 1,
				'duration_seconds': 720, 'error': 'Amass a dépassé le délai de 720 s',
			},
		],
		'inventory': [
			{'name': 'www.example.com', 'resolvable': True, 'sources': ['subfinder:crtsh', 'dnsx']},
			{'name': 'idp.example.com', 'resolvable': True, 'sources': ['dnsx', 'amass']},
			{'name': 'old.example.com', 'resolvable': False, 'sources': ['subfinder:thc']},
		],
	})


def exposureEvent(name, change='unchanged', grade='A', **tls):
	return({
		'server': {'domain': name, 'registered_domain': 'example.com'},
		'asmira': {'exposure': {
			'present': True,
			'change': change,
			'open_ports': [80, 443, 8080],
			'cleartext_ports': [],
			'services': ['80:clear', '443:tls', '8080:redirect'],
			'dns': {'caa': {'status': 'absent'}},
			'tls': {'grade': grade, 'findings': [], **tls},
		}},
	})


def exposureEvents():
	return([
		exposureEvent(
			'www.example.com', change='updated', grade='C', grade_changed=True, previous_grade='A',
			findings=['WEAK_64BIT_CIPHER'], findings_opened=['WEAK_64BIT_CIPHER'], max_severity='high',
			certificate_days_remaining=[12], pqc_kex_status='hybrid', pqc_kex_groups=['X25519MLKEM768'],
		),
		exposureEvent(
			'idp.example.com', change='new', grade='M', findings=['CERT_HOSTNAME_MISMATCH'],
			max_severity='critical', certificate_issuer_authorized=False,
		),
	])


def previousEvents():
	return([
		exposureEvent('www.example.com', grade='A'),
		exposureEvent('legacy.example.com', grade='B'),
	])


def analysis(**kwargs):
	return(asmiraReport.analyseRun(
		kwargs.get('run', runEvent()),
		kwargs.get('discovery', discoveryResult()),
		kwargs.get('events', exposureEvents()),
		kwargs.get('previous', previousEvents()),
	))


def testAnalysisComputesIndicators():
	result = analysis()

	assert result['durations'] == {'total': 11863.0, 'discovery': 3336.0, 'mapping': 8527.0}
	assert result['sources']['active_only'] == ['idp.example.com']
	assert [row['source'] for row in result['sources']['contribution']][:1] == ['dnsx']
	exposure = result['exposure']
	assert exposure['changes'] == {'updated': 1, 'new': 1}
	assert exposure['absent'] == [('example.com', 'legacy.example.com')]
	assert [event['server']['domain'] for event in exposure['degraded']] == ['www.example.com']
	assert [event['server']['domain'] for event in exposure['new']] == ['idp.example.com']
	assert [(event['server']['domain'], days) for event, days in exposure['expiring']] == [('www.example.com', 12)]
	assert exposure['caa_unauthorized'] == ['idp.example.com']
	assert exposure['port_states'][(8080, 'redirect')] == 2
	assert exposure['domains'][0]['good'] == 0
	assert exposure['domains'][0]['hybrid'] == 1


def testAttentionPointsAreOrderedBySeverity():
	levels = [level for level, unused in analysis()['attention']]

	assert levels == sorted(levels, key=asmiraReport.severityRank)
	texts = ' '.join(text for unused, text in analysis()['attention'])
	assert '1 nouveau(x) FQDN avec un constat critique ou élevé' in texts
	assert 'Run partiel (1 raison(s), détail dans « Exécution »)' in texts
	assert 'Amass et dnsx ont trouvé 1 FQDN résolus' in texts


def testSummaryIsShortPlainText():
	summary = asmiraReport.renderSummary(analysis())

	assert summary.startswith('ASMIRA — bilan du run 20261002T180634Z-b82f430f (sonde probe)')
	assert 'Statut : succès partiel.' in summary
	assert 'du 2 oct. 2026 à 20:06 au 2 oct. 2026 à 23:24' in summary
	assert 'Surface : 2 FQDN, dont 1 nouveaux, 1 modifiés et 0 disparus.' in summary
	assert 'Le bilan détaillé est joint' in summary
	assert len(summary.splitlines()) < 30


def testHtmlReportIsSelfContained():
	report = asmiraReport.renderHtml(analysis(), maxItems=10)

	assert report.startswith('<!doctype html>')
	assert "default-src 'none'; style-src 'unsafe-inline'" in report
	for forbidden in ('<script', 'src=', 'href="http', '@import', 'url('):
		assert forbidden not in report
	for anchor in ('synthese', 'execution', 'sources', 'surface', 'tls', 'certificats', 'constats', 'ports'):
		assert f'<section id="{anchor}">' in report
	assert report.count('<svg class="chart"') >= 5
	assert '<span class="badge g-m">M</span>' in report
	assert 'Désactiver les suites à blocs de 64 bits' in report


def testHtmlReportEscapesObservedValues():
	events = [exposureEvent('<b>x</b>.example.com', change='new')]

	report = asmiraReport.renderHtml(analysis(events=events), maxItems=10)

	assert '<b>x</b>' not in report
	assert '&lt;b&gt;x&lt;/b&gt;.example.com' in report


def testHtmlReportWithoutMappingStopsAfterSources():
	failed = asmiraReport.analyseRun(
		runEvent(status='failed', partial=False, error='RuntimeError: boom'), discoveryResult(),
	)

	report = asmiraReport.renderHtml(failed)

	assert '<section id="sources">' in report
	assert '<section id="tls">' not in report
	assert 'Le run a échoué : RuntimeError: boom.' in report
	assert 'pas de cartographie active' in asmiraReport.renderSummary(failed)


def testHtmlReportTruncatesLongLists():
	events = [exposureEvent(f'h{index}.example.com', change='new') for index in range(5)]

	report = asmiraReport.renderHtml(analysis(events=events), maxItems=2)

	assert '… et 3 autre(s)' in report


def reportConfig(**overrides):
	values = {
		'reportEmailEnabled': True,
		'reportEmailTo': ('soc@example.org',),
		'reportEmailFrom': 'asmira@example.org',
		'reportSmtpHost': 'localhost',
		'reportSmtpPort': 25,
		'reportSmtpStartTls': False,
		'reportSmtpUsername': None,
		'reportSmtpTimeout': 30,
		'reportMaxItems': 50,
	}
	values.update(overrides)
	return(SimpleNamespace(**values))


class FakeSmtp:
	instances = []

	def __init__(self, host, port, timeout=None):
		self.address = (host, port, timeout)
		self.calls = []
		self.messages = []
		FakeSmtp.instances.append(self)

	def __enter__(self):
		return(self)

	def __exit__(self, *args):
		return(False)

	def starttls(self, context=None):
		self.calls.append('starttls')

	def login(self, username, password):
		self.calls.append(('login', username, password))

	def send_message(self, message):
		self.messages.append(message)


def testSendRunReportAttachesMarkdown():
	FakeSmtp.instances = []

	message = asmiraReport.sendRunReport(
		'Résumé\n', '<!doctype html>', analysis(), reportConfig(), smtpFactory=FakeSmtp, environ={},
	)

	smtp = FakeSmtp.instances[0]
	assert smtp.address == ('localhost', 25, 30)
	assert smtp.calls == []
	assert smtp.messages == [message]
	assert message['To'] == 'soc@example.org'
	assert message['Subject'] == '[ASMIRA] Run 20261002T180634Z-b82f430f : succès partiel, 2 FQDN'
	attachment = next(message.iter_attachments())
	assert attachment.get_filename() == 'asmira_report_20261002T180634Z-b82f430f.html'
	assert attachment.get_content_type() == 'text/html'
	assert message.get_body(('plain',)).get_content() == 'Résumé\n'


def testSendRunReportUsesStartTlsAndPasswordFromEnvironment():
	FakeSmtp.instances = []
	config = reportConfig(reportSmtpStartTls=True, reportSmtpUsername='asmira', reportSmtpPort=587)

	asmiraReport.sendRunReport(
		'Résumé\n', '<!doctype html>', analysis(), config, smtpFactory=FakeSmtp,
		environ={asmiraReport.PASSWORD_ENVIRONMENT: 'motdepasse'},
	)

	assert FakeSmtp.instances[0].calls == ['starttls', ('login', 'asmira', 'motdepasse')]


def testSendRunReportRequiresPasswordWithUsername():
	FakeSmtp.instances = []

	with pytest.raises(ValueError, match=asmiraReport.PASSWORD_ENVIRONMENT):
		asmiraReport.sendRunReport(
			'Résumé\n', '<!doctype html>', analysis(), reportConfig(reportSmtpUsername='asmira'),
			smtpFactory=FakeSmtp, environ={},
		)
	assert FakeSmtp.instances == []


def testEmailFailureDoesNotFailTheRun(tmp_path, monkeypatch, capsys):
	def refuse(*args, **kwargs):
		raise ConnectionRefusedError('relais injoignable')

	monkeypatch.setattr(asmiraReport, 'sendRunReport', refuse)
	reportFile = tmp_path / 'report.html'

	sent = asmira.writeRunReport(reportConfig(), reportFile, runEvent(), discoveryResult(), None, None)

	assert sent is False
	assert reportFile.read_text(encoding='utf-8').startswith('<!doctype html>')
	assert 'bilan non envoyé par e-mail' in capsys.readouterr().err
