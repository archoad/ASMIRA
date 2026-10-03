#!/usr/bin/env python3
"""Bilan d’un run : analyse, rapport HTML autonome et e-mail de synthèse.

analyseRun() calcule une fois tous les indicateurs à partir de l’événement run,
du résultat de la découverte et des événements d’exposition du run et du run
précédent. renderHtml() en tire un rapport détaillé autonome (CSS et graphiques
SVG intégrés, ni script ni ressource externe) ; renderSummary() le texte court
de l’e-mail. Ces fonctions sont pures ; seul sendRunReport() fait des I/O.
"""

import email.utils
import html
import os
import smtplib
import socket
import ssl
from collections import Counter, defaultdict
from datetime import datetime, timezone
from email.message import EmailMessage

import asmiraGrade


ACTIVE_SOURCES = ('amass', 'dnsx')
NO_GRADE = '—'
GRADE_COLUMNS = ('A+', 'A', 'A-', 'B', 'C', 'D', 'E', 'F', 'T', 'M', asmiraGrade.NOT_GRADED, NO_GRADE)
GOOD_GRADES = ('A+', 'A', 'A-')
GRADE_LABELS = {
	'T': 'T : certificat non fiable',
	'M': 'M : nom non couvert',
	asmiraGrade.NOT_GRADED: 'NA : TLS non évaluable',
	NO_GRADE: '— : aucun port ouvert',
}
SERVICE_STATES = (
	('tls', 'TLS'),
	('starttls', 'STARTTLS'),
	('ssh', 'SSH'),
	('redirect', 'Redirection HTTPS'),
	('clear', 'En clair'),
	('inconnu', 'Indéterminé'),
)
KEX_STATES = (
	('hybrid', 'Hybride (conforme ANSSI)'),
	('pure', 'ML-KEM seul'),
	('partial', 'Partiel'),
	('classical', 'Classique'),
	('no_tls13', 'Sans TLS 1.3'),
	('unknown', 'Indéterminé'),
)
CHANGE_LABELS = (
	('new', 'Nouveaux'),
	('updated', 'Modifiés'),
	('unchanged', 'Inchangés'),
	('disappeared', 'Disparus'),
)
SEVERITY_LABELS = {
	'critical': 'critique',
	'high': 'élevée',
	'medium': 'moyenne',
	'low': 'faible',
	'info': 'info',
}
CERTIFICATE_PQC_LABELS = {
	'classical': 'classique',
	'hybrid': 'hybride',
	'pqc': 'post-quantique',
	'unknown': 'indéterminée (pas de certificat lu)',
}
PASSWORD_ENVIRONMENT = 'ASMIRA_SMTP_PASSWORD'
TIMEZONE_NAME = 'Europe/Paris'
MONTHS = ('janv.', 'févr.', 'mars', 'avr.', 'mai', 'juin', 'juil.', 'août', 'sept.', 'oct.', 'nov.', 'déc.')


# --- Accès aux événements -------------------------------------------------

def exposureOf(event):
	return(event.get('asmira', {}).get('exposure', {}))


def tlsOf(event):
	return(exposureOf(event).get('tls') or {})


def serverOf(event):
	return(event.get('server') or {})


def fqdnOf(event):
	return(serverOf(event).get('domain'))


def domainOf(event):
	return(serverOf(event).get('registered_domain') or '?')


def gradeOf(event):
	return(tlsOf(event).get('grade') or NO_GRADE)


def isPresent(event):
	return(exposureOf(event).get('present', True))


def firstValue(values):
	if isinstance(values, list):
		return(values[0] if values else None)
	return(values)


def asnOf(event):
	organization = (serverOf(event).get('as') or {}).get('organization') or {}
	return(firstValue(organization.get('name')) or 'inconnu')


def countryOf(event):
	return(firstValue((serverOf(event).get('geo') or {}).get('country_iso_code')) or 'inconnu')


def sourceFamily(source):
	return(str(source).split(':', 1)[0])


def severityRank(severity):
	order = asmiraGrade.SEVERITY_ORDER
	return(order.index(severity) if severity in order else len(order))


def findingSeverity(code):
	return(asmiraGrade.FINDINGS.get(code, ('info',))[0])


def gradeMove(previousGrade, grade):
	"""-1 amélioration, 1 dégradation, 0 sinon (notes hors échelle comprises)."""
	if previousGrade not in asmiraGrade.GRADE_ORDER or grade not in asmiraGrade.GRADE_ORDER:
		return(0)
	difference = asmiraGrade.gradeRank(grade) - asmiraGrade.gradeRank(previousGrade)
	return((difference > 0) - (difference < 0))


def worstFirst(events):
	"""FQDN les plus graves d’abord : sévérité maximale, nombre de constats, nom."""
	return(sorted(events, key=lambda event: (
		severityRank(tlsOf(event).get('max_severity')),
		-len(tlsOf(event).get('findings') or []),
		fqdnOf(event) or '',
	)))


# --- Analyse ---------------------------------------------------------------

def analyseSources(discoveryResult):
	reports = (discoveryResult or {}).get('source_reports') or []
	inventory = (discoveryResult or {}).get('inventory') or []
	names = Counter()
	resolved = Counter()
	unique = Counter()
	uniqueResolved = Counter()
	activeOnly = []
	for record in inventory:
		families = {sourceFamily(source) for source in record.get('sources', [])}
		for family in families:
			names[family] += 1
			resolved[family] += bool(record.get('resolvable'))
			if len(families) == 1:
				unique[family] += 1
				uniqueResolved[family] += bool(record.get('resolvable'))
		if record.get('resolvable') and families and families <= set(ACTIVE_SOURCES):
			activeOnly.append(record['name'])
	return({
		'reports': reports,
		'names': sorted({report.get('source') for report in reports}),
		'domains': sorted({report.get('domain') for report in reports}),
		'failures': [report for report in reports if report.get('status') != 'success'],
		'contribution': [
			{
				'source': family,
				'names': names[family],
				'resolved': resolved[family],
				'unique': unique[family],
				'unique_resolved': uniqueResolved[family],
			}
			for family in sorted(names, key=lambda family: (-uniqueResolved[family], -names[family], family))
		],
		'active_enabled': any(report.get('source') in ACTIVE_SOURCES for report in reports),
		'active_only': sorted(activeOnly),
	})


def analyseDomains(events):
	byDomain = defaultdict(list)
	for event in events:
		byDomain[domainOf(event)].append(event)
	rows = []
	for domain, domainEvents in sorted(byDomain.items()):
		grades = Counter(gradeOf(event) for event in domainEvents)
		graded = sum(count for grade, count in grades.items() if grade in asmiraGrade.GRADE_ORDER)
		tlsEvents = [event for event in domainEvents if tlsOf(event).get('pqc_kex_status')]
		rows.append({
			'domain': domain,
			'fqdns': len(domainEvents),
			'new': sum(exposureOf(event).get('change') == 'new' for event in domainEvents),
			'grades': grades,
			'graded': graded,
			'good': sum(grades.get(grade, 0) for grade in GOOD_GRADES),
			'critical': sum(tlsOf(event).get('max_severity') == 'critical' for event in domainEvents),
			'hybrid': sum(tlsOf(event).get('pqc_kex_status') == 'hybrid' for event in tlsEvents),
			'tls': len(tlsEvents),
			'caa': sum(
				((exposureOf(event).get('dns') or {}).get('caa') or {}).get('status') == 'present'
				for event in domainEvents
			),
			'expired': sum('CERT_EXPIRED' in (tlsOf(event).get('findings') or []) for event in domainEvents),
		})
	return(rows)


def analyseExposure(exposureEvents, previousEvents, partial):
	allEvents = list(exposureEvents or [])
	events = [event for event in allEvents if isPresent(event)]
	previous = [event for event in previousEvents or [] if isPresent(event)]
	currentNames = {fqdnOf(event) for event in events}
	changed = [event for event in events if tlsOf(event).get('grade_changed')]

	remaining = []
	for event in events:
		days = tlsOf(event).get('certificate_days_remaining')
		if days:
			remaining.append((event, min(days)))

	states = Counter()
	openPorts = Counter()
	for event in events:
		for port in exposureOf(event).get('open_ports') or []:
			openPorts[port] += 1
		for service in exposureOf(event).get('services') or []:
			port, separator, state = service.partition(':')
			if separator and port.isdigit():
				states[(int(port), state)] += 1

	findingCounts = Counter(code for event in events for code in tlsOf(event).get('findings') or [])
	opened = Counter(code for event in events for code in tlsOf(event).get('findings_opened') or [])
	resolved = Counter(code for event in events for code in tlsOf(event).get('findings_resolved') or [])
	codes = sorted(
		set(findingCounts) | set(opened) | set(resolved),
		key=lambda code: (severityRank(findingSeverity(code)), -findingCounts[code], code),
	)
	caaAuthorities = Counter(
		authority
		for event in events
		for authority in (((exposureOf(event).get('dns') or {}).get('caa') or {}).get('authorized_ca') or [])
	)
	return({
		'events': events,
		'changes': Counter(exposureOf(event).get('change') for event in allEvents),
		'has_previous': bool(previous),
		'absent': sorted(
			((domainOf(event), fqdnOf(event)) for event in previous if fqdnOf(event) not in currentNames),
		) if partial else [],
		'new': worstFirst(event for event in events if exposureOf(event).get('change') == 'new'),
		'grades': Counter(gradeOf(event) for event in events),
		'previous_grades': Counter(gradeOf(event) for event in previous),
		'transitions': Counter((tlsOf(event).get('previous_grade'), gradeOf(event)) for event in changed),
		'degraded': [event for event in changed if gradeMove(tlsOf(event).get('previous_grade'), gradeOf(event)) > 0],
		'improved': [event for event in changed if gradeMove(tlsOf(event).get('previous_grade'), gradeOf(event)) < 0],
		'severities': Counter(tlsOf(event).get('max_severity') for event in events if tlsOf(event).get('max_severity')),
		'priorities': worstFirst(
			event for event in events if tlsOf(event).get('max_severity') in ('critical', 'high')
		),
		'kex': Counter(tlsOf(event).get('pqc_kex_status') for event in events if tlsOf(event).get('pqc_kex_status')),
		'kex_groups': Counter(group for event in events for group in tlsOf(event).get('pqc_kex_groups') or []),
		'hybrid_levels': Counter(
			tlsOf(event).get('pqc_hybrid_level') for event in events if tlsOf(event).get('pqc_hybrid_level')
		),
		'certificate_pqc': Counter(
			status for event in events for status in tlsOf(event).get('certificate_pqc_status') or []
		),
		'expired': sorted((item for item in remaining if item[1] < 0), key=lambda item: item[1]),
		'expiring': sorted(
			(item for item in remaining if 0 <= item[1] < asmiraGrade.EXPIRY_WARNING_DAYS),
			key=lambda item: item[1],
		),
		'certificates_changed': sorted(
			fqdnOf(event) for event in events if tlsOf(event).get('certificate_changed')
		),
		'issuers': Counter(
			issuer for event in events for issuer in set(tlsOf(event).get('issuer_organization') or [])
		),
		'caa': Counter(
			((exposureOf(event).get('dns') or {}).get('caa') or {}).get('status') or 'inconnu' for event in events
		),
		'caa_authorities': caaAuthorities,
		'caa_unauthorized': sorted(
			fqdnOf(event) for event in events if tlsOf(event).get('certificate_issuer_authorized') is False
		),
		'findings': [
			{
				'code': code,
				'severity': findingSeverity(code),
				'advice': asmiraGrade.FINDINGS.get(code, ('', None, ''))[2],
				'count': findingCounts[code],
				'opened': opened[code],
				'resolved': resolved[code],
			}
			for code in codes
		],
		'opened_total': sum(opened.values()),
		'resolved_total': sum(resolved.values()),
		'open_ports': openPorts,
		'port_states': states,
		'cleartext': sorted(
			(event for event in events if exposureOf(event).get('cleartext_ports')),
			key=lambda event: fqdnOf(event) or '',
		),
		'rdp': sorted(fqdnOf(event) for event in events if 'RDP_EXPOSED' in (tlsOf(event).get('findings') or [])),
		'asn': Counter(asnOf(event) for event in events),
		'countries': Counter(countryOf(event) for event in events),
		'domains': analyseDomains(events),
	})


def attentionPoints(analysis):
	"""Points d’attention, du plus grave au moins grave : (niveau, texte)."""
	run = analysis['run']
	exposure = analysis['exposure']
	points = []
	if run.get('status') != 'success':
		points.append(('critical', f'Le run a échoué : {run.get("error") or "erreur inconnue"}.'))
	if exposure:
		expired = len(exposure['expired'])
		if expired:
			points.append(('critical', f'{fmt(expired)} FQDN présentent un certificat expiré.'))
		newSevere = [
			event for event in exposure['new']
			if tlsOf(event).get('max_severity') in ('critical', 'high')
		]
		if newSevere:
			points.append((
				'high',
				f'{fmt(len(newSevere))} nouveau(x) FQDN avec un constat critique ou élevé, '
				'à qualifier en priorité (voir « Nouveaux FQDN »).',
			))
		openedSevere = [
			finding for finding in exposure['findings']
			if finding['opened'] and finding['severity'] in ('critical', 'high')
		]
		if openedSevere:
			points.append(('high', 'Constats critiques ou élevés apparus depuis le run précédent : ' + ', '.join(
				f'{finding["code"]} ({fmt(finding["opened"])})' for finding in openedSevere
			) + '.'))
		if exposure['expiring']:
			points.append((
				'high',
				f'{fmt(len(exposure["expiring"]))} certificat(s) expirent dans moins de '
				f'{asmiraGrade.EXPIRY_WARNING_DAYS} jours.',
			))
		if exposure['rdp']:
			points.append(('high', f'{fmt(len(exposure["rdp"]))} FQDN exposent le bureau à distance (RDP).'))
		if exposure['caa_unauthorized']:
			points.append((
				'high',
				f'{fmt(len(exposure["caa_unauthorized"]))} certificat(s) émis par une autorité que le CAA '
				'n’autorise pas : leur prochain renouvellement échouera.',
			))
		if exposure['degraded']:
			points.append(('medium', f'{fmt(len(exposure["degraded"]))} FQDN ont vu leur note se dégrader.'))
		if exposure['cleartext']:
			points.append((
				'medium',
				f'{fmt(len(exposure["cleartext"]))} FQDN exposent un service sans chiffrement (hors port 80).',
			))
	if run.get('partial'):
		reasons = run.get('coverage_reasons') or []
		points.append((
			'medium',
			f'Run partiel ({fmt(len(reasons))} raison(s), détail dans « Exécution ») : les FQDN observés '
			'sont à jour, mais aucune disparition n’est déclarée.',
		))
	sources = analysis['sources']
	if sources['active_enabled'] and sources['active_only']:
		points.append((
			'info',
			f'Amass et dnsx ont trouvé {fmt(len(sources["active_only"]))} FQDN résolus absents de toutes '
			'les sources passives.',
		))
	if exposure and exposure['resolved_total']:
		points.append(('info', f'{fmt(exposure["resolved_total"])} constat(s) corrigé(s) depuis le run précédent.'))
	return(sorted(points, key=lambda point: severityRank(point[0])))


def analyseRun(runEvent, discoveryResult=None, exposureEvents=None, previousEvents=None):
	run = runEvent.get('asmira', {}).get('run', {})
	discoveryReport = (discoveryResult or {}).get('report') or {}
	discoveryDuration = discoveryReport.get('duration_seconds')
	totalDuration = run.get('duration_seconds')
	analysis = {
		'run': run,
		'probe': runEvent.get('observer', {}).get('hostname'),
		'durations': {
			'total': totalDuration,
			'discovery': discoveryDuration,
			'mapping': (
				totalDuration - discoveryDuration
				if exposureEvents is not None and totalDuration is not None and discoveryDuration is not None
				else None
			),
		},
		'sources': analyseSources(discoveryResult),
		'exposure': (
			None if exposureEvents is None
			else analyseExposure(exposureEvents, previousEvents, run.get('partial'))
		),
	}
	analysis['attention'] = attentionPoints(analysis)
	return(analysis)


# --- Mise en forme commune ---------------------------------------------------

def fmt(value):
	"""Entier avec séparateur de milliers (espace fine insécable)."""
	if value is None:
		return('—')
	return(f'{value:,}'.replace(',', ' '))


def fmtOrBlank(value):
	return(fmt(value) if value else '')


def percent(part, total):
	return('—' if not total else f'{round(100 * part / total)} %')


def formatDuration(seconds):
	if seconds is None:
		return('—')
	seconds = int(round(seconds))
	hours, remainder = divmod(seconds, 3600)
	minutes, seconds = divmod(remainder, 60)
	if hours:
		return(f'{hours} h {minutes:02d}')
	if minutes:
		return(f'{minutes} min {seconds:02d} s')
	return(f'{seconds} s')


def localTime(value):
	"""Horodatage ISO → « 2 oct. 2026 à 20:06 » (heure de Paris si disponible)."""
	if not value:
		return('—')
	try:
		moment = datetime.fromisoformat(str(value).replace('Z', '+00:00'))
	except ValueError:
		return(str(value))
	if moment.tzinfo is None:
		moment = moment.replace(tzinfo=timezone.utc)
	try:
		from zoneinfo import ZoneInfo
		moment = moment.astimezone(ZoneInfo(TIMEZONE_NAME))
	except Exception:
		moment = moment.astimezone(timezone.utc)
	return(f'{moment.day} {MONTHS[moment.month - 1]} {moment.year} à {moment:%H:%M}')


def statusLabel(run):
	if run.get('status') != 'success':
		return('échec')
	return('succès partiel' if run.get('partial') else 'succès')


def reportSubject(analysis):
	run = analysis['run']
	counts = run.get('counts', {})
	return(f'[ASMIRA] Run {run.get("id")} : {statusLabel(run)}, {fmt(counts.get("fqdns", 0))} FQDN')


def gradeLine(grades):
	return(' · '.join(
		f'{grade} {fmt(grades[grade])}' for grade in GRADE_COLUMNS if grades.get(grade) and grade != NO_GRADE
	))


# --- Résumé texte (corps de l’e-mail) ---------------------------------------

def renderSummary(analysis):
	run = analysis['run']
	counts = run.get('counts', {})
	durations = analysis['durations']
	exposure = analysis['exposure']
	lines = [
		f'ASMIRA — bilan du run {run.get("id")} (sonde {analysis.get("probe") or "?"})',
		'',
		f'Statut : {statusLabel(run)}.',
		f'Période : du {localTime(run.get("started_at"))} au {localTime(run.get("finished_at"))}, '
		f'soit {formatDuration(durations["total"])} '
		f'(découverte {formatDuration(durations["discovery"])}, '
		f'cartographie {formatDuration(durations["mapping"])}).',
	]
	if exposure:
		changes = exposure['changes']
		lines += [
			f'Surface : {fmt(counts.get("fqdns", 0))} FQDN, dont {fmt(changes.get("new", 0))} nouveaux, '
			f'{fmt(changes.get("updated", 0))} modifiés et {fmt(changes.get("disappeared", 0))} disparus.',
			f'Notes TLS : {gradeLine(exposure["grades"])} ; '
			f'{fmt(exposure["grades"].get(NO_GRADE, 0))} FQDN sans port ouvert.',
			f'Constats : {fmt(exposure["severities"].get("critical", 0))} FQDN au niveau critique, '
			f'{fmt(exposure["severities"].get("high", 0))} au niveau élevé ; '
			f'{fmt(exposure["opened_total"])} apparus, {fmt(exposure["resolved_total"])} corrigés.',
			f'Post-quantique : {fmt(exposure["kex"].get("hybrid", 0))} FQDN en échange de clés hybride '
			f'({percent(exposure["kex"].get("hybrid", 0), sum(exposure["kex"].values()))} des FQDN en TLS).',
			f'Certificats : {fmt(len(exposure["expired"]))} expirés, {fmt(len(exposure["expiring"]))} expirent '
			f'sous {asmiraGrade.EXPIRY_WARNING_DAYS} jours.',
		]
	else:
		lines.append(
			f'Découverte : {fmt(counts.get("resolvable_hosts", 0))} FQDN résolus ; pas de cartographie active.'
		)
	if analysis['attention']:
		lines += ['', 'Points d’attention :']
		lines += [f'- {text}' for unused, text in analysis['attention'][:8]]
	lines += [
		'',
		'Le bilan détaillé est joint : fichier HTML autonome, à ouvrir dans un navigateur.',
		'Il décrit la surface d’attaque de l’organisation : ne pas le transférer hors des destinataires prévus.',
	]
	return('\n'.join(lines) + '\n')


# --- Rapport HTML -------------------------------------------------------------

class Html(str):
	"""Fragment HTML déjà échappé."""


def esc(value):
	if isinstance(value, Html):
		return(value)
	return(html.escape('' if value is None else str(value), quote=True))


def gradeSlug(grade):
	return({'A+': 'ap', 'A-': 'am', NO_GRADE: 'none', asmiraGrade.NOT_GRADED: 'na'}.get(grade, str(grade).lower()))


def gradeBadge(grade):
	return(Html(f'<span class="badge g-{gradeSlug(grade)}">{esc(grade)}</span>'))


def severityBadge(severity):
	if not severity:
		return(Html('<span class="muted">—</span>'))
	return(Html(f'<span class="badge s-{esc(severity)}">{esc(SEVERITY_LABELS.get(severity, severity))}</span>'))


def codeList(values):
	return(Html(' '.join(f'<code>{esc(value)}</code>' for value in values) or '<span class="muted">—</span>'))


def table(headers, rows, numeric=(), caption=None):
	"""Tableau HTML ; numeric liste les index de colonnes alignées à droite."""
	numeric = set(numeric)

	def attributes(index):
		return(' class="num"' if index in numeric else '')

	head = ''.join(f'<th{attributes(index)}>{esc(header)}</th>' for index, header in enumerate(headers))
	body = ''.join(
		'<tr>' + ''.join(f'<td{attributes(index)}>{esc(value)}</td>' for index, value in enumerate(row)) + '</tr>'
		for row in rows
	)
	captionHtml = f'<caption>{esc(caption)}</caption>' if caption else ''
	return(Html(f'<div class="table"><table>{captionHtml}<thead><tr>{head}</tr></thead><tbody>{body}</tbody></table></div>'))


def collapsible(title, content, count, maxItems, isOpen=False):
	"""Liste longue repliée ; mention des éléments non affichés."""
	more = f'<p class="muted">… et {fmt(count - maxItems)} autre(s), consultables dans Kibana.</p>' if count > maxItems else ''
	return(Html(
		f'<details{" open" if isOpen else ""}><summary>{esc(title)} ({fmt(count)})</summary>{content}{more}</details>'
	))


def shorten(text, limit):
	text = str(text)
	return(text if len(text) <= limit else text[:limit - 1] + '…')


def barChart(rows, label, width=720, barClass='bar'):
	"""Barres horizontales : rows = [(libellé, valeur, classe CSS facultative)]."""
	rows = [row if len(row) == 3 else (row[0], row[1], barClass) for row in rows]
	if not rows:
		return(Html(''))
	labelWidth, valueWidth, rowHeight = 210, 70, 24
	barWidth = width - labelWidth - valueWidth
	maximum = max(value for unused, value, unused2 in rows) or 1
	height = rowHeight * len(rows) + 4
	parts = [
		f'<svg class="chart" viewBox="0 0 {width} {height}" role="img" aria-label="{esc(label)}">'
	]
	for index, (name, value, cssClass) in enumerate(rows):
		y = index * rowHeight + 2
		length = max(value / maximum * barWidth, 1 if value else 0)
		parts.append(
			f'<text class="lbl" x="{labelWidth - 8}" y="{y + 16}" text-anchor="end">{esc(shorten(name, 28))}'
			f'<title>{esc(name)}</title></text>'
			f'<rect class="{esc(cssClass)}" x="{labelWidth}" y="{y + 3}" width="{length:.1f}" height="{rowHeight - 8}" rx="3"/>'
			f'<text class="val" x="{labelWidth + length + 6:.1f}" y="{y + 16}">{esc(fmt(value))}</text>'
		)
	parts.append('</svg>')
	return(Html(''.join(parts)))


def stackedChart(rows, segments, label, normalize=True, width=720):
	"""Barres empilées : rows = [(libellé, Counter)], segments = [(clé, libellé, classe)]."""
	if not rows:
		return(Html(''))
	labelWidth, totalWidth, rowHeight = 210, 70, 26
	barWidth = width - labelWidth - totalWidth
	maximum = max(sum(counts.get(key, 0) for key, unused, unused2 in segments) for unused, counts in rows) or 1
	height = rowHeight * len(rows) + 4
	parts = [f'<svg class="chart" viewBox="0 0 {width} {height}" role="img" aria-label="{esc(label)}">']
	for index, (name, counts) in enumerate(rows):
		y = index * rowHeight + 2
		total = sum(counts.get(key, 0) for key, unused, unused2 in segments)
		scale = barWidth / (total if normalize else maximum) if total else 0
		x = labelWidth
		parts.append(
			f'<text class="lbl" x="{labelWidth - 8}" y="{y + 17}" text-anchor="end">{esc(shorten(name, 28))}'
			f'<title>{esc(name)}</title></text>'
		)
		for key, segmentLabel, cssClass in segments:
			value = counts.get(key, 0)
			if not value:
				continue
			length = value * scale
			parts.append(
				f'<rect class="{esc(cssClass)}" x="{x:.1f}" y="{y + 3}" width="{length:.1f}" height="{rowHeight - 8}">'
				f'<title>{esc(name)} — {esc(segmentLabel)} : {esc(fmt(value))}</title></rect>'
			)
			x += length
		parts.append(f'<text class="val" x="{x + 6:.1f}" y="{y + 17}">{esc(fmt(total))}</text>')
	parts.append('</svg>')
	legend = ''.join(
		f'<span><i class="{esc(cssClass)}"></i>{esc(segmentLabel)}</span>'
		for key, segmentLabel, cssClass in segments
		if any(counts.get(key) for unused, counts in rows)
	)
	return(Html(''.join(parts) + f'<div class="legend">{legend}</div>'))


GRADE_SEGMENTS = [(grade, GRADE_LABELS.get(grade, grade), f'g-{gradeSlug(grade)}') for grade in GRADE_COLUMNS]
SERVICE_SEGMENTS = [(state, label, f'st-{state}') for state, label in SERVICE_STATES]
KEX_SEGMENTS = [(state, label, f'kx-{state}') for state, label in KEX_STATES]


def kpi(value, label, tone=''):
	return(Html(f'<div class="kpi {esc(tone)}"><b>{esc(value)}</b><span>{esc(label)}</span></div>'))


def section(anchor, title, *content):
	return(Html(f'<section id="{esc(anchor)}"><h2>{esc(title)}</h2>{"".join(esc(part) for part in content)}</section>'))


def paragraph(text):
	return(Html(f'<p>{esc(text)}</p>'))


def renderSynthesis(analysis):
	run = analysis['run']
	counts = run.get('counts', {})
	exposure = analysis['exposure']
	cards = [kpi(fmt(counts.get('fqdns') or counts.get('resolvable_hosts', 0)), 'FQDN exposés')]
	if exposure:
		graded = sum(exposure['grades'].get(grade, 0) for grade in asmiraGrade.GRADE_ORDER)
		good = sum(exposure['grades'].get(grade, 0) for grade in GOOD_GRADES)
		cards += [
			kpi(fmt(exposure['changes'].get('new', 0)), 'nouveaux FQDN', 'warn' if exposure['changes'].get('new') else ''),
			kpi(percent(good, graded), 'des FQDN notés en A+, A ou A-'),
			kpi(fmt(exposure['severities'].get('critical', 0)), 'FQDN au niveau critique', 'bad'),
			kpi(fmt(len(exposure['expired'])), 'certificats expirés', 'bad' if exposure['expired'] else ''),
			kpi(
				percent(exposure['kex'].get('hybrid', 0), sum(exposure['kex'].values())),
				'des FQDN TLS en échange hybride post-quantique',
			),
		]
	cards.append(kpi(fmt(len(analysis['sources']['failures'])), 'sources incomplètes',
		'warn' if analysis['sources']['failures'] else ''))
	points = ''.join(
		f'<li class="pt-{esc(level)}">{esc(text)}</li>' for level, text in analysis['attention']
	) or '<li class="pt-info">Aucun point bloquant relevé automatiquement.</li>'
	return(section(
		'synthese', 'Synthèse',
		Html(f'<div class="kpis">{"".join(cards)}</div>'),
		Html('<h3>Points d’attention</h3>'),
		Html(f'<ul class="points">{points}</ul>'),
	))


def renderExecution(analysis):
	run = analysis['run']
	counts = run.get('counts', {})
	durations = analysis['durations']
	parts = [
		paragraph(
			f'Le run a démarré le {localTime(run.get("started_at"))} et s’est terminé le '
			f'{localTime(run.get("finished_at"))}, soit {formatDuration(durations["total"])}. '
			f'Statut : {statusLabel(run)}.'
		),
		table(('Phase', 'Durée'), (
			('Découverte : collecte multisource, validation DNS, wildcard et CAA', formatDuration(durations['discovery'])),
			('Cartographie active et consolidation par FQDN', formatDuration(durations['mapping'])),
			('Total', formatDuration(durations['total'])),
		), numeric=(1,)),
		table(('Compteur', 'Valeur'), (
			('Domaines surveillés', fmt(counts.get('domains', 0))),
			('Noms candidats collectés', fmt(counts.get('candidates', 0))),
			('Noms explicites (hors motifs wildcard)', fmt(counts.get('inventory', 0))),
			('FQDN résolus', fmt(counts.get('resolvable_hosts', 0))),
			('Couples FQDN/IP analysés', fmt(counts.get('endpoints', 0))),
			('Couples en échec', fmt(counts.get('failed_endpoints', 0))),
			('FQDN déclarés disparus', fmt(counts.get('disappeared_fqdns', 0))),
		), numeric=(1,)),
	]
	if run.get('error'):
		parts.append(Html(f'<p class="alert">Erreur : <code>{esc(run["error"])}</code></p>'))
	if run.get('partial'):
		parts.append(paragraph(
			'Le run est partiel : au moins une source n’a pas abouti ou le nombre de couples analysés était '
			'plafonné. Les FQDN observés sont mis à jour normalement, mais aucun FQDN n’est déclaré disparu, '
			'pour ne pas confondre une panne de source avec un retrait réel.'
		))
		parts.append(Html('<p>Raisons : ' + codeList(run.get('coverage_reasons') or []) + '</p>'))
	return(section('execution', '1. Exécution', *parts))


def renderSources(analysis, maxItems):
	sources = analysis['sources']
	if not sources['reports']:
		return(Html(''))
	byKey = {(report.get('domain'), report.get('source')): report for report in sources['reports']}
	rows = []
	for domain in sources['domains']:
		row = [domain]
		for source in sources['names']:
			report = byKey.get((domain, source))
			if report is None:
				row.append('')
			elif report.get('status') == 'skipped':
				row.append(Html('<span class="cell skip">ignorée</span>'))
			else:
				failed = report.get('status') != 'success'
				row.append(Html(
					f'<span class="cell{" fail" if failed else ""}" title="{esc(report.get("error") or "")}">'
					f'<b>{esc(fmt(report.get("count", 0)))}</b> <small>{esc(formatDuration(report.get("duration_seconds")))}</small></span>'
				))
		rows.append(row)
	parts = [
		paragraph(
			'Nombre de noms rapportés par chaque source pour chaque domaine, et durée de la collecte. '
			'Une case rouge signale une source incomplète : les noms déjà obtenus sont conservés, '
			'mais le run devient partiel.'
		),
		table(['Domaine', *sources['names']], rows),
	]
	if sources['failures']:
		parts.append(Html('<h3>Sources incomplètes</h3>'))
		parts.append(table(('Domaine', 'Source', 'Statut', 'Noms conservés', 'Diagnostic'), [
			(report.get('domain'), report.get('source'), report.get('status'), fmt(report.get('count', 0)), report.get('error'))
			for report in sources['failures']
		], numeric=(3,)))
	if sources['contribution']:
		parts += [
			Html('<h3>Apport de chaque source</h3>'),
			paragraph(
				'« Vus par elle seule » compte les noms qu’aucune autre source n’a rapportés : c’est la mesure '
				'de l’apport réel d’une source. Les noms non résolus sont souvent historiques.'
			),
			barChart(
				[(row['source'], row['unique_resolved'], 'bar') for row in sources['contribution']],
				'FQDN résolus vus par une seule source',
			),
			table(('Source', 'Noms', 'Résolus', 'Vus par elle seule', 'Dont résolus'), [
				(row['source'], fmt(row['names']), fmt(row['resolved']), fmt(row['unique']), fmt(row['unique_resolved']))
				for row in sources['contribution']
			], numeric=(1, 2, 3, 4)),
		]
	if sources['active_enabled']:
		activeOnly = sources['active_only']
		parts.append(paragraph(
			f'{fmt(len(activeOnly))} FQDN résolus n’ont été trouvés que par les sources actives Amass et dnsx : '
			'ils n’apparaissent ni dans les journaux de transparence des certificats ni dans les bases passives, '
			'et correspondent souvent à des services internes ou oubliés.'
		))
		if activeOnly:
			parts.append(collapsible(
				'FQDN trouvés uniquement par Amass et dnsx',
				Html('<p class="names">' + codeList(activeOnly[:maxItems]) + '</p>'),
				len(activeOnly), maxItems,
			))
	return(section('sources', '2. Sources de découverte', *parts))


def fqdnRows(events):
	return([
		(
			fqdnOf(event),
			gradeBadge(gradeOf(event)),
			severityBadge(tlsOf(event).get('max_severity')),
			codeList(exposureOf(event).get('services') or []),
			codeList(tlsOf(event).get('findings') or []),
		)
		for event in events
	])


FQDN_HEADERS = ('FQDN', 'Note', 'Sévérité', 'Services', 'Constats')


def renderSurface(analysis, maxItems):
	exposure = analysis['exposure']
	changes = exposure['changes']
	parts = [
		Html('<div class="kpis small">' + ''.join(
			kpi(fmt(changes.get(change, 0)), label) for change, label in CHANGE_LABELS
		) + '</div>'),
		paragraph(
			'Un FQDN est « modifié » lorsque son état comparable change : ports, certificat, note, constats. '
			'« Inchangé » ignore les seules variations de date.'
		),
	]
	if exposure['absent']:
		byDomain = Counter(domain for domain, unused in exposure['absent'])
		parts.append(paragraph(
			f'{fmt(len(exposure["absent"]))} FQDN du run précédent n’ont pas été revus. Le run étant partiel, '
			'ils ne sont pas déclarés disparus : ils peuvent n’avoir été rapportés que par une source '
			'incomplète cette fois. Par domaine : '
			+ ', '.join(f'{domain} ({fmt(count)})' for domain, count in byDomain.most_common()) + '.'
		))
		parts.append(collapsible(
			'FQDN non revus',
			Html('<p class="names">' + codeList(name for unused, name in exposure['absent'][:maxItems]) + '</p>'),
			len(exposure['absent']), maxItems,
		))
	parts.append(Html('<h3>Par domaine</h3>'))
	parts.append(stackedChart(
		[(row['domain'], row['grades']) for row in exposure['domains']],
		GRADE_SEGMENTS, 'Répartition des notes par domaine',
	))
	parts.append(table(
		('Domaine', 'FQDN', 'Nouveaux', 'Notés', 'A+ à A-', 'Critiques', 'Cert. expirés', 'PQC hybride', 'CAA'),
		[
			(
				row['domain'], fmt(row['fqdns']), fmt(row['new']), fmt(row['graded']),
				percent(row['good'], row['graded']), fmt(row['critical']), fmt(row['expired']),
				percent(row['hybrid'], row['tls']), percent(row['caa'], row['fqdns']),
			)
			for row in exposure['domains']
		],
		numeric=(1, 2, 3, 4, 5, 6, 7, 8),
	))
	if exposure['new']:
		parts += [
			Html(f'<h3>Nouveaux FQDN ({fmt(len(exposure["new"]))})</h3>'),
			paragraph('Classés du plus grave au moins grave. Un nouveau FQDN est à qualifier : service attendu, oublié ou non maîtrisé.'),
			collapsible('Nouveaux FQDN', table(FQDN_HEADERS, fqdnRows(exposure['new'][:maxItems])),
				len(exposure['new']), maxItems, isOpen=True),
		]
	if exposure['priorities']:
		parts += [
			Html('<h3>FQDN à traiter en priorité</h3>'),
			paragraph('FQDN dont le constat le plus grave est critique ou élevé, du plus grave au moins grave.'),
			collapsible('FQDN prioritaires', table(FQDN_HEADERS, fqdnRows(exposure['priorities'][:maxItems])),
				len(exposure['priorities']), maxItems),
		]
	return(section('surface', '3. Surface exposée', *parts))


def renderTls(analysis, maxItems):
	exposure = analysis['exposure']
	grades = exposure['grades']
	rows = [('Ce run', grades)]
	if exposure['has_previous']:
		rows.append(('Run précédent', exposure['previous_grades']))
	parts = [
		paragraph(
			'La note est celle de l’adresse IP la plus faible du FQDN, selon le modèle de notation '
			f'v{asmiraGrade.GRADE_VERSION} inspiré de SSL Labs. T : certificat non fiable (expiré, auto-signé, '
			'chaîne incomplète) ; M : certificat qui ne couvre pas le nom ; NA : TLS non évaluable ; '
			'— : aucun port ouvert.'
		),
		stackedChart(rows, GRADE_SEGMENTS, 'Répartition des notes', normalize=False),
		table(
			['Note', 'Ce run', *(['Run précédent', 'Écart'] if exposure['has_previous'] else [])],
			[
				[
					gradeBadge(grade), fmt(grades.get(grade, 0)),
					*([
						fmt(exposure['previous_grades'].get(grade, 0)),
						f'{grades.get(grade, 0) - exposure["previous_grades"].get(grade, 0):+d}',
					] if exposure['has_previous'] else []),
				]
				for grade in GRADE_COLUMNS
				if grades.get(grade) or exposure['previous_grades'].get(grade)
			],
			numeric=(1, 2, 3),
		),
	]
	if exposure['transitions']:
		parts.append(paragraph(
			f'{fmt(sum(exposure["transitions"].values()))} changement(s) de note : '
			+ ', '.join(
				f'{before} → {after} ({fmt(count)})'
				for (before, after), count in exposure['transitions'].most_common(12)
			)
			+ '. Les passages vers ou depuis NA traduisent souvent une poignée de main TLS instable plutôt '
			'qu’un vrai changement de configuration.'
		))
	for title, events in (('Notes dégradées', exposure['degraded']), ('Notes améliorées', exposure['improved'])):
		if events:
			parts.append(collapsible(title, table(
				('FQDN', 'Avant', 'Après', 'Constats'),
				[
					(fqdnOf(event), gradeBadge(tlsOf(event).get('previous_grade')), gradeBadge(gradeOf(event)),
						codeList(tlsOf(event).get('findings') or []))
					for event in events[:maxItems]
				],
			), len(events), maxItems, isOpen=title == 'Notes dégradées'))

	kexTotal = sum(exposure['kex'].values())
	parts += [
		Html('<h3>Post-quantique</h3>'),
		paragraph(
			'L’ANSSI exige d’associer un algorithme classique à un algorithme post-quantique normalisé : seul '
			'un échange de clés hybride (X25519MLKEM768, SecP256r1MLKEM768, SecP384r1MLKEM1024) est conforme. '
			f'{fmt(exposure["kex"].get("hybrid", 0))} des {fmt(kexTotal)} FQDN évalués '
			f'({percent(exposure["kex"].get("hybrid", 0), kexTotal)}) le proposent.'
		),
		stackedChart([('Échange de clés', exposure['kex'])], KEX_SEGMENTS, 'Échange de clés post-quantique'),
	]
	if exposure['kex_groups']:
		parts.append(table(('Groupe ML-KEM accepté', 'Type', 'FQDN'), [
			(group, 'hybride' if group in asmiraGrade.PQC_HYBRID_KEX_GROUPS else 'ML-KEM seul', fmt(count))
			for group, count in exposure['kex_groups'].most_common()
		], numeric=(2,)))
	if exposure['certificate_pqc']:
		parts.append(paragraph('Signature des certificats : ' + ', '.join(
			f'{CERTIFICATE_PQC_LABELS.get(status, status)} ({fmt(count)})'
			for status, count in exposure['certificate_pqc'].most_common()
		) + '. Aucune autorité publique n’émet encore de certificat ML-DSA.'))
	return(section('tls', '4. État TLS et post-quantique', *parts))


def renderCertificates(analysis, maxItems):
	exposure = analysis['exposure']
	parts = [
		Html('<div class="kpis small">' + ''.join((
			kpi(fmt(len(exposure['expired'])), 'expirés', 'bad' if exposure['expired'] else ''),
			kpi(fmt(len(exposure['expiring'])), f'expirent sous {asmiraGrade.EXPIRY_WARNING_DAYS} jours',
				'warn' if exposure['expiring'] else ''),
			kpi(fmt(len(exposure['certificates_changed'])), 'changés depuis le run précédent'),
			kpi(fmt(len(exposure['caa_unauthorized'])), 'émetteurs refusés par le CAA',
				'bad' if exposure['caa_unauthorized'] else ''),
		)) + '</div>'),
	]
	if exposure['expiring']:
		parts.append(collapsible('Expiration prochaine', table(
			('FQDN', 'Jours restants'), [(fqdnOf(event), fmt(days)) for event, days in exposure['expiring'][:maxItems]],
			numeric=(1,),
		), len(exposure['expiring']), maxItems, isOpen=True))
	if exposure['expired']:
		parts.append(collapsible('Certificats expirés', table(
			('FQDN', 'Expiré depuis (jours)'), [(fqdnOf(event), fmt(-days)) for event, days in exposure['expired'][:maxItems]],
			numeric=(1,),
		), len(exposure['expired']), maxItems))
	if exposure['issuers']:
		parts += [
			Html('<h3>Autorités émettrices</h3>'),
			barChart(
				[(issuer, count) for issuer, count in exposure['issuers'].most_common(12)],
				'FQDN par autorité émettrice',
			),
		]
	caaTotal = sum(exposure['caa'].values())
	parts += [
		Html('<h3>CAA</h3>'),
		paragraph(
			'L’enregistrement CAA désigne les autorités autorisées à émettre pour un nom : c’est le prérequis '
			'd’un déploiement ACME maîtrisé. '
			f'{fmt(exposure["caa"].get("present", 0))} FQDN sur {fmt(caaTotal)} '
			f'({percent(exposure["caa"].get("present", 0), caaTotal)}) en ont un effectif.'
		),
	]
	if exposure['caa_authorities']:
		parts.append(table(('Autorité autorisée par le CAA', 'FQDN'), [
			(authority, fmt(count)) for authority, count in exposure['caa_authorities'].most_common(12)
		], numeric=(1,)))
	if exposure['caa_unauthorized']:
		parts.append(Html('<p>Certificat émis par une autorité non autorisée : '
			+ codeList(exposure['caa_unauthorized'][:maxItems]) + '</p>'))
	return(section('certificats', '5. Certificats et CAA', *parts))


def renderFindings(analysis):
	exposure = analysis['exposure']
	if not exposure['findings']:
		return(Html(''))
	return(section(
		'constats', '6. Constats',
		paragraph(
			'Nombre de FQDN concernés par chaque constat, du plus grave au moins grave, avec les constats '
			'apparus et corrigés depuis le run précédent et la correction recommandée.'
		),
		barChart(
			[(finding['code'], finding['count'], f's-{finding["severity"]}') for finding in exposure['findings'] if finding['count']],
			'FQDN par constat',
		),
		table(('Constat', 'Sévérité', 'FQDN', 'Apparus', 'Corrigés', 'Correction recommandée'), [
			(
				Html(f'<code>{esc(finding["code"])}</code>'), severityBadge(finding['severity']),
				fmt(finding['count']), fmtOrBlank(finding['opened']),
				fmtOrBlank(finding['resolved']), finding['advice'],
			)
			for finding in exposure['findings']
		], numeric=(2, 3, 4)),
	))


def renderPorts(analysis, maxItems):
	exposure = analysis['exposure']
	if not exposure['open_ports']:
		return(Html(''))
	rows = [
		(f'port {port}', Counter({state: exposure['port_states'].get((port, state), 0) for state, unused in SERVICE_STATES}))
		for port in sorted(exposure['open_ports'])
	]
	parts = [
		paragraph(
			'Chiffrement constaté sur chaque port ouvert. Un port n’est classé en clair que sur preuve ; '
			'« Indéterminé » signale un port qui accepte la connexion sans répondre, fréquent derrière un CDN. '
			'Le port 80 est du HTTP en clair par nature ; un 8080 qui redirige vers HTTPS est classé « Redirection HTTPS ».'
		),
		stackedChart(rows, SERVICE_SEGMENTS, 'Chiffrement par port', normalize=False),
		table(['Port', 'FQDN ouverts', *[label for unused, label in SERVICE_STATES]], [
			[port, fmt(exposure['open_ports'][port]),
				*[fmtOrBlank(exposure['port_states'].get((port, state), 0)) for state, unused in SERVICE_STATES]]
			for port in sorted(exposure['open_ports'])
		], numeric=tuple(range(1, len(SERVICE_STATES) + 2))),
	]
	if exposure['cleartext']:
		parts.append(collapsible('Services sans chiffrement', table(
			('FQDN', 'Ports en clair', 'Hébergement'),
			[
				(fqdnOf(event), ', '.join(str(port) for port in exposureOf(event)['cleartext_ports']), asnOf(event))
				for event in exposure['cleartext'][:maxItems]
			],
		), len(exposure['cleartext']), maxItems))
	if exposure['rdp']:
		parts.append(Html('<p class="alert">RDP exposé : ' + codeList(exposure['rdp'][:maxItems]) + '</p>'))
	parts += [
		Html('<h3>Hébergement</h3>'),
		Html('<div class="cols">'),
		barChart(exposure['asn'].most_common(10), 'FQDN par opérateur (ASN)', width=520),
		barChart(exposure['countries'].most_common(10), 'FQDN par pays', width=520),
		Html('</div>'),
	]
	return(section('ports', '7. Ports, chiffrement et hébergement', *parts))


STYLE = """
:root{--bg:#f6f7f9;--card:#fff;--ink:#1d2330;--muted:#677084;--line:#dde1e8;--accent:#2f5bd3;
--good:#1f8a4c;--warn:#c27a00;--bad:#c62f2f;--soft:#eef1f6}
@media (prefers-color-scheme:dark){:root{--bg:#12151b;--card:#1a1e26;--ink:#e6e9ef;--muted:#9aa3b5;
--line:#2c323e;--accent:#7d9cff;--soft:#222834}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.55 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
main{max-width:1120px;margin:0 auto;padding:24px 16px 64px}
header{display:flex;flex-wrap:wrap;gap:12px 24px;align-items:baseline;justify-content:space-between;margin-bottom:8px}
h1{font-size:26px;margin:0}h2{font-size:20px;margin:0 0 12px;padding-bottom:6px;border-bottom:2px solid var(--line)}
h3{font-size:16px;margin:22px 0 8px}
.meta{color:var(--muted);font-size:14px}
.status{display:inline-block;padding:3px 10px;border-radius:999px;font-weight:600;font-size:13px;color:#fff;background:var(--good)}
.status.partial{background:var(--warn)}.status.failed{background:var(--bad)}
.notice{background:var(--soft);border-left:4px solid var(--warn);padding:8px 12px;font-size:13px;color:var(--muted);margin:12px 0 20px}
nav{display:flex;flex-wrap:wrap;gap:6px 14px;font-size:14px;margin:0 0 20px}
nav a{color:var(--accent);text-decoration:none}
section{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:18px 20px;margin:0 0 18px}
.kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:10px;margin:4px 0 8px}
.kpi{background:var(--soft);border-radius:8px;padding:10px 12px;border-top:3px solid var(--accent)}
.kpi b{display:block;font-size:24px;line-height:1.2}.kpi span{font-size:13px;color:var(--muted)}
.kpi.bad{border-top-color:var(--bad)}.kpi.warn{border-top-color:var(--warn)}
.kpis.small .kpi b{font-size:20px}
.points{list-style:none;padding:0;margin:0}
.points li{padding:7px 10px 7px 14px;border-left:4px solid var(--muted);margin:6px 0;background:var(--soft);border-radius:0 6px 6px 0}
.points .pt-critical{border-left-color:var(--bad)}.points .pt-high{border-left-color:#e0662b}
.points .pt-medium{border-left-color:var(--warn)}.points .pt-info,.points .pt-low{border-left-color:var(--accent)}
.table{overflow-x:auto;margin:10px 0}
table{border-collapse:collapse;width:100%;font-size:13.5px}
th,td{text-align:left;padding:6px 8px;border-bottom:1px solid var(--line);vertical-align:top}
th{font-weight:600;color:var(--muted);white-space:nowrap}
td.num,th.num{text-align:right;white-space:nowrap;font-variant-numeric:tabular-nums}
tbody tr:hover{background:var(--soft)}
code{font:12.5px ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;background:var(--soft);padding:1px 4px;border-radius:4px}
.names code{display:inline-block;margin:2px 2px}
.muted{color:var(--muted)}
.alert{color:var(--bad)}
.cell{white-space:nowrap}.cell small{color:var(--muted)}.cell.fail{color:var(--bad)}.cell.skip{color:var(--muted)}
details{margin:10px 0}summary{cursor:pointer;font-weight:600;color:var(--accent)}
.badge{display:inline-block;min-width:28px;text-align:center;padding:1px 7px;border-radius:5px;font-weight:600;font-size:12.5px;color:#fff}
.chart{width:100%;max-width:780px;height:auto;display:block;margin:8px 0}
.chart .lbl{font-size:12.5px;fill:var(--ink)}.chart .val{font-size:12px;fill:var(--muted)}
.chart .bar{fill:var(--accent)}
.legend{display:flex;flex-wrap:wrap;gap:4px 14px;font-size:12.5px;color:var(--muted);margin:0 0 8px}
.legend i{display:inline-block;width:11px;height:11px;border-radius:2px;margin-right:5px;vertical-align:-1px}
.cols{display:grid;grid-template-columns:repeat(auto-fit,minmax(320px,1fr));gap:12px}
.g-ap{background:#14713d;fill:#14713d}.g-a{background:#2a9a55;fill:#2a9a55}.g-am{background:#6dbb5a;fill:#6dbb5a}
.g-b{background:#b5b52a;fill:#b5b52a}.g-c{background:#e0a020;fill:#e0a020}.g-d,.g-e{background:#e0662b;fill:#e0662b}
.g-f{background:#c62f2f;fill:#c62f2f}.g-t{background:#8a4fc0;fill:#8a4fc0}.g-m{background:#c4508f;fill:#c4508f}
.g-na{background:#8d95a5;fill:#8d95a5}.g-none{background:#c9ced8;fill:#c9ced8;color:#333}
.s-critical{background:#c62f2f;fill:#c62f2f}.s-high{background:#e0662b;fill:#e0662b}.s-medium{background:#e0a020;fill:#e0a020}
.s-low{background:#3f7fd0;fill:#3f7fd0}.s-info{background:#8d95a5;fill:#8d95a5}
.st-tls{fill:#2a9a55;background:#2a9a55}.st-starttls{fill:#6dbb5a;background:#6dbb5a}.st-ssh{fill:#3f7fd0;background:#3f7fd0}
.st-redirect{fill:#7fb3e6;background:#7fb3e6}.st-clear{fill:#c62f2f;background:#c62f2f}.st-inconnu{fill:#c9ced8;background:#c9ced8}
.kx-hybrid{fill:#14713d;background:#14713d}.kx-pure{fill:#e0a020;background:#e0a020}.kx-partial{fill:#6dbb5a;background:#6dbb5a}
.kx-classical{fill:#8d95a5;background:#8d95a5}.kx-no_tls13{fill:#e0662b;background:#e0662b}.kx-unknown{fill:#c9ced8;background:#c9ced8}
footer{color:var(--muted);font-size:12.5px;text-align:center;margin-top:24px}
@media print{body{background:#fff}section{break-inside:avoid-page;border:0;padding:0}nav{display:none}details{display:block}}
"""


def renderHtml(analysis, maxItems=50):
	"""Rapport HTML autonome : aucune ressource externe ni script (CSP stricte)."""
	run = analysis['run']
	statusClass = 'failed' if run.get('status') != 'success' else ('partial' if run.get('partial') else '')
	sections = [renderSynthesis(analysis), renderExecution(analysis), renderSources(analysis, maxItems)]
	navigation = [('synthese', 'Synthèse'), ('execution', 'Exécution'), ('sources', 'Sources')]
	if analysis['exposure']:
		sections += [
			renderSurface(analysis, maxItems), renderTls(analysis, maxItems),
			renderCertificates(analysis, maxItems), renderFindings(analysis), renderPorts(analysis, maxItems),
		]
		navigation += [
			('surface', 'Surface'), ('tls', 'TLS et PQC'), ('certificats', 'Certificats et CAA'),
			('constats', 'Constats'), ('ports', 'Ports et hébergement'),
		]
	links = ''.join(f'<a href="#{esc(anchor)}">{esc(label)}</a>' for anchor, label in navigation)
	return(
		'<!doctype html>\n<html lang="fr"><head><meta charset="utf-8">'
		'<meta name="viewport" content="width=device-width, initial-scale=1">'
		'<meta http-equiv="Content-Security-Policy" content="default-src \'none\'; style-src \'unsafe-inline\'">'
		f'<title>ASMIRA — run {esc(run.get("id"))}</title><style>{STYLE}</style></head><body><main>'
		'<header><div>'
		f'<h1>Bilan ASMIRA</h1><div class="meta">Run <code>{esc(run.get("id"))}</code> · sonde '
		f'{esc(analysis.get("probe") or "?")} · {esc(localTime(run.get("started_at")))} → '
		f'{esc(localTime(run.get("finished_at")))}</div></div>'
		f'<span class="status {statusClass}">{esc(statusLabel(run))}</span></header>'
		'<p class="notice">Ce bilan décrit la surface d’attaque de l’organisation : il est sensible et ne doit pas '
		'être diffusé hors des destinataires prévus.</p>'
		f'<nav>{links}</nav>'
		+ ''.join(sections)
		+ f'<footer>ASMIRA · modèle de notation v{esc(asmiraGrade.GRADE_VERSION)} · '
		'listes limitées par [report] max_items ; le détail complet est dans Kibana.</footer>'
		'</main></body></html>\n'
	)


# --- Envoi --------------------------------------------------------------------

def defaultSender():
	return(f'asmira@{socket.getfqdn()}')


def sendRunReport(summary, reportHtml, analysis, config, smtpFactory=smtplib.SMTP, environ=None):
	"""Envoie le résumé (corps texte) et le bilan HTML (pièce jointe) aux
	destinataires de [report] email_to. Le mot de passe SMTP éventuel vient de
	l’environnement."""
	environ = os.environ if environ is None else environ
	runId = analysis['run'].get('id')
	sender = config.reportEmailFrom or defaultSender()
	message = EmailMessage()
	message['Subject'] = reportSubject(analysis)
	message['From'] = sender
	message['To'] = ', '.join(config.reportEmailTo)
	message['Date'] = email.utils.formatdate(localtime=True)
	message['Message-ID'] = email.utils.make_msgid(domain=sender.rsplit('@', 1)[-1])
	message.set_content(summary, subtype='plain', charset='utf-8')
	message.add_attachment(
		reportHtml.encode('utf-8'),
		maintype='text',
		subtype='html',
		filename=f'asmira_report_{runId}.html',
	)
	password = environ.get(PASSWORD_ENVIRONMENT)
	if config.reportSmtpUsername and not password:
		raise ValueError(f'{PASSWORD_ENVIRONMENT} est requis avec [report] smtp_username')
	with smtpFactory(config.reportSmtpHost, config.reportSmtpPort, timeout=config.reportSmtpTimeout) as smtp:
		if config.reportSmtpStartTls:
			smtp.starttls(context=ssl.create_default_context())
		if config.reportSmtpUsername:
			smtp.login(config.reportSmtpUsername, password)
		smtp.send_message(message)
	return(message)
