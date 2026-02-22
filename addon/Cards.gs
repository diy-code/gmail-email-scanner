/**
 * Cards.gs v3 \u2014 "Sentinel" design system
 *
 * Aesthetic: Industrial security terminal. Terse. Decisive. Color-coded.
 * Every pixel of data earns its place or gets cut.
 *
 * Architecture (matching Code.gs contract):
 *   buildHomepageCard()                   \u2192 onHomepage()
 *   buildInitialCard(subject, sender, id) \u2192 onGmailMessageOpen()
 *   buildResultCard(result)               \u2192 analyzeEmail() success
 *   buildErrorCard(message, detail)       \u2192 analyzeEmail() failure
 *
 * CardService features used:
 *   MaterialIcon \u00B7 DecoratedText \u00B7 TextParagraph \u00B7 Columns
 *   Divider \u00B7 FixedFooter \u00B7 Collapsible sections \u00B7 HTML formatting
 *
 * Constraints: ES5 only \u00B7 ~300px sidebar \u00B7 CardHeader requires URL icons
 * HTML subset: <b> <i> <u> <s> <font color> <a href> <br>
 */


// \u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550
//  DESIGN TOKENS
// \u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550

var C = {
  SAFE:    '#00C853',   // electric green
  WARN:    '#FFD600',   // bright yellow
  DANGER:  '#FF1744',   // hot red
  CRIT:    '#D50000',   // deep red
  HIGH:    '#FF6D00',   // orange
  BLUE:    '#2979FF',   // info blue
  CYAN:    '#00B0FF',   // accent cyan
  MUTE:    '#78909C',   // blue-gray
  FAINT:   '#B0BEC5'    // light gray
};

// CardHeader only accepts icon URLs, not MaterialIcon
var HDR = {
  SHIELD:   'https://www.gstatic.com/images/icons/material/system/2x/security_black_24dp.png',
  VERIFIED: 'https://www.gstatic.com/images/icons/material/system/2x/verified_user_black_24dp.png',
  WARN:     'https://www.gstatic.com/images/icons/material/system/2x/warning_black_24dp.png',
  DANGER:   'https://www.gstatic.com/images/icons/material/system/2x/dangerous_black_24dp.png',
  ERR:      'https://www.gstatic.com/images/icons/material/system/2x/error_black_24dp.png'
};

// Verdict \u2192 display config
var V_IMG    = { SAFE: HDR.VERIFIED, SUSPICIOUS: HDR.WARN, MALICIOUS: HDR.DANGER };
var V_COLOR  = { SAFE: C.SAFE, SUSPICIOUS: C.WARN, MALICIOUS: C.DANGER };
var V_MI     = { SAFE: 'verified_user', SUSPICIOUS: 'warning', MALICIOUS: 'dangerous' };

var V_TITLE  = { SAFE: 'CLEAR', SUSPICIOUS: 'CAUTION', MALICIOUS: 'HOSTILE' };
var V_SUB    = {
  SAFE:       'All signals nominal \u2014 no threats detected',
  SUSPICIOUS: 'Anomalies detected \u2014 exercise caution',
  MALICIOUS:  'Active threat indicators \u2014 do not engage'
};
var V_ACTION = {
  SAFE:       'No action required. This email appears legitimate.',
  SUSPICIOUS: 'Avoid unknown links. Do not share credentials or personal data.',
  MALICIOUS:  'Do NOT click links or download attachments. Report as phishing now.'
};
var V_ACT_ICON = { SAFE: 'check_circle', SUSPICIOUS: 'warning', MALICIOUS: 'block' };

// Icon URL map — URL-based icons are universally supported (MaterialIcon is not)
var ICO = {
  fingerprint:   'https://www.gstatic.com/images/icons/material/system/2x/fingerprint_black_24dp.png',
  link:          'https://www.gstatic.com/images/icons/material/system/2x/link_black_24dp.png',
  dns:           'https://www.gstatic.com/images/icons/material/system/2x/dns_black_24dp.png',
  event:         'https://www.gstatic.com/images/icons/material/system/2x/event_black_24dp.png',
  visibility:    'https://www.gstatic.com/images/icons/material/system/2x/visibility_black_24dp.png',
  person:        'https://www.gstatic.com/images/icons/material/system/2x/person_black_24dp.png',
  mail:          'https://www.gstatic.com/images/icons/material/system/2x/mail_black_24dp.png',
  check_circle:  'https://www.gstatic.com/images/icons/material/system/2x/check_circle_black_24dp.png',
  warning:       'https://www.gstatic.com/images/icons/material/system/2x/warning_black_24dp.png',
  dangerous:     'https://www.gstatic.com/images/icons/material/system/2x/dangerous_black_24dp.png',
  error:         'https://www.gstatic.com/images/icons/material/system/2x/error_black_24dp.png',
  info:          'https://www.gstatic.com/images/icons/material/system/2x/info_black_24dp.png',
  flag:          'https://www.gstatic.com/images/icons/material/system/2x/flag_black_24dp.png',
  block:         'https://www.gstatic.com/images/icons/material/system/2x/block_black_24dp.png',
  auto_awesome:  'https://www.gstatic.com/images/icons/material/system/2x/auto_awesome_black_24dp.png',
  calculate:     'https://www.gstatic.com/images/icons/material/system/2x/calculate_black_24dp.png',
  label:         'https://www.gstatic.com/images/icons/material/system/2x/label_black_24dp.png',
  speed:         'https://www.gstatic.com/images/icons/material/system/2x/speed_black_24dp.png',
  bug_report:    'https://www.gstatic.com/images/icons/material/system/2x/bug_report_black_24dp.png',
  verified_user: 'https://www.gstatic.com/images/icons/material/system/2x/verified_user_black_24dp.png',
  security:      'https://www.gstatic.com/images/icons/material/system/2x/security_black_24dp.png'
};

// Category config
var CAT = {
  header:   { lbl: 'AUTH',     desc: 'SPF \u00B7 DKIM \u00B7 DMARC',          mi: 'fingerprint',    cap: 45 },
  url:      { lbl: 'URLS',     desc: 'VirusTotal \u00B7 Safe Browsing',        mi: 'link',           cap: 40 },
  ip:       { lbl: 'IP REP',   desc: 'AbuseIPDB confidence score',             mi: 'dns',            cap: 20 },
  domain:   { lbl: 'DOMAIN',   desc: 'Registration age analysis',              mi: 'event',          cap: 20 },
  behavior: { lbl: 'BEHAVIOR', desc: 'Social engineering cues',                mi: 'visibility',     cap: 10 }
};
var CAT_ORDER = ['header', 'url', 'ip', 'domain', 'behavior'];


// \u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550
//  CORE HELPERS
// \u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550

/** Icon by name — uses URL-based icons for universal compatibility. */
function mi(name) {
  var url = ICO[name] || ICO.info;
  return CardService.newIconImage().setIconUrl(url);
}

/** HTML bold. */
function b(t) { return '<b>' + t + '</b>'; }

/** HTML font color. */
function fc(t, c) { return '<font color="' + c + '">' + t + '</font>'; }

/** Bold + colored. */
function bc(t, c) { return '<font color="' + c + '"><b>' + t + '</b></font>'; }

/** Score 0-100 \u2192 threat color. */
function sColor(score) {
  if (score <= 25) return C.SAFE;
  if (score <= 55) return C.WARN;
  return C.DANGER;
}

/** Severity string \u2192 color hex. */
function sevColor(sev) {
  switch ((sev || '').toLowerCase()) {
    case 'critical': return C.CRIT;
    case 'high':     return C.HIGH;
    case 'medium':   return C.WARN;
    case 'low':      return C.BLUE;
    default:         return C.MUTE;
  }
}

/** Severity \u2192 icon name (maps to ICO keys). */
function sevMi(sev) {
  switch ((sev || '').toLowerCase()) {
    case 'critical': return 'dangerous';
    case 'high':     return 'warning';
    case 'medium':   return 'flag';
    case 'low':      return 'info';
    default:         return 'info';
  }
}

/** HTML colored severity badge: \u25CF CRITICAL etc. */
function sevTag(sev) {
  var s = (sev || '').toLowerCase();
  var label = (s === 'critical' || s === 'high' || s === 'medium' || s === 'low')
    ? s.toUpperCase() : 'INFO';
  return bc('\u25CF ' + label, sevColor(sev));
}

/** 20-char Unicode score bar with finer resolution than 10-char. */
function scoreBar(score) {
  var n = Math.round(score / 5);
  var bar = '';
  for (var i = 0; i < n; i++) bar += '\u2588';
  for (var j = 0; j < 20 - n; j++) bar += '\u2591';
  return bar;
}

/** Points \u2192 color based on ratio to cap. */
function ptColor(pts, cap) {
  if (cap === 0) return C.MUTE;
  var r = pts / cap;
  return r < 0.25 ? C.SAFE : r < 0.5 ? C.WARN : C.DANGER;
}


// \u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550
//  HOMEPAGE CARD
// \u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550

function buildHomepageCard() {
  var header = CardService.newCardHeader()
    .setTitle('SENTINEL')
    .setSubtitle('Email Threat Intelligence')
    .setImageUrl(HDR.SHIELD)
    .setImageStyle(CardService.ImageStyle.CIRCLE);

  var intro = CardService.newCardSection()
    .addWidget(CardService.newTextParagraph().setText(
      b('Open any email') + ' to initiate a threat scan.' + '<br><br>' +
      fc('Five signal engines analyze each message in parallel. ' +
      'Results include a composite threat score, confidence rating, ' +
      'and AI-generated risk narrative.', C.MUTE)
    ));

  var engines = [
    { n: 'fingerprint',    t: 'Authentication',      d: 'SPF, DKIM, DMARC header validation' },
    { n: 'link',           t: 'URL Intelligence',    d: 'VirusTotal & Google Safe Browsing' },
    { n: 'dns',            t: 'IP Reputation',       d: 'AbuseIPDB confidence scoring' },
    { n: 'event',          t: 'Domain Analysis',     d: 'Registration age & freshness check' },
    { n: 'visibility',     t: 'Behavioral Signals',  d: 'Urgency & social engineering patterns' }
  ];

  var engSec = CardService.newCardSection().setHeader('THREAT INTEL ENGINES');
  for (var i = 0; i < engines.length; i++) {
    if (i > 0) engSec.addWidget(CardService.newDivider());
    engSec.addWidget(
      CardService.newDecoratedText()
        .setText(b(engines[i].t))
        .setBottomLabel(engines[i].d)
        .setStartIcon(mi(engines[i].n))
    );
  }

  return CardService.newCardBuilder()
    .setHeader(header)
    .addSection(intro)
    .addSection(engSec)
    .build();
}


// \u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550
//  INITIAL CARD (pre-scan)
// \u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550

/**
 * @param {string} subject   - Email subject line.
 * @param {string} sender    - From address.
 * @param {string} messageId - Gmail message ID.
 * @return {Card}
 */
function buildInitialCard(subject, sender, messageId) {
  var header = CardService.newCardHeader()
    .setTitle('SENTINEL')
    .setSubtitle('Target acquired')
    .setImageUrl(HDR.SHIELD)
    .setImageStyle(CardService.ImageStyle.CIRCLE);

  var target = CardService.newCardSection()
    .setHeader('TARGET')
    .addWidget(
      CardService.newDecoratedText()
        .setTopLabel('SENDER')
        .setText(b(sender.substring(0, 100)))
        .setWrapText(true)
        .setStartIcon(mi('person'))
    )
    .addWidget(CardService.newDivider())
    .addWidget(
      CardService.newDecoratedText()
        .setTopLabel('SUBJECT')
        .setText(subject.substring(0, 100))
        .setWrapText(true)
        .setStartIcon(mi('mail'))
    );

  var brief = CardService.newCardSection()
    .addWidget(CardService.newTextParagraph().setText(
      fc('Scans authentication headers, URLs, sender IP, domain age, ' +
      'and behavioral patterns. Typical analysis: 2\u20134 seconds.', C.MUTE)
    ));

  var footer = CardService.newFixedFooter()
    .setPrimaryButton(
      CardService.newTextButton()
        .setText('RUN SCAN')
        .setOnClickAction(CardService.newAction().setFunctionName('analyzeEmail'))
        .setTextButtonStyle(CardService.TextButtonStyle.FILLED)
    );

  return CardService.newCardBuilder()
    .setHeader(header)
    .addSection(target)
    .addSection(brief)
    .setFixedFooter(footer)
    .build();
}


// \u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550
//  RESULT CARD
// \u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550

/**
 * Sections (visible \u2192 progressive disclosure):
 *   \u00A71  Score + Action    \u2014 hero metrics, colored bar, directive
 *   \u00A72  Threat Intel      \u2014 top contributors + AI narrative
 *   \u00A73  Signal Grid       \u2014 per-category breakdown (collapsible)
 *   \u00A74  Evidence Chain    \u2014 raw evidence items (collapsible)
 *   \u00A75  All Signals       \u2014 every signal fired (collapsible)
 *   \u00A76  Forensics         \u2014 request ID + timing (collapsible)
 *
 * @param {Object} result - AnalyzeResponse JSON from backend.
 * @return {Card}
 */
function buildResultCard(result) {
  var verdict     = result.verdict         || 'UNKNOWN';
  var score       = result.score           != null ? result.score : 0;
  var confidence  = result.confidence      != null ? result.confidence : 0;
  var confLabel   = result.confidence_label || '';
  var explanation = result.explanation      || 'No analysis narrative available.';
  var topContrib  = result.top_contributors || [];
  var allSignals  = result.signals         || [];
  var evidence    = result.evidence        || [];
  var breakdown   = result.scoring_breakdown || {};
  var requestId   = result.request_id      || '';
  var timing      = result.analysis_time_ms || 0;

  var vc = V_COLOR[verdict] || C.MUTE;
  var sc = sColor(score);

  // \u2500\u2500 Header \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500
  var header = CardService.newCardHeader()
    .setTitle(V_TITLE[verdict] || verdict)
    .setSubtitle(V_SUB[verdict] || 'Analysis complete')
    .setImageUrl(V_IMG[verdict] || HDR.SHIELD)
    .setImageStyle(CardService.ImageStyle.CIRCLE);

  // \u2500\u2500 \u00A71: Score + Action \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500
  var scoreSec = CardService.newCardSection();

  // Columns: threat score | confidence
  try {
    scoreSec.addWidget(
      CardService.newColumns()
        .addColumn(
          CardService.newColumn()
            .setHorizontalSizeStyle(CardService.HorizontalSizeStyle.FILL_AVAILABLE_SPACE)
            .setHorizontalAlignment(CardService.HorizontalAlignment.CENTER)
            .setVerticalAlignment(CardService.VerticalAlignment.CENTER)
            .addWidget(
              CardService.newDecoratedText()
                .setTopLabel('THREAT SCORE')
                .setText(bc('' + score, sc) + fc(' / 100', C.MUTE))
            )
        )
        .addColumn(
          CardService.newColumn()
            .setHorizontalSizeStyle(CardService.HorizontalSizeStyle.FILL_AVAILABLE_SPACE)
            .setHorizontalAlignment(CardService.HorizontalAlignment.CENTER)
            .setVerticalAlignment(CardService.VerticalAlignment.CENTER)
            .addWidget(
              CardService.newDecoratedText()
                .setTopLabel('CONFIDENCE')
                .setText(bc(confidence + '%', C.BLUE))
                .setBottomLabel(confLabel)
            )
        )
        .setWrapStyle(CardService.WrapStyle.WRAP)
    );
  } catch (_) {
    // Fallback for runtimes without Columns support
    scoreSec.addWidget(
      CardService.newDecoratedText()
        .setTopLabel('THREAT SCORE')
        .setText(bc(score + ' / 100', sc))
        .setBottomLabel('Confidence: ' + confidence + '% \u00B7 ' + confLabel)
        .setStartIcon(mi(V_MI[verdict] || 'security'))
    );
  }

  // Score bar + numeric label
  scoreSec.addWidget(
    CardService.newTextParagraph().setText(
      fc(scoreBar(score), sc) + '  ' + bc(score + '%', sc)
    )
  );

  // Directive
  scoreSec.addWidget(CardService.newDivider());
  scoreSec.addWidget(
    CardService.newDecoratedText()
      .setText(bc(V_ACTION[verdict] || 'Review analysis below.', vc))
      .setWrapText(true)
      .setStartIcon(mi(V_ACT_ICON[verdict] || 'info'))
  );

  // \u2500\u2500 \u00A72: Threat Intel \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500
  var threatSec = CardService.newCardSection()
    .setHeader('THREAT INTEL');

  if (topContrib.length === 0) {
    threatSec.addWidget(
      CardService.newDecoratedText()
        .setText(
          bc('ALL CLEAR', C.SAFE) +
          fc(' \u2014 no risk indicators triggered', C.MUTE)
        )
        .setStartIcon(mi('check_circle'))
    );
  } else {
    for (var i = 0; i < topContrib.length; i++) {
      var t = topContrib[i];
      if (i > 0) threatSec.addWidget(CardService.newDivider());
      var w = CardService.newDecoratedText()
        .setTopLabel(t.name + '  \u00B7  ' + bc('+' + t.points, sevColor(t.severity)))
        .setText(sevTag(t.severity) + '<br>' + t.description.substring(0, 140))
        .setWrapText(true)
        .setStartIcon(mi(sevMi(t.severity)));
      if (t.value) w.setBottomLabel(t.value.substring(0, 80));
      threatSec.addWidget(w);
    }
  }

  // AI narrative
  threatSec.addWidget(CardService.newDivider());
  threatSec.addWidget(
    CardService.newDecoratedText()
      .setTopLabel('AI ANALYSIS')
      .setText(explanation)
      .setWrapText(true)
      .setStartIcon(mi('auto_awesome'))
  );

  // \u2500\u2500 \u00A73: Signal Grid (collapsible) \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500
  var catPts = breakdown.category_points || {};

  var gridSec = CardService.newCardSection()
    .setHeader('SIGNAL GRID')
    .setCollapsible(true)
    .setNumUncollapsibleWidgets(0);

  // Scoring formula
  gridSec.addWidget(
    CardService.newDecoratedText()
      .setTopLabel('SCORING')
      .setText(
        fc('Raw ', C.MUTE) + b('' + (breakdown.total_points || 0)) +
        fc(' \u2192 Capped ', C.MUTE) + b('' + (breakdown.capped_points || 0)) +
        fc(' / ' + (breakdown.max_points || 0), C.MUTE)
      )
      .setWrapText(true)
      .setStartIcon(mi('calculate'))
  );

  gridSec.addWidget(CardService.newDivider());

  // Per-category rows
  for (var c = 0; c < CAT_ORDER.length; c++) {
    var key  = CAT_ORDER[c];
    var meta = CAT[key];
    var pts  = catPts[key] || 0;
    gridSec.addWidget(
      CardService.newDecoratedText()
        .setTopLabel(meta.lbl)
        .setText(bc('' + pts, ptColor(pts, meta.cap)) + fc(' / ' + meta.cap + ' pts', C.MUTE))
        .setBottomLabel(meta.desc)
        .setStartIcon(mi(meta.mi))
    );
  }

  // \u2500\u2500 \u00A74: Evidence Chain (collapsible) \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500
  var evSec = CardService.newCardSection()
    .setHeader('EVIDENCE CHAIN (' + evidence.length + ')')
    .setCollapsible(true)
    .setNumUncollapsibleWidgets(0);

  if (evidence.length === 0) {
    evSec.addWidget(
      CardService.newTextParagraph()
        .setText(fc('No evidence items logged.', C.MUTE))
    );
  } else {
    var evCap = Math.min(evidence.length, 15);
    for (var k = 0; k < evCap; k++) {
      var ev = evidence[k];
      if (k > 0) evSec.addWidget(CardService.newDivider());
      var idx = k < 9 ? '0' + (k + 1) : '' + (k + 1);
      evSec.addWidget(
        CardService.newDecoratedText()
          .setTopLabel('[' + idx + '] ' + ev.signal + '  \u00B7  +' + ev.points)
          .setText(ev.raw_value.substring(0, 140))
          .setBottomLabel(ev.source)
          .setWrapText(true)
      );
    }
    if (evidence.length > 15) {
      evSec.addWidget(
        CardService.newTextParagraph()
          .setText(fc('\u2026 and ' + (evidence.length - 15) + ' more entries', C.MUTE))
      );
    }
  }

  // \u2500\u2500 \u00A75: All Signals (collapsible) \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500
  var sigSec = CardService.newCardSection()
    .setHeader('ALL SIGNALS (' + allSignals.length + ')')
    .setCollapsible(true)
    .setNumUncollapsibleWidgets(0);

  if (allSignals.length === 0) {
    sigSec.addWidget(
      CardService.newTextParagraph()
        .setText(fc('No signals activated.', C.MUTE))
    );
  } else {
    for (var j = 0; j < allSignals.length; j++) {
      var s = allSignals[j];
      if (j > 0) sigSec.addWidget(CardService.newDivider());
      sigSec.addWidget(
        CardService.newDecoratedText()
          .setTopLabel(
            s.category.toUpperCase() + '  \u00B7  ' +
            bc('+' + s.points, sevColor(s.severity))
          )
          .setText(
            sevTag(s.severity) + '<br>' +
            b(s.name) + ' \u2014 ' + s.description.substring(0, 120)
          )
          .setWrapText(true)
          .setStartIcon(mi(sevMi(s.severity)))
      );
    }
  }

  // \u2500\u2500 \u00A76: Forensics (collapsible) \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500
  var metaSec = CardService.newCardSection()
    .setHeader('FORENSICS')
    .setCollapsible(true)
    .setNumUncollapsibleWidgets(0)
    .addWidget(
      CardService.newDecoratedText()
        .setTopLabel('REQUEST ID')
        .setText(fc(requestId, C.MUTE))
        .setWrapText(true)
        .setStartIcon(mi('label'))
    )
    .addWidget(CardService.newDivider())
    .addWidget(
      CardService.newDecoratedText()
        .setTopLabel('ANALYSIS TIME')
        .setText(b(timing + ' ms'))
        .setStartIcon(mi('speed'))
    );

  // \u2500\u2500 Assemble \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500
  return CardService.newCardBuilder()
    .setHeader(header)
    .addSection(scoreSec)
    .addSection(threatSec)
    .addSection(gridSec)
    .addSection(evSec)
    .addSection(sigSec)
    .addSection(metaSec)
    .build();
}


// \u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550
//  ERROR CARD
// \u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550

/**
 * @param {string} message  - User-facing error message.
 * @param {string} [detail] - Optional technical detail.
 * @return {Card}
 */
function buildErrorCard(message, detail) {
  var header = CardService.newCardHeader()
    .setTitle('SCAN FAILED')
    .setSubtitle('Unable to complete analysis')
    .setImageUrl(HDR.ERR)
    .setImageStyle(CardService.ImageStyle.CIRCLE);

  var errSec = CardService.newCardSection()
    .addWidget(
      CardService.newDecoratedText()
        .setText(bc(message, C.DANGER))
        .setWrapText(true)
        .setStartIcon(mi('error'))
    );

  if (detail) {
    errSec.addWidget(CardService.newDivider());
    errSec.addWidget(
      CardService.newDecoratedText()
        .setTopLabel('DIAGNOSTIC')
        .setText(fc(detail.substring(0, 200), C.MUTE))
        .setWrapText(true)
        .setStartIcon(mi('bug_report'))
    );
  }

  var hintSec = CardService.newCardSection()
    .addWidget(CardService.newTextParagraph().setText(
      fc('Backend may be cold-starting. Wait a few seconds, then retry.', C.MUTE)
    ));

  var footer = CardService.newFixedFooter()
    .setPrimaryButton(
      CardService.newTextButton()
        .setText('RETRY SCAN')
        .setOnClickAction(CardService.newAction().setFunctionName('analyzeEmail'))
        .setTextButtonStyle(CardService.TextButtonStyle.FILLED)
    );

  return CardService.newCardBuilder()
    .setHeader(header)
    .addSection(errSec)
    .addSection(hintSec)
    .setFixedFooter(footer)
    .build();
}
