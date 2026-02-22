/**
 * Cards.gs v4 — "Sentinel" design system
 *
 * Aesthetic: Industrial security terminal. Terse. Decisive. Color-coded.
 * Every pixel of data earns its place or gets cut.
 *
 * Architecture (matching Code.gs contract):
 *   buildHomepageCard(history, autoScan, blacklist) → onHomepage()
 *   buildInitialCard(subject, sender, id)           → onGmailMessageOpen()
 *   buildResultCard(result, sender)                 → analyzeEmail() success
 *   buildErrorCard(message, detail)                 → analyzeEmail() failure
 *   buildBlockedCard(domain)                        → blockSender() confirmation
 *
 * CardService features used:
 *   MaterialIcon · DecoratedText · TextParagraph · Columns
 *   Divider · FixedFooter · Collapsible sections · HTML formatting
 *
 * Constraints: ES5 only · ~300px sidebar · CardHeader requires URL icons
 * HTML subset: <b> <i> <u> <s> <font color> <a href> <br>
 */


// ═══════════════════════════════════════════════════════════
//  DESIGN TOKENS
// ═══════════════════════════════════════════════════════════

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

// Verdict → display config
var V_IMG    = { SAFE: HDR.VERIFIED, SUSPICIOUS: HDR.WARN, MALICIOUS: HDR.DANGER };
var V_COLOR  = { SAFE: C.SAFE, SUSPICIOUS: C.WARN, MALICIOUS: C.DANGER };
var V_MI     = { SAFE: 'verified_user', SUSPICIOUS: 'warning', MALICIOUS: 'dangerous' };

var V_TITLE  = { SAFE: 'CLEAR', SUSPICIOUS: 'CAUTION', MALICIOUS: 'HOSTILE' };
var V_SUB    = {
  SAFE:       'All signals nominal — no threats detected',
  SUSPICIOUS: 'Anomalies detected — exercise caution',
  MALICIOUS:  'Active threat indicators — do not engage'
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
  security:      'https://www.gstatic.com/images/icons/material/system/2x/security_black_24dp.png',
  history:       'https://www.gstatic.com/images/icons/material/system/2x/history_black_24dp.png',
  settings:      'https://www.gstatic.com/images/icons/material/system/2x/settings_black_24dp.png',
  toggle_on:     'https://www.gstatic.com/images/icons/material/system/2x/toggle_on_black_24dp.png',
  toggle_off:    'https://www.gstatic.com/images/icons/material/system/2x/toggle_off_black_24dp.png',
  delete:        'https://www.gstatic.com/images/icons/material/system/2x/delete_black_24dp.png'
};

// Category config
var CAT = {
  header:   { lbl: 'AUTH',     desc: 'SPF · DKIM · DMARC',          mi: 'fingerprint',    cap: 45 },
  url:      { lbl: 'URLS',     desc: 'VirusTotal · Safe Browsing',   mi: 'link',           cap: 40 },
  ip:       { lbl: 'IP REP',   desc: 'AbuseIPDB confidence score',   mi: 'dns',            cap: 20 },
  domain:   { lbl: 'DOMAIN',   desc: 'Registration age analysis',    mi: 'event',          cap: 20 },
  behavior: { lbl: 'BEHAVIOR', desc: 'Social engineering cues',      mi: 'visibility',     cap: 10 }
};
var CAT_ORDER = ['header', 'url', 'ip', 'domain', 'behavior'];

// Confidence penalties (must match backend scoring.py CONFIDENCE_PENALTIES)
var CONF_PENALTIES = {
  virustotal:    { label: 'VirusTotal',      pts: 20 },
  safe_browsing: { label: 'Safe Browsing',   pts: 15 },
  abuseipdb:     { label: 'AbuseIPDB',       pts: 10 },
  whois:         { label: 'WHOIS',           pts: 10 }
};


// ═══════════════════════════════════════════════════════════
//  CORE HELPERS
// ═══════════════════════════════════════════════════════════

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

/** Score 0-100 → threat color. */
function sColor(score) {
  if (score <= 25) return C.SAFE;
  if (score <= 55) return C.WARN;
  return C.DANGER;
}

/** Severity string → color hex. */
function sevColor(sev) {
  switch ((sev || '').toLowerCase()) {
    case 'critical': return C.CRIT;
    case 'high':     return C.HIGH;
    case 'medium':   return C.WARN;
    case 'low':      return C.BLUE;
    default:         return C.MUTE;
  }
}

/** Severity → icon name (maps to ICO keys). */
function sevMi(sev) {
  switch ((sev || '').toLowerCase()) {
    case 'critical': return 'dangerous';
    case 'high':     return 'warning';
    case 'medium':   return 'flag';
    case 'low':      return 'info';
    default:         return 'info';
  }
}

/** HTML colored severity badge: ● CRITICAL etc. */
function sevTag(sev) {
  var s = (sev || '').toLowerCase();
  var label = (s === 'critical' || s === 'high' || s === 'medium' || s === 'low')
    ? s.toUpperCase() : 'INFO';
  return bc('● ' + label, sevColor(sev));
}

/** 20-char Unicode score bar with finer resolution than 10-char. */
function scoreBar(score) {
  var n = Math.round(score / 5);
  var bar = '';
  for (var i = 0; i < n; i++) bar += '█';
  for (var j = 0; j < 20 - n; j++) bar += '░';
  return bar;
}

/** Points → color based on ratio to cap. */
function ptColor(pts, cap) {
  if (cap === 0) return C.MUTE;
  var r = pts / cap;
  return r < 0.25 ? C.SAFE : r < 0.5 ? C.WARN : C.DANGER;
}

/** Relative time string: "2h ago", "3d ago", "just now". */
function relativeTime(isoString) {
  try {
    var then = new Date(isoString);
    var now  = new Date();
    var diff = Math.floor((now.getTime() - then.getTime()) / 1000);
    if (diff < 60)    return 'just now';
    if (diff < 3600)  return Math.floor(diff / 60) + 'm ago';
    if (diff < 86400) return Math.floor(diff / 3600) + 'h ago';
    return Math.floor(diff / 86400) + 'd ago';
  } catch (_) {
    return '';
  }
}


// ═══════════════════════════════════════════════════════════
//  HOMEPAGE CARD (with history, auto-scan toggle, blacklist)
// ═══════════════════════════════════════════════════════════

/**
 * @param {Array}   history        - Array of scan history items (newest first).
 * @param {boolean} autoScanEnabled - Whether auto-scan mode is active.
 * @param {Array}   blacklist      - Array of blocked domain strings.
 * @return {Card}
 */
function buildHomepageCard(history, autoScanEnabled, blacklist) {
  history   = history   || [];
  blacklist = blacklist || [];

  var header = CardService.newCardHeader()
    .setTitle('SENTINEL')
    .setSubtitle('Email Threat Intelligence')
    .setImageUrl(HDR.SHIELD)
    .setImageStyle(CardService.ImageStyle.CIRCLE);

  // ── Settings section (auto-scan toggle) ───────────────
  var settingsSec = CardService.newCardSection()
    .setHeader('SETTINGS');

  var toggleBtn = CardService.newTextButton()
    .setText(autoScanEnabled ? 'DISABLE' : 'ENABLE')
    .setOnClickAction(CardService.newAction().setFunctionName('toggleAutoScan'))
    .setTextButtonStyle(CardService.TextButtonStyle.FILLED);

  settingsSec.addWidget(
    CardService.newDecoratedText()
      .setTopLabel('AUTO-SCAN')
      .setText(bc(autoScanEnabled ? 'ENABLED' : 'DISABLED', autoScanEnabled ? C.SAFE : C.MUTE))
      .setBottomLabel('Analyze every email automatically on open')
      .setStartIcon(mi(autoScanEnabled ? 'toggle_on' : 'toggle_off'))
      .setButton(toggleBtn)
  );

  // ── Recent scans section ──────────────────────────────
  var historySec = CardService.newCardSection()
    .setHeader('RECENT SCANS');

  if (history.length === 0) {
    historySec.addWidget(
      CardService.newTextParagraph().setText(
        fc('No scans yet — open an email to begin.', C.MUTE)
      )
    );
  } else {
    // Stats summary
    var totalScans = history.length;
    var malCount = 0;
    var susCount = 0;
    for (var h = 0; h < history.length; h++) {
      if (history[h].verdict === 'MALICIOUS')  malCount++;
      if (history[h].verdict === 'SUSPICIOUS') susCount++;
    }
    var statsText = b('' + totalScans) + fc(' scanned', C.MUTE);
    if (malCount > 0) statsText += '  ·  ' + bc('' + malCount + ' threats', C.DANGER);
    if (susCount > 0) statsText += '  ·  ' + bc('' + susCount + ' suspicious', C.WARN);
    historySec.addWidget(
      CardService.newTextParagraph().setText(statsText)
    );

    // Individual entries (max 7 shown)
    var showCount = Math.min(history.length, 7);
    for (var i = 0; i < showCount; i++) {
      var item = history[i];
      var itemColor = V_COLOR[item.verdict] || C.MUTE;
      historySec.addWidget(CardService.newDivider());
      historySec.addWidget(
        CardService.newDecoratedText()
          .setTopLabel(
            bc(item.verdict || 'UNKNOWN', itemColor) +
            fc('  ·  Score: ' + (item.score != null ? item.score : '?'), C.MUTE)
          )
          .setText((item.sender || '').substring(0, 60))
          .setBottomLabel(
            (item.subject || '').substring(0, 50) +
            '  ·  ' + relativeTime(item.ts)
          )
          .setWrapText(true)
          .setStartIcon(mi(V_MI[item.verdict] || 'info'))
      );
    }
    if (history.length > 7) {
      historySec.addWidget(
        CardService.newTextParagraph().setText(
          fc('… and ' + (history.length - 7) + ' more', C.MUTE)
        )
      );
    }
  }

  // ── Blacklist section ─────────────────────────────────
  var blSec = CardService.newCardSection()
    .setHeader('BLOCKED DOMAINS (' + blacklist.length + ')')
    .setCollapsible(true)
    .setNumUncollapsibleWidgets(0);

  if (blacklist.length === 0) {
    blSec.addWidget(
      CardService.newTextParagraph().setText(
        fc('No blocked domains. Use the "BLOCK SENDER" button on scan results to add entries.', C.MUTE)
      )
    );
  } else {
    for (var bl = 0; bl < blacklist.length; bl++) {
      var dom = blacklist[bl];
      var unblockBtn = CardService.newTextButton()
        .setText('UNBLOCK')
        .setOnClickAction(
          CardService.newAction()
            .setFunctionName('unblockSender')
            .setParameters({ 'domain': dom })
        );
      blSec.addWidget(
        CardService.newDecoratedText()
          .setText(bc(dom, C.DANGER))
          .setStartIcon(mi('block'))
          .setButton(unblockBtn)
      );
    }
  }

  // ── Engine listing ────────────────────────────────────
  var engines = [
    { n: 'fingerprint',    t: 'Authentication',      d: 'SPF, DKIM, DMARC header validation' },
    { n: 'link',           t: 'URL Intelligence',    d: 'VirusTotal & Google Safe Browsing' },
    { n: 'dns',            t: 'IP Reputation',       d: 'AbuseIPDB confidence scoring' },
    { n: 'event',          t: 'Domain Analysis',     d: 'Registration age & freshness check' },
    { n: 'visibility',     t: 'Behavioral Signals',  d: 'Urgency & social engineering patterns' }
  ];

  var engSec = CardService.newCardSection()
    .setHeader('THREAT INTEL ENGINES')
    .setCollapsible(true)
    .setNumUncollapsibleWidgets(0);
  for (var e = 0; e < engines.length; e++) {
    if (e > 0) engSec.addWidget(CardService.newDivider());
    engSec.addWidget(
      CardService.newDecoratedText()
        .setText(b(engines[e].t))
        .setBottomLabel(engines[e].d)
        .setStartIcon(mi(engines[e].n))
    );
  }

  return CardService.newCardBuilder()
    .setHeader(header)
    .addSection(settingsSec)
    .addSection(historySec)
    .addSection(blSec)
    .addSection(engSec)
    .build();
}


// ═══════════════════════════════════════════════════════════
//  INITIAL CARD (pre-scan)
// ═══════════════════════════════════════════════════════════

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
      'and behavioral patterns. Typical analysis: 2–4 seconds.', C.MUTE)
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


// ═══════════════════════════════════════════════════════════
//  RESULT CARD
// ═══════════════════════════════════════════════════════════

/**
 * Sections (visible → progressive disclosure):
 *   §1  Score + Action    — hero metrics, colored bar, directive
 *   §2  Threat Intel      — top contributors + AI narrative + block button
 *   §3  Signal Grid       — per-category breakdown (collapsible)
 *   §4  Evidence Chain    — raw evidence items (collapsible)
 *   §5  All Signals       — every signal fired (collapsible)
 *   §6  Confidence Detail — source availability breakdown (collapsible)
 *   §7  Forensics         — request ID + timing (collapsible)
 *
 * @param {Object} result - AnalyzeResponse JSON from backend.
 * @param {string} [sender] - Full sender string (for block button).
 * @return {Card}
 */
function buildResultCard(result, sender) {
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
  var srcAvail    = result.source_availability || {};

  var vc = V_COLOR[verdict] || C.MUTE;
  var sc = sColor(score);

  // ── Header ────────────────────────────────────────────
  var header = CardService.newCardHeader()
    .setTitle(V_TITLE[verdict] || verdict)
    .setSubtitle(V_SUB[verdict] || 'Analysis complete')
    .setImageUrl(V_IMG[verdict] || HDR.SHIELD)
    .setImageStyle(CardService.ImageStyle.CIRCLE);

  // ── §1: Score + Action ───────────────────────────────
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
        .setBottomLabel('Confidence: ' + confidence + '% · ' + confLabel)
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

  // ── §2: Threat Intel ──────────────────────────────────
  var threatSec = CardService.newCardSection()
    .setHeader('THREAT INTEL');

  if (topContrib.length === 0) {
    threatSec.addWidget(
      CardService.newDecoratedText()
        .setText(
          bc('ALL CLEAR', C.SAFE) +
          fc(' — no risk indicators triggered', C.MUTE)
        )
        .setStartIcon(mi('check_circle'))
    );
  } else {
    for (var i = 0; i < topContrib.length; i++) {
      var t = topContrib[i];
      if (i > 0) threatSec.addWidget(CardService.newDivider());
      var w = CardService.newDecoratedText()
        .setTopLabel(t.name + '  ·  ' + bc('+' + t.points, sevColor(t.severity)))
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

  // Block Sender button (for MALICIOUS or SUSPICIOUS verdicts)
  if (sender && (verdict === 'MALICIOUS' || verdict === 'SUSPICIOUS')) {
    threatSec.addWidget(CardService.newDivider());
    threatSec.addWidget(
      CardService.newDecoratedText()
        .setText(fc('Flag all future emails from this sender as hostile', C.MUTE))
        .setStartIcon(mi('block'))
        .setButton(
          CardService.newTextButton()
            .setText('BLOCK SENDER')
            .setOnClickAction(
              CardService.newAction()
                .setFunctionName('blockSender')
                .setParameters({ 'sender': sender.substring(0, 200) })
            )
            .setTextButtonStyle(CardService.TextButtonStyle.FILLED)
        )
    );
  }

  // ── §3: Signal Grid (collapsible) ─────────────────────
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
        fc(' → Capped ', C.MUTE) + b('' + (breakdown.capped_points || 0)) +
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

  // ── §4: Evidence Chain (collapsible) ──────────────────
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
          .setTopLabel('[' + idx + '] ' + ev.signal + '  ·  +' + ev.points)
          .setText(ev.raw_value.substring(0, 140))
          .setBottomLabel(ev.source)
          .setWrapText(true)
      );
    }
    if (evidence.length > 15) {
      evSec.addWidget(
        CardService.newTextParagraph()
          .setText(fc('… and ' + (evidence.length - 15) + ' more entries', C.MUTE))
      );
    }
  }

  // ── §5: All Signals (collapsible) ─────────────────────
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
            s.category.toUpperCase() + '  ·  ' +
            bc('+' + s.points, sevColor(s.severity))
          )
          .setText(
            sevTag(s.severity) + '<br>' +
            b(s.name) + ' — ' + s.description.substring(0, 120)
          )
          .setWrapText(true)
          .setStartIcon(mi(sevMi(s.severity)))
      );
    }
  }

  // ── §6: Confidence Detail (collapsible) ───────────────
  var confSec = CardService.newCardSection()
    .setHeader('CONFIDENCE DETAIL')
    .setCollapsible(true)
    .setNumUncollapsibleWidgets(0);

  confSec.addWidget(
    CardService.newDecoratedText()
      .setTopLabel('CONFIDENCE RATING')
      .setText(bc(confidence + '%', C.BLUE) + '  ' + fc(confLabel, C.MUTE))
      .setStartIcon(mi('verified_user'))
  );

  var anyDown = false;
  var sourceKeys = ['virustotal', 'safe_browsing', 'abuseipdb', 'whois'];
  for (var si = 0; si < sourceKeys.length; si++) {
    var sk = sourceKeys[si];
    var cp = CONF_PENALTIES[sk];
    if (srcAvail[sk] === false) {
      anyDown = true;
      confSec.addWidget(
        CardService.newDecoratedText()
          .setText(
            fc('✗ ', C.WARN) + fc(cp.label + ' unavailable', C.MUTE) +
            bc('  −' + cp.pts + ' pts', C.WARN)
          )
          .setStartIcon(mi('warning'))
      );
    } else {
      confSec.addWidget(
        CardService.newDecoratedText()
          .setText(
            fc('✓ ', C.SAFE) + fc(cp.label + ' active', C.MUTE)
          )
          .setStartIcon(mi('check_circle'))
      );
    }
  }

  if (!anyDown) {
    confSec.addWidget(CardService.newDivider());
    confSec.addWidget(
      CardService.newTextParagraph().setText(
        fc('All intelligence sources active — full confidence', C.SAFE)
      )
    );
  }

  // ── §7: Forensics (collapsible) ───────────────────────
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

  // ── Assemble ──────────────────────────────────────────
  return CardService.newCardBuilder()
    .setHeader(header)
    .addSection(scoreSec)
    .addSection(threatSec)
    .addSection(gridSec)
    .addSection(evSec)
    .addSection(sigSec)
    .addSection(confSec)
    .addSection(metaSec)
    .build();
}


// ═══════════════════════════════════════════════════════════
//  BLOCKED CONFIRMATION CARD
// ═══════════════════════════════════════════════════════════

/**
 * Shown after the user blocks a sender domain.
 *
 * @param {string} domain - The domain that was blocked.
 * @return {Card}
 */
function buildBlockedCard(domain) {
  var header = CardService.newCardHeader()
    .setTitle('SENDER BLOCKED')
    .setSubtitle('Domain added to blacklist')
    .setImageUrl(HDR.DANGER)
    .setImageStyle(CardService.ImageStyle.CIRCLE);

  var bodySec = CardService.newCardSection()
    .addWidget(
      CardService.newDecoratedText()
        .setText(
          bc(domain || 'unknown', C.DANGER) + '<br><br>' +
          fc('All future emails from this domain will be flagged as ', C.MUTE) +
          bc('MALICIOUS', C.DANGER) +
          fc(' instantly — no API calls required.', C.MUTE)
        )
        .setWrapText(true)
        .setStartIcon(mi('block'))
    );

  var hintSec = CardService.newCardSection()
    .addWidget(CardService.newTextParagraph().setText(
      fc('To unblock this domain, visit the add-on homepage and remove it from the BLOCKED DOMAINS list.', C.MUTE)
    ));

  return CardService.newCardBuilder()
    .setHeader(header)
    .addSection(bodySec)
    .addSection(hintSec)
    .build();
}


// ═══════════════════════════════════════════════════════════
//  ERROR CARD
// ═══════════════════════════════════════════════════════════

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
