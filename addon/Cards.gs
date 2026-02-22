/**
 * Phase 5 — CardService UI builders (Cards.gs)
 * Builds all Gmail Add-on cards using the CardService API.
 *
 * CardService constraints:
 * - No arbitrary text colors (workaround: verdict badge images hosted on GitHub raw).
 * - No HTML/CSS — Card-based UI only.
 * - Progress bars not natively supported — score shown as "XX/100" text.
 * - Collapsible sections via CardSection.setCollapsible(true).
 *
 * Verdict badge images:
 *   Hosted at https://raw.githubusercontent.com/diy-code/gmail-email-scanner/main/assets/
 *   badge_safe.png, badge_suspicious.png, badge_malicious.png
 */

var BADGE_BASE_URL = 'https://www.gstatic.com/images/icons/material/system/2x/';
var SHIELD_ICON = 'https://www.gstatic.com/images/icons/material/system/2x/security_black_24dp.png';

// Using Google Material icons as fallback (repo assets not yet uploaded)
var VERDICT_BADGE = {
  'SAFE':       'https://www.gstatic.com/images/icons/material/system/2x/check_circle_black_24dp.png',
  'SUSPICIOUS': 'https://www.gstatic.com/images/icons/material/system/2x/warning_black_24dp.png',
  'MALICIOUS':  'https://www.gstatic.com/images/icons/material/system/2x/dangerous_black_24dp.png'
};

// ---------------------------------------------------------------------------
// Homepage card
// ---------------------------------------------------------------------------

function buildHomepageCard() {
  var header  = CardService.newCardHeader()
    .setTitle('Email Security Scanner')
    .setSubtitle('Open an email to analyze it')
    .setImageUrl(SHIELD_ICON)
    .setImageStyle(CardService.ImageStyle.CIRCLE);

  var section = CardService.newCardSection()
    .addWidget(CardService.newTextParagraph().setText(
      'This add-on analyzes the currently open email for phishing indicators, ' +
      'suspicious links, and authentication failures. Open an email and click ' +
      '"Analyze Email" to get started.'
    ));

  return CardService.newCardBuilder()
    .setHeader(header)
    .addSection(section)
    .build();
}

// ---------------------------------------------------------------------------
// Initial card (shown when email opens — before analysis)
// ---------------------------------------------------------------------------

/**
 * @param {string} subject - Email subject line.
 * @param {string} sender  - From address.
 * @param {string} messageId - Gmail message ID (passed to analyzeEmail action).
 * @return {Card}
 */
function buildInitialCard(subject, sender, messageId) {
  var header = CardService.newCardHeader()
    .setTitle('Email Security Scanner')
    .setSubtitle('Analyze this email for threats')
    .setImageUrl(SHIELD_ICON)
    .setImageStyle(CardService.ImageStyle.CIRCLE);

  var infoSection = CardService.newCardSection()
    .setHeader('Email Details')
    .addWidget(
      CardService.newKeyValue()
        .setTopLabel('Subject')
        .setContent(subject.substring(0, 100))
    )
    .addWidget(
      CardService.newKeyValue()
        .setTopLabel('From')
        .setContent(sender.substring(0, 100))
    );

  // "Analyze Email" button in fixed footer
  var analyzeAction = CardService.newAction()
    .setFunctionName('analyzeEmail');

  var footer = CardService.newFixedFooter()
    .setPrimaryButton(
      CardService.newTextButton()
        .setText('🔍 Analyze Email')
        .setOnClickAction(analyzeAction)
        .setTextButtonStyle(CardService.TextButtonStyle.FILLED)
    );

  return CardService.newCardBuilder()
    .setHeader(header)
    .addSection(infoSection)
    .setFixedFooter(footer)
    .build();
}

// ---------------------------------------------------------------------------
// Result card (shown after analysis completes)
// ---------------------------------------------------------------------------

/**
 * Builds the full analysis result card.
 * Layout: verdict badge → score/confidence → top 3 signals → AI explanation → all signals.
 *
 * @param {Object} result - The AnalyzeResponse JSON from the backend.
 * @return {Card}
 */
function buildResultCard(result) {
  var verdict    = result.verdict    || 'UNKNOWN';
  var score      = result.score      != null ? result.score : 0;
  var confidence = result.confidence != null ? result.confidence : 0;
  var confidenceLabel = result.confidence_label || '';
  var explanation     = result.explanation || 'No explanation available.';
  var topContributors = result.top_contributors || [];
  var allSignals      = result.signals || [];
  var requestId       = result.request_id || '';

  var header = CardService.newCardHeader()
    .setTitle('Security Analysis')
    .setSubtitle(verdict + ' · ' + score + '/100')
    .setImageUrl(VERDICT_BADGE[verdict] || SHIELD_ICON);

  // ---- Verdict section ----
  var verdictSection = CardService.newCardSection()
    .setHeader('Verdict')
    .addWidget(
      CardService.newImage()
        .setImageUrl(VERDICT_BADGE[verdict] || VERDICT_BADGE['SUSPICIOUS'])
        .setAltText(verdict)
    )
    .addWidget(
      CardService.newKeyValue()
        .setTopLabel('Risk Score')
        .setContent(score + ' / 100')
        .setBottomLabel('Confidence: ' + confidence + '% (' + confidenceLabel + ')')
    );

  // ---- Top contributors section ----
  var signalSection = CardService.newCardSection()
    .setHeader('⚠ Key Risk Indicators');

  if (topContributors.length === 0) {
    signalSection.addWidget(
      CardService.newTextParagraph().setText('No risk indicators detected.')
    );
  } else {
    for (var i = 0; i < topContributors.length; i++) {
      var sig = topContributors[i];
      var icon = severityIcon(sig.severity);
      signalSection.addWidget(
        CardService.newKeyValue()
          .setTopLabel(icon + ' ' + sig.name + '  ·  +' + sig.points + ' pts')
          .setContent(sig.description.substring(0, 120))
          .setBottomLabel(sig.value ? sig.value.substring(0, 80) : '')
      );
    }
  }

  // ---- AI explanation section ----
  var aiSection = CardService.newCardSection()
    .setHeader('AI Analysis')
    .addWidget(
      CardService.newTextParagraph().setText('"' + explanation + '"')
    );

  // ---- Action guidance section ----
  var actionText = verdict === 'SAFE'
    ? 'This email appears safe. No immediate action required.'
    : verdict === 'SUSPICIOUS'
    ? 'Be cautious. Do not click unfamiliar links or provide personal information.'
    : 'Do NOT click any links or attachments. Consider reporting this email as phishing.';

  var actionSection = CardService.newCardSection()
    .setHeader('Recommended Action')
    .addWidget(CardService.newTextParagraph().setText(actionText));

  // ---- All signals (collapsible) ----
  var allSignalsSection = CardService.newCardSection()
    .setHeader('All Signals (' + allSignals.length + ')')
    .setCollapsible(true)
    .setNumUncollapsibleWidgets(0);

  if (allSignals.length === 0) {
    allSignalsSection.addWidget(
      CardService.newTextParagraph().setText('No signals fired.')
    );
  } else {
    for (var j = 0; j < allSignals.length; j++) {
      var s = allSignals[j];
      allSignalsSection.addWidget(
        CardService.newKeyValue()
          .setTopLabel(s.name + '  [' + s.category.toUpperCase() + '] +' + s.points + ' pts')
          .setContent(s.description.substring(0, 120))
      );
    }
  }

  // ---- Debug / request ID (small footer note) ----
  var metaSection = CardService.newCardSection()
    .setCollapsible(true)
    .setNumUncollapsibleWidgets(0)
    .setHeader('Debug Info')
    .addWidget(
      CardService.newTextParagraph().setText(
        'Request ID: ' + requestId + '\nTime: ' + (result.analysis_time_ms || 0) + 'ms'
      )
    );

  return CardService.newCardBuilder()
    .setHeader(header)
    .addSection(verdictSection)
    .addSection(signalSection)
    .addSection(aiSection)
    .addSection(actionSection)
    .addSection(allSignalsSection)
    .addSection(metaSection)
    .build();
}

// ---------------------------------------------------------------------------
// Error card
// ---------------------------------------------------------------------------

/**
 * @param {string} message - User-facing error message.
 * @param {string} [detail] - Optional technical detail (shown in collapsible section).
 * @return {Card}
 */
function buildErrorCard(message, detail) {
  var header = CardService.newCardHeader()
    .setTitle('Analysis Unavailable')
    .setSubtitle('Something went wrong')
    .setImageUrl(SHIELD_ICON);

  var section = CardService.newCardSection()
    .addWidget(CardService.newTextParagraph().setText(message));

  if (detail) {
    section.addWidget(
      CardService.newKeyValue()
        .setTopLabel('Technical detail')
        .setContent(detail.substring(0, 200))
    );
  }

  section.addWidget(
    CardService.newTextParagraph().setText(
      'If the backend is cold-starting, wait 10 seconds and re-open the email.'
    )
  );

  return CardService.newCardBuilder()
    .setHeader(header)
    .addSection(section)
    .build();
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Returns a visual severity indicator for a signal severity level.
 * @param {string} severity
 * @return {string}
 */
function severityIcon(severity) {
  switch ((severity || '').toLowerCase()) {
    case 'critical': return '🔴';
    case 'high':     return '🟠';
    case 'medium':   return '🟡';
    case 'low':      return '🔵';
    default:         return '⚪';
  }
}
