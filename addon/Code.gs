/**
 * Phase 5 — Gmail Add-on entry point (Code.gs)
 * Handles the contextual trigger (email open), the "Analyze" button action,
 * and the homepage trigger (no email open).
 *
 * Features:
 * - Auto-scan mode: automatically analyze emails on open (toggle on homepage)
 * - Scan history: last 10 scans stored in UserProperties, shown on homepage
 * - Sender blacklist: user-managed domain blocklist, instant MALICIOUS verdict
 *
 * Critical notes:
 * - setCurrentMessageAccessToken() MUST be called before any GmailApp method.
 * - Contextual trigger functions MUST return an ARRAY of cards: return [card]
 * - getRawContent() is used (not getHeader()) to capture all Received headers.
 *
 * Setup: run the setup() function ONCE from the Apps Script editor to store
 * BACKEND_URL and BACKEND_API_KEY in Script Properties.
 */

// ---------------------------------------------------------------------------
// One-time setup — run from the Apps Script editor
// ---------------------------------------------------------------------------

/**
 * Store backend configuration in Script Properties.
 * Run this function ONCE from the Apps Script editor after deployment.
 * Never hardcode API keys in source files.
 */
function setup() {
  PropertiesService.getScriptProperties().setProperties({
    'BACKEND_URL': 'https://email-scanner-backend-249452416372.us-central1.run.app',
    'BACKEND_API_KEY': 'this_is_a_random_key',
    'AUTO_SCAN': 'false'
  });
  Logger.log('Setup complete. Backend URL and API key stored in Script Properties.');
}

// ---------------------------------------------------------------------------
// Contextual trigger — fires when user opens any email
// ---------------------------------------------------------------------------

/**
 * Called automatically when the user opens a Gmail message.
 * If AUTO_SCAN is enabled, runs the full scan immediately.
 * Otherwise returns the initial "Analyze Email" card.
 *
 * @param {Object} e - The event object from the Gmail contextual trigger.
 * @return {Array} Array containing the initial or result card.
 */
function onGmailMessageOpen(e) {
  // Required before any GmailApp call — PLAN.md Phase 5.2 critical note
  GmailApp.setCurrentMessageAccessToken(e.gmail.accessToken);

  try {
    var messageId = e.gmail.messageId;
    var message = GmailApp.getMessageById(messageId);

    var subject = message.getSubject() || '(No Subject)';
    var sender  = message.getFrom()    || '(Unknown Sender)';

    // --- Auto-scan mode ---
    var autoScan = PropertiesService.getScriptProperties().getProperty('AUTO_SCAN');
    if (autoScan === 'true') {
      try {
        // Check blacklist first
        if (isBlacklisted(sender)) {
          var blResult = buildBlacklistHitResult(sender);
          saveToHistory(blResult, sender, subject);
          return [buildResultCard(blResult, sender)];
        }

        var payload = extractEmailPayload(message);
        var result = callAnalyzeEndpoint(payload);

        if (!result.error) {
          saveToHistory(result, sender, subject);
          return [buildResultCard(result, sender)];
        }
        // On API error, fall through to manual card
      } catch (autoErr) {
        Logger.log('Auto-scan error (falling back to manual): ' + autoErr.message);
      }
    }

    return [buildInitialCard(subject, sender, messageId)];

  } catch (err) {
    Logger.log('onGmailMessageOpen error: ' + err.message);
    return [buildErrorCard('Could not load email. Please try reopening it.', err.message)];
  }
}

// ---------------------------------------------------------------------------
// Action callback — fires when user clicks "Analyze Email"
// ---------------------------------------------------------------------------

/**
 * Called when the user clicks the "Analyze Email" button.
 * Extracts email data, calls the backend, and returns the result card.
 *
 * @param {Object} e - The action event object.
 * @return {Object} CardService navigation action with the result card.
 */
function analyzeEmail(e) {
  // Re-set access token in action callbacks too (token may differ from trigger)
  GmailApp.setCurrentMessageAccessToken(e.gmail.accessToken);

  var messageId = e.gmail.messageId;

  try {
    var message = GmailApp.getMessageById(messageId);
    var payload = extractEmailPayload(message);
    var sender = payload.sender || message.getFrom() || '';
    var subject = payload.subject || message.getSubject() || '';

    // --- Blacklist check: skip API call, instant MALICIOUS ---
    if (isBlacklisted(sender)) {
      var blResult = buildBlacklistHitResult(sender);
      saveToHistory(blResult, sender, subject);
      return CardService.newActionResponseBuilder()
        .setNavigation(CardService.newNavigation().pushCard(
          buildResultCard(blResult, sender)
        ))
        .build();
    }

    var result = callAnalyzeEndpoint(payload);

    if (result.error) {
      return CardService.newActionResponseBuilder()
        .setNavigation(CardService.newNavigation().pushCard(
          buildErrorCard('Analysis failed: ' + result.error)
        ))
        .build();
    }

    // Save to scan history
    saveToHistory(result, sender, subject);

    return CardService.newActionResponseBuilder()
      .setNavigation(CardService.newNavigation().pushCard(
        buildResultCard(result, sender)
      ))
      .build();

  } catch (err) {
    Logger.log('analyzeEmail error: ' + err.message + '\n' + err.stack);
    return CardService.newActionResponseBuilder()
      .setNavigation(CardService.newNavigation().pushCard(
        buildErrorCard('Analysis encountered an unexpected error.', err.message)
      ))
      .build();
  }
}

// ---------------------------------------------------------------------------
// Homepage trigger — shown when no email is open
// ---------------------------------------------------------------------------

/**
 * Shown when the add-on is opened outside of a Gmail message context.
 * Now passes scan history and auto-scan state to the card builder.
 *
 * @return {Object} A single welcome card (NOT an array — homepage returns one card).
 */
function onHomepage() {
  var history = getHistory();
  var autoScan = PropertiesService.getScriptProperties().getProperty('AUTO_SCAN') === 'true';
  var blacklist = getBlacklist();
  return buildHomepageCard(history, autoScan, blacklist);
}

// ---------------------------------------------------------------------------
// Auto-scan toggle callback
// ---------------------------------------------------------------------------

/**
 * Toggles auto-scan mode on/off. Called from the homepage settings section.
 *
 * @param {Object} e - The action event object.
 * @return {Object} CardService action response that updates the homepage card.
 */
function toggleAutoScan(e) {
  var props = PropertiesService.getScriptProperties();
  var current = props.getProperty('AUTO_SCAN');
  var newVal = (current === 'true') ? 'false' : 'true';
  props.setProperty('AUTO_SCAN', newVal);

  var history = getHistory();
  var blacklist = getBlacklist();
  return CardService.newActionResponseBuilder()
    .setNavigation(CardService.newNavigation().updateCard(
      buildHomepageCard(history, newVal === 'true', blacklist)
    ))
    .build();
}

// ---------------------------------------------------------------------------
// Scan history helpers (UserProperties)
// ---------------------------------------------------------------------------

var HISTORY_KEY = 'SCAN_HISTORY';
var MAX_HISTORY = 10;

/**
 * Saves a scan result to user history.
 *
 * @param {Object} result - The AnalyzeResponse JSON (or blacklist hit result).
 * @param {string} sender - The sender address.
 * @param {string} subject - The email subject.
 */
function saveToHistory(result, sender, subject) {
  try {
    var history = getHistory();
    history.unshift({
      sender:  (sender || '').substring(0, 120),
      subject: (subject || '').substring(0, 120),
      score:   result.score != null ? result.score : 0,
      verdict: result.verdict || 'UNKNOWN',
      ts:      new Date().toISOString()
    });
    if (history.length > MAX_HISTORY) {
      history = history.slice(0, MAX_HISTORY);
    }
    PropertiesService.getUserProperties().setProperty(HISTORY_KEY, JSON.stringify(history));
  } catch (err) {
    Logger.log('saveToHistory error: ' + err.message);
  }
}

/**
 * Reads scan history from UserProperties.
 *
 * @return {Array} Array of history items, newest first.
 */
function getHistory() {
  try {
    var raw = PropertiesService.getUserProperties().getProperty(HISTORY_KEY);
    return raw ? JSON.parse(raw) : [];
  } catch (err) {
    Logger.log('getHistory error: ' + err.message);
    return [];
  }
}

// ---------------------------------------------------------------------------
// Blacklist helpers (UserProperties)
// ---------------------------------------------------------------------------

var BLACKLIST_KEY = 'BLACKLIST';

/**
 * Extracts the domain from a sender string like "Name <user@domain.com>".
 *
 * @param {string} sender - Full sender string.
 * @return {string} Lowercase domain, or empty string if unparseable.
 */
function extractDomain(sender) {
  var match = (sender || '').match(/@([^>\s]+)/);
  return match ? match[1].toLowerCase() : '';
}

/**
 * Checks if a sender's domain is on the user blacklist.
 *
 * @param {string} sender - Full sender string.
 * @return {boolean} True if blacklisted.
 */
function isBlacklisted(sender) {
  var domain = extractDomain(sender);
  if (!domain) return false;
  var list = getBlacklist();
  return list.indexOf(domain) !== -1;
}

/**
 * Reads the blacklist from UserProperties.
 *
 * @return {Array} Array of blocked domain strings.
 */
function getBlacklist() {
  try {
    var raw = PropertiesService.getUserProperties().getProperty(BLACKLIST_KEY);
    return raw ? JSON.parse(raw) : [];
  } catch (err) {
    Logger.log('getBlacklist error: ' + err.message);
    return [];
  }
}

/**
 * Adds a domain to the blacklist.
 *
 * @param {string} domain - Lowercase domain string.
 */
function addToBlacklist(domain) {
  var list = getBlacklist();
  if (list.indexOf(domain) === -1) {
    list.push(domain);
    PropertiesService.getUserProperties().setProperty(BLACKLIST_KEY, JSON.stringify(list));
  }
}

/**
 * Removes a domain from the blacklist.
 *
 * @param {string} domain - Lowercase domain string.
 */
function removeFromBlacklist(domain) {
  var list = getBlacklist();
  var idx = list.indexOf(domain);
  if (idx !== -1) {
    list.splice(idx, 1);
    PropertiesService.getUserProperties().setProperty(BLACKLIST_KEY, JSON.stringify(list));
  }
}

/**
 * Action callback: block the sender's domain.
 * Called from the result card BLOCK SENDER button.
 *
 * @param {Object} e - Action event with e.parameters.sender.
 * @return {Object} CardService push-card navigation to confirmation card.
 */
function blockSender(e) {
  var sender = (e.parameters && e.parameters.sender) || '';
  var domain = extractDomain(sender);

  if (domain) {
    addToBlacklist(domain);
  }

  return CardService.newActionResponseBuilder()
    .setNavigation(CardService.newNavigation().pushCard(
      buildBlockedCard(domain)
    ))
    .build();
}

/**
 * Action callback: unblock a domain from the blacklist.
 * Called from the homepage blacklist section.
 *
 * @param {Object} e - Action event with e.parameters.domain.
 * @return {Object} CardService action response that updates the homepage card.
 */
function unblockSender(e) {
  var domain = (e.parameters && e.parameters.domain) || '';
  if (domain) {
    removeFromBlacklist(domain);
  }

  var history = getHistory();
  var autoScan = PropertiesService.getScriptProperties().getProperty('AUTO_SCAN') === 'true';
  var blacklist = getBlacklist();
  return CardService.newActionResponseBuilder()
    .setNavigation(CardService.newNavigation().updateCard(
      buildHomepageCard(history, autoScan, blacklist)
    ))
    .build();
}

/**
 * Builds a synthetic MALICIOUS result for blacklisted senders.
 * No API call is made — instant verdict.
 *
 * @param {string} sender - Full sender string.
 * @return {Object} Fake AnalyzeResponse-shaped object.
 */
function buildBlacklistHitResult(sender) {
  var domain = extractDomain(sender);
  return {
    request_id:          'blacklist-hit',
    score:               100,
    verdict:             'MALICIOUS',
    confidence:          100,
    confidence_label:    'High',
    explanation:         'This sender\'s domain (' + domain + ') is on your personal blacklist. ' +
                         'The email was flagged instantly without contacting external threat intelligence services.',
    signals:             [],
    top_contributors:    [{
      name:        'Blacklisted Domain',
      category:    'domain',
      severity:    'critical',
      description: 'Domain ' + domain + ' is on your personal blacklist.',
      value:       domain,
      points:      100
    }],
    evidence:            [{
      signal:    'Blacklisted Domain',
      source:    'User Blacklist',
      raw_value: domain,
      points:    100
    }],
    scoring_breakdown:   {
      total_points:    100,
      capped_points:   100,
      max_points:      100,
      formula:         'blacklist_override',
      category_points: { header: 0, url: 0, ip: 0, domain: 100, behavior: 0 }
    },
    source_availability: { virustotal: true, safe_browsing: true, abuseipdb: true, whois: true },
    analysis_time_ms:    0
  };
}

// ---------------------------------------------------------------------------
// Email data extraction
// ---------------------------------------------------------------------------

/**
 * Extracts all required email fields for the /analyze API call.
 * Uses getRawContent() to capture ALL Received headers — not just the first.
 * See PLAN.md Phase 5.3 for the rationale.
 *
 * @param {GmailMessage} message - The Gmail message object.
 * @return {Object} The payload object matching the AnalyzeRequest model.
 */
function extractEmailPayload(message) {
  var raw = message.getRawContent();

  // --- Received headers (all of them, ordered) ---
  var receivedHeaders = [];
  var receivedMatches = raw.match(/^Received:[ \t].*(?:\r?\n[ \t].*)*/gmi);
  if (receivedMatches) {
    receivedHeaders = receivedMatches;
  }

  // --- Authentication-Results header ---
  var authMatch = raw.match(/^Authentication-Results:[ \t].*(?:\r?\n[ \t].*)*/mi);
  var authResults = authMatch ? authMatch[0] : '';

  // --- URLs from HTML body (de-duplicated, capped at 10) ---
  var body = message.getBody(); // HTML
  var urlMatches = body.match(/https?:\/\/[^\s"'<>]+/g) || [];
  var urls = [];
  var seen = {};
  for (var i = 0; i < urlMatches.length && urls.length < 10; i++) {
    var u = urlMatches[i].replace(/[.,;)]+$/, ''); // strip trailing punctuation
    if (!seen[u]) {
      seen[u] = true;
      urls.push(u);
    }
  }

  // --- Plain text body (for behavior analysis) ---
  var plainBody = message.getPlainBody() || '';

  return {
    subject:                message.getSubject() || '',
    sender:                 message.getFrom()    || '',
    reply_to:               message.getHeader('Reply-To') || null,
    authentication_results: authResults || null,
    received_headers:       receivedHeaders,
    body_plain:             plainBody.substring(0, 50000),
    body_html:              body.substring(0, 100000),
    urls:                   urls,
    message_date:           message.getDate() ? message.getDate().toISOString() : null
  };
}


