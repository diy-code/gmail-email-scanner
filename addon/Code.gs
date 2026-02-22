/**
 * Phase 5 — Gmail Add-on entry point (Code.gs)
 * Handles the contextual trigger (email open), the "Analyze" button action,
 * and the homepage trigger (no email open).
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
    'BACKEND_URL': 'https://REPLACE_WITH_YOUR_CLOUD_RUN_URL',
    'BACKEND_API_KEY': 'REPLACE_WITH_YOUR_API_KEY'
  });
  Logger.log('Setup complete. Backend URL and API key stored in Script Properties.');
}

// ---------------------------------------------------------------------------
// Contextual trigger — fires when user opens any email
// ---------------------------------------------------------------------------

/**
 * Called automatically when the user opens a Gmail message.
 * Returns the initial "Analyze Email" card.
 *
 * @param {Object} e - The event object from the Gmail contextual trigger.
 * @return {Array} Array containing the initial card.
 */
function onGmailMessageOpen(e) {
  // Required before any GmailApp call — PLAN.md Phase 5.2 critical note
  GmailApp.setCurrentMessageAccessToken(e.gmail.accessToken);

  try {
    var messageId = e.gmail.messageId;
    var message = GmailApp.getMessageById(messageId);

    var subject = message.getSubject() || '(No Subject)';
    var sender  = message.getFrom()    || '(Unknown Sender)';

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

    // Show a loading card while analysis runs
    // (Apps Script is synchronous — we show a brief status via card title)
    var result = callAnalyzeEndpoint(payload);

    if (result.error) {
      return CardService.newActionResponseBuilder()
        .setNavigation(CardService.newNavigation().pushCard(
          buildErrorCard('Analysis failed: ' + result.error)
        ))
        .build();
    }

    return CardService.newActionResponseBuilder()
      .setNavigation(CardService.newNavigation().pushCard(
        buildResultCard(result)
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
 *
 * @return {Object} A single welcome card (NOT an array — homepage returns one card).
 */
function onHomepage() {
  return buildHomepageCard();
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
