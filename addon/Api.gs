/**
 * Phase 5 — Backend API client (Api.gs)
 * Handles the UrlFetchApp call to the FastAPI /analyze endpoint.
 *
 * Security notes:
 * - API key is read from Script Properties (never hardcoded).
 * - muteHttpExceptions: true prevents UrlFetchApp from throwing on 4xx/5xx.
 *   All error handling is done manually with explicit response codes.
 * - Request timeout is governed by the Apps Script 30s execution limit.
 */

/**
 * Calls the backend /analyze endpoint with the extracted email payload.
 *
 * @param {Object} payload - The AnalyzeRequest payload object.
 * @return {Object} Parsed JSON response, or {error: string} on failure.
 */
function callAnalyzeEndpoint(payload) {
  var props       = PropertiesService.getScriptProperties();
  var apiKey      = props.getProperty('BACKEND_API_KEY');
  var backendUrl  = props.getProperty('BACKEND_URL');

  if (!backendUrl || !apiKey) {
    return {
      error: 'Backend not configured. Please run the setup() function in the Apps Script editor.'
    };
  }

  var options = {
    method:          'post',
    contentType:     'application/json',
    payload:         JSON.stringify(payload),
    headers:         { 'X-API-Key': apiKey },
    muteHttpExceptions: true  // handle all HTTP errors manually — never let fetch throw
  };

  var response;
  try {
    response = UrlFetchApp.fetch(backendUrl + '/analyze', options);
  } catch (err) {
    // Network-level failure (DNS error, connection refused, etc.)
    Logger.log('UrlFetchApp network error: ' + err.message);
    return { error: 'Could not reach the analysis backend. Check your internet connection.' };
  }

  var code = response.getResponseCode();
  var body = response.getContentText();

  Logger.log('Backend response code: ' + code);

  if (code === 200) {
    try {
      return JSON.parse(body);
    } catch (parseErr) {
      Logger.log('JSON parse error: ' + parseErr.message + ' | body: ' + body.substring(0, 200));
      return { error: 'Backend returned malformed JSON.' };
    }
  }

  if (code === 401) {
    return { error: 'Authentication failed. Check that the API key in Script Properties matches the backend.' };
  }
  if (code === 429) {
    return { error: 'Rate limit reached. Wait a minute before analyzing another email.' };
  }
  if (code >= 500) {
    return { error: 'Backend server error (' + code + '). The analysis service may be starting up — try again in 10 seconds.' };
  }

  return { error: 'Backend returned unexpected status ' + code + '.' };
}

/**
 * Calls the backend /health endpoint.
 * Use this in the setup flow to verify connectivity before the demo.
 *
 * @return {Object} Health response or error object.
 */
function checkBackendHealth() {
  var backendUrl = PropertiesService.getScriptProperties().getProperty('BACKEND_URL');
  if (!backendUrl) {
    return { error: 'BACKEND_URL not configured.' };
  }

  try {
    var response = UrlFetchApp.fetch(backendUrl + '/health', { muteHttpExceptions: true });
    if (response.getResponseCode() === 200) {
      return JSON.parse(response.getContentText());
    }
    return { error: 'Health check returned ' + response.getResponseCode() };
  } catch (err) {
    return { error: 'Health check failed: ' + err.message };
  }
}
