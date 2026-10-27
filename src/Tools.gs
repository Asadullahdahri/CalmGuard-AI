/**
 * CalmGuard AI - External Threat Intelligence & QR Decoding Tools
 */

/**
 * Tool 1: External Live URL & Domain Security Reputation Checker
 * Queries Cloudflare's Security Threat Intelligence (1.1.1.2 DoH)
 */
function externalCheckDomainReputation(params) {
  const domain = (params.domain || "").toLowerCase().trim();
  if (!domain) return { error: "No domain provided" };

  const OFFICIAL_DOMAINS = ["utar.edu.my", "1utar.my"];
  const isOfficial = OFFICIAL_DOMAINS.some(d => domain === d || domain.endsWith("." + d));

  let threatIntelResult = {
    domain: domain,
    is_official_campus_domain: isOfficial,
    is_blocked_by_security_dns: false,
    external_provider: "Cloudflare Security Threat Intel"
  };

  try {
    // Query Cloudflare's public security resolver (blocks malware/phishing)
    const dohUrl = `https://security.cloudflare-dns.com/dns-query?name=${encodeURIComponent(domain)}&type=A`;
    const response = UrlFetchApp.fetch(dohUrl, {
      method: "get",
      headers: { "Accept": "application/dns-json" },
      muteHttpExceptions: true
    });

    if (response.getResponseCode() === 200) {
      const dnsData = JSON.parse(response.getContentText());
      // Status 3 = NXDOMAIN, or returns blocked sinkhole IP (0.0.0.0)
      if (dnsData.Status === 3) {
        threatIntelResult.is_blocked_by_security_dns = true;
        threatIntelResult.risk_assessment = "HIGH: Non-existent or sinkholed domain";
      } else if (dnsData.Answer) {
        const hasSinkhole = dnsData.Answer.some(a => a.data === "0.0.0.0");
        if (hasSinkhole) {
          threatIntelResult.is_blocked_by_security_dns = true;
          threatIntelResult.risk_assessment = "CRITICAL: Blocked by Threat Intelligence DNS as malicious/phishing";
        } else {
          threatIntelResult.risk_assessment = isOfficial ? "SAFE: Verified official campus domain" : "UNVERIFIED: Active domain, not yet in public blocklists";
        }
      }
    }
  } catch (err) {
    threatIntelResult.error = "DNS Threat Lookup failed: " + err.message;
  }

  return threatIntelResult;
}

/**
 * Tool 2: External Optical QR Code Decoder API
 * Decodes QR images using goQR's public REST engine
 */
function externalDecodeQRCodeFromBytes(imageBytes, mimeType) {
  const apiUrl = "https://api.qrserver.com/v1/read-qr-code/";
  
  try {
    const boundary = "----WebKitFormBoundary" + Utilities.getUuid();
    let body = Utilities.newBlob("").getBytes();

    // Construct multipart/form-data payload
    const header = Utilities.newBlob(
      `--${boundary}\r\n` +
      `Content-Disposition: form-data; name="file"; filename="qrcode.${mimeType.includes("png") ? "png" : "jpg"}"\r\n` +
      `Content-Type: ${mimeType}\r\n\r\n`
    ).getBytes();
    
    const footer = Utilities.newBlob(`\r\n--${boundary}--\r\n`).getBytes();
    
    const payload = [].concat(header, imageBytes, footer);

    const options = {
      method: "post",
      contentType: `multipart/form-data; boundary=${boundary}`,
      payload: payload,
      muteHttpExceptions: true
    };

    const res = UrlFetchApp.fetch(apiUrl, options);
    const json = JSON.parse(res.getContentText());

    if (json && json[0] && json[0].symbol && json[0].symbol[0]) {
      const symbolData = json[0].symbol[0];
      if (symbolData.data) {
        return {
          qr_found: true,
          decoded_content: symbolData.data,
          error: null
        };
      }
    }
  } catch (e) {
    return { qr_found: false, error: e.message };
  }

  return { qr_found: false, decoded_content: null, error: "No readable QR code found in attachment." };
}

/**
 * Gemini Declarations for External Tools
 */
function getGeminiToolDeclarations() {
  return [
    {
      functionDeclarations: [
        {
          name: "check_domain_reputation",
          description: "Queries external Cloudflare Threat Intelligence DNS to inspect whether a domain or URL hostname is flagged for phishing or sinkholed.",
          parameters: {
            type: "OBJECT",
            properties: {
              domain: { 
                type: "STRING", 
                description: "The hostname or domain to query (e.g., 'utar-edu.my' or 'login-portal.top')" 
              }
            },
            required: ["domain"]
          }
        }
      ]
    }
  ];
}

/**
 * PII Redaction
 */
function redactPII(text) {
  if (!text) return "";
  return text
    .replace(/\b\d{6}-\d{2}-\d{4}\b/g, "[REDACTED_IC]")
    .replace(/\b(\+?60|0)1[0-9]-?[0-9]{7,8}\b/g, "[REDACTED_PHONE]")
    .replace(/\b(2\d{6})\b/g, "[REDACTED_STUDENT_ID]")
    .replace(/\b\d{10,16}\b/g, "[REDACTED_BANK_ACC]");
}


function testExternalTools() {
  // Test 1: External Threat Intel Lookup on a known safe institutional domain vs spoof
  Logger.log("Testing External Threat Intel Tool...");
  const officialCheck = externalCheckDomainReputation({ domain: "utar.edu.my" });
  Logger.log("Official domain result: " + JSON.stringify(officialCheck));

  const spoofCheck = externalCheckDomainReputation({ domain: "utar-tuition-payment.xyz" });
  Logger.log("Suspicious domain result: " + JSON.stringify(spoofCheck));

  // Test 2: External QR Code Decoding Tool
  Logger.log("Testing External QR Code Decoder Tool...");
  // Fetches a sample public QR image to test decoding
  const testQrImage = UrlFetchApp.fetch("https://api.qrserver.com/v1/create-qr-code/?size=150x150&data=https://utar-phish-portal.com").getBlob();
  const qrResult = externalDecodeQRCodeFromBytes(testQrImage.getBytes(), "image/png");
  Logger.log("QR Decoder Output: " + JSON.stringify(qrResult));
}

/**
 * Audit Log Subsystem: Logs forensic triage events to a Google Sheet and returns the row index.
 */
function logTriageToAuditSheet(sheetId, analysis, emailMeta, toolsUsed) {
  if (!sheetId) {
    Logger.log("No AUDIT_SHEET_ID configured. Skipping audit logging.");
    return null;
  }

  try {
    const ss = SpreadsheetApp.openById(sheetId);
    let sheet = ss.getSheetByName("CalmGuard_Audit_Logs");

    if (!sheet) {
      const oldSheet = ss.getSheetByName("Triage_Audit_Log");
      if (oldSheet) {
        oldSheet.setName("CalmGuard_Audit_Logs");
        sheet = oldSheet;
      } else {
        sheet = ss.insertSheet("CalmGuard_Audit_Logs");
        sheet.appendRow([
          "Timestamp",
          "Sender",
          "Subject",
          "Threat Level",
          "Confidence Score",
          "Phishing Type",
          "Tools Invoked",
          "Uncertainty Note",
          "Human Review Status",
          "Direct Email Link"
        ]);
        sheet.setFrozenRows(1);
      }
    }

    const timestamp = new Date().toLocaleString("en-GB", { timeZone: "Asia/Kuala_Lumpur" });
    const threatLevel = analysis.threat_level || "UNKNOWN";
    
    let rawConf = analysis.confidence_score;
    let confidenceNum = 95;
    if (typeof rawConf === "number") {
      confidenceNum = rawConf <= 1 ? Math.round(rawConf * 100) : Math.round(rawConf);
    } else if (typeof rawConf === "string") {
      const parsed = parseFloat(rawConf.replace("%", ""));
      confidenceNum = !isNaN(parsed) ? (parsed <= 1 ? Math.round(parsed * 100) : Math.round(parsed)) : 95;
    }
    const confidenceFormatted = confidenceNum + "%";

    const phishingType = analysis.phishing_type || "N/A";
    const toolsStr = toolsUsed && toolsUsed.length > 0 ? toolsUsed.join(", ") : "None";
    const uncertainty = analysis.uncertainty_analysis || "None";
    const defaultReviewStatus = analysis.threat_level === "HIGH" ? "Pending Review" : "Auto-Resolved";

    // Point the sheet's Direct Email Link to the mobile-safe Web App Single Email Inspector
    const threadId = emailMeta.threadId || "";
    const webAppUrl = PropertiesService.getScriptProperties().getProperty("WEB_APP_URL") || "";
    const directEmailUrl = (webAppUrl && threadId)
      ? `${webAppUrl}?action=view_single&threadId=${encodeURIComponent(threadId)}`
      : "https://mail.google.com/";
      
    sheet.appendRow([
      timestamp,
      emailMeta.sender || "Unknown",
      emailMeta.subject || "No Subject",
      threatLevel,
      confidenceFormatted,
      phishingType,
      toolsStr,
      uncertainty,
      defaultReviewStatus,
      directEmailUrl
    ]);

    // Return the exact row index that was just added
    const insertedRowIndex = sheet.getLastRow();
    Logger.log("Audit log row recorded successfully at row index: " + insertedRowIndex);
    return insertedRowIndex;

  } catch (err) {
    Logger.log("Failed to write to Audit Sheet: " + err.message);
    return null;
  }
}