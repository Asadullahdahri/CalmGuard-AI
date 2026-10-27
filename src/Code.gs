/**
 * CalmGuard AI - Core Pipeline Orchestrator with 5-Model Fallback Rotation
 */

const CONFIG = {
  MODELS: [
    "gemini-3.8-flash",
    "gemini-3.7-flash",
    "gemini-3.6-flash",
    "gemini-3.5-flash",
    "gemini-3.5-flash-lite"
  ],
  LABEL_SECURE: "CalmGuard/Secure",
  LABEL_QUARANTINE: "CalmGuard/Quarantine",
  MAX_THREADS: 5,
  SUPPORTED_IMAGE_TYPES: ["image/jpeg", "image/png", "image/webp"]
};

/**
 * Main execution function triggered manually or via time-driven trigger.
 */
function runEmailTriage() {
  const scriptProperties = PropertiesService.getScriptProperties();
  const apiKey = scriptProperties.getProperty("GEMINI_API_KEY");
  const discordWebhook = scriptProperties.getProperty("TARGET_DESTINATION");
  const auditSheetId = scriptProperties.getProperty("AUDIT_SHEET_ID");

  if (!apiKey || !discordWebhook) {
    throw new Error("Missing GEMINI_API_KEY or TARGET_DESTINATION in Script Properties.");
  }

  let labelSecure = GmailApp.getUserLabelByName(CONFIG.LABEL_SECURE) || GmailApp.createLabel(CONFIG.LABEL_SECURE);
  let labelQuarantine = GmailApp.getUserLabelByName(CONFIG.LABEL_QUARANTINE) || GmailApp.createLabel(CONFIG.LABEL_QUARANTINE);

  const searchQuery = `is:unread -label:${CONFIG.LABEL_SECURE} -label:${CONFIG.LABEL_QUARANTINE}`;
  const threads = GmailApp.search(searchQuery, 0, CONFIG.MAX_THREADS);
  Logger.log(`Found ${threads.length} unread and unprocessed thread(s) to process.`);

  threads.forEach(thread => {
    const messages = thread.getMessages();
    const latestMessage = messages[messages.length - 1];

    const rawSubject = latestMessage.getSubject() || "";
    const rawBody = latestMessage.getPlainBody() || "";
    const sender = latestMessage.getFrom() || "";
    const threadId = thread.getId();

    const cleanSubject = redactPII(rawSubject);
    const cleanBody = redactPII(rawBody);

    let qrDecoderResults = [];
    const attachments = latestMessage.getAttachments();
    const multimodalParts = [];

    attachments.forEach(att => {
      const mime = att.getContentType();
      if (CONFIG.SUPPORTED_IMAGE_TYPES.includes(mime)) {
        const qrScan = externalDecodeQRCodeFromBytes(att.getBytes(), mime);
        if (qrScan.qr_found && qrScan.decoded_content) {
          qrDecoderResults.push(qrScan.decoded_content);
        }

        multimodalParts.push({
          inlineData: { mimeType: mime, data: Utilities.base64Encode(att.getBytes()) }
        });
      } else if (mime === "application/pdf") {
        multimodalParts.push({
          inlineData: { mimeType: mime, data: Utilities.base64Encode(att.getBytes()) }
        });
      }
    });

    const initialTextPayload = `
EMAIL TO ANALYZE:
----------------
Sender: ${sender}
Subject: ${cleanSubject}
Body:
${cleanBody}

EXTERNAL QR CODE TOOL DECODE RESULTS:
------------------------------------
${qrDecoderResults.length > 0 ? JSON.stringify(qrDecoderResults) : "No QR codes detected in visual attachments."}
`;

    const userParts = [{ text: initialTextPayload }, ...multimodalParts];
    const agentResult = callGeminiAgent(apiKey, userParts);

    if (agentResult && agentResult.analysis) {
      const analysis = agentResult.analysis;
      const toolsUsed = agentResult.toolsInvoked;

      const emailMeta = {
        subject: cleanSubject,
        sender: sender,
        threadId: threadId,
        auditSheetId: auditSheetId
      };

      let sheetRowIndex = null;
      if (auditSheetId) {
        sheetRowIndex = logTriageToAuditSheet(auditSheetId, analysis, emailMeta, toolsUsed);
      }
      emailMeta.rowIndex = sheetRowIndex;

      const isThreat = analysis.is_phishing || analysis.threat_level === "HIGH" || analysis.threat_level === "MEDIUM";

      if (isThreat) {
        thread.addLabel(labelQuarantine);
        thread.moveToArchive();
        Logger.log(`[QUARANTINED] Moved thread ${threadId} out of Inbox.`);
        sendDiscordAlert(discordWebhook, analysis, emailMeta);
      } else {
        thread.addLabel(labelSecure);
        Logger.log(`[SECURE] Tagged thread ${threadId} as secure.`);
      }
    }
  });
}

/**
 * Multi-turn Gemini Agent Execution Loop with 5-Model Automatic Fallback Rotation
 */
function callGeminiAgent(apiKey, userParts) {
  for (let m = 0; m < CONFIG.MODELS.length; m++) {
    const currentModel = CONFIG.MODELS[m];
    const url = `https://generativelanguage.googleapis.com/v1beta/models/${currentModel}:generateContent?key=${apiKey}`;

    let contents = [{ role: "user", parts: userParts }];
    const tools = getGeminiToolDeclarations();
    let toolsInvoked = [];
    let modelFailed = false;

    for (let turn = 0; turn < 3; turn++) {
      const payload = {
        contents: contents,
        systemInstruction: { parts: [{ text: PROMPT_SYSTEM_INSTRUCTIONS }] },
        tools: tools
      };

      const options = {
        method: "post",
        contentType: "application/json",
        payload: JSON.stringify(payload),
        muteHttpExceptions: true
      };

      const response = UrlFetchApp.fetch(url, options);
      const responseCode = response.getResponseCode();
      const responseText = response.getContentText();

      if (responseCode === 503 || responseText.includes("high demand") || responseText.includes("UNAVAILABLE")) {
        Logger.log(`[Model Overloaded] Model ${currentModel} failed. Rotating fallback...`);
        modelFailed = true;
        break;
      }

      const json = JSON.parse(responseText);
      if (!json.candidates || !json.candidates[0].content) {
        modelFailed = true;
        break;
      }

      const candidateMessage = json.candidates[0].content;
      contents.push(candidateMessage);

      const functionCallPart = candidateMessage.parts.find(p => p.functionCall);

      if (functionCallPart) {
        const call = functionCallPart.functionCall;
        toolsInvoked.push(call.name);
        
        let toolResult = {};
        if (call.name === "check_domain_reputation") {
          toolResult = externalCheckDomainReputation(call.args);
        }

        contents.push({
          role: "user",
          parts: [{ functionResponse: { name: call.name, response: { result: toolResult } } }]
        });
      } else {
        const textPart = candidateMessage.parts.find(p => p.text);
        if (textPart) {
          try {
            const cleaned = textPart.text.replace(/```json\n?|```/g, "").trim();
            return { analysis: JSON.parse(cleaned), toolsInvoked: toolsInvoked };
          } catch (e) {
            modelFailed = true;
            break;
          }
        }
        break;
      }
    }

    if (!modelFailed) break;
  }
  return null;
}

/**
 * Web App Endpoint: Handles GET requests (Quarantine dashboard view & quick actions)
 */
function doGet(e) {
  try {
    const scriptProps = PropertiesService.getScriptProperties();
    const expectedSecret = scriptProps.getProperty("ADMIN_SECRET");
    const auditSheetId = scriptProps.getProperty("AUDIT_SHEET_ID");

    const params = e.parameter || {};
    const action = params.action || "view_quarantine";
    const threadId = params.threadId || "";
    const providedToken = params.token || "";

    if (expectedSecret && providedToken !== expectedSecret) {
      return HtmlService.createHtmlOutput("<h3 style='color:#E74C3C;font-family:sans-serif;text-align:center;margin-top:50px;'>🔒 403 Unauthorized</h3>");
    }

    if (action === "view_quarantine") {
      const label = GmailApp.getUserLabelByName(CONFIG.LABEL_QUARANTINE);
      const threads = label ? label.getThreads(0, 10) : [];
      const webAppUrl = scriptProps.getProperty("WEB_APP_URL") || ScriptApp.getService().getUrl();

      let itemsHtml = "";
      threads.forEach(t => {
        const msg = t.getMessages()[0];
        const tId = t.getId();
        const fpLink = `${webAppUrl}?action=false_positive&threadId=${tId}&token=${encodeURIComponent(providedToken)}`;
        const vsLink = `${webAppUrl}?action=verify_scam&threadId=${tId}&token=${encodeURIComponent(providedToken)}`;

        itemsHtml += `
          <div style="border-left:4px solid #E74C3C; background:#fafafa; padding:12px; margin-bottom:12px; border-radius:4px; text-align:left;">
            <h4 style="margin:0 0 5px 0;">${msg.getSubject()}</h4>
            <p style="margin:0 0 10px 0; font-size:12px; color:#666;"><b>Sender:</b> ${msg.getFrom()}</p>
            <a href="${fpLink}" style="background:#2ECC71; color:white; padding:6px 12px; text-decoration:none; border-radius:4px; font-size:12px; font-weight:bold; margin-right:6px;">✅ False Positive</a>
            <a href="${vsLink}" style="background:#E74C3C; color:white; padding:6px 12px; text-decoration:none; border-radius:4px; font-size:12px; font-weight:bold;">🚨 Verify Scam</a>
          </div>
        `;
      });

      if (!itemsHtml) itemsHtml = "<p>✅ No emails currently in quarantine!</p>";

      return HtmlService.createHtmlOutput(`<!DOCTYPE html><html><body style="font-family:sans-serif; background:#f4f6f9; padding:30px 15px; text-align:center;"><div style="background:white; max-width:550px; margin:auto; padding:25px; border-radius:10px; box-shadow:0 4px 12px rgba(0,0,0,0.1);"><h2 style="margin-top:0; color:#2C3E50;">📂 Active Quarantine List</h2>${itemsHtml}</div></body></html>`);
    }

    if (action === "false_positive" || action === "verify_scam") {
      if (!threadId || threadId.startsWith("test_")) {
        return HtmlService.createHtmlOutput(`<html><body style="font-family:sans-serif; text-align:center; padding-top:60px; background:#f4f6f9;"><div style="background:white; padding:30px; border-radius:10px; display:inline-block;"><h2 style="color:#2ECC71;">✅ Test Action Completed</h2></div></body></html>`);
      }

      const thread = GmailApp.getThreadById(threadId);
      if (!thread) return HtmlService.createHtmlOutput("<h3 style='color:red;text-align:center;'>Error: Thread not found.</h3>");

      const labelQuarantine = GmailApp.getUserLabelByName(CONFIG.LABEL_QUARANTINE) || GmailApp.createLabel(CONFIG.LABEL_QUARANTINE);
      const labelSecure = GmailApp.getUserLabelByName(CONFIG.LABEL_SECURE) || GmailApp.createLabel(CONFIG.LABEL_SECURE);
      const subject = thread.getFirstMessageSubject();

      if (action === "verify_scam") {
        try { thread.removeLabel(labelSecure); } catch (err) {}
        thread.addLabel(labelQuarantine);
        thread.moveToArchive();
      } else {
        try { thread.removeLabel(labelQuarantine); } catch (err) {}
        thread.addLabel(labelSecure);
        thread.moveToInbox();
      }

      if (auditSheetId) {
        const ss = SpreadsheetApp.openById(auditSheetId);
        const sheet = ss.getSheetByName("CalmGuard_Audit_Logs");
        if (sheet) {
          const data = sheet.getDataRange().getValues();
          for (let i = data.length - 1; i >= 1; i--) {
            if ((data[i][9] && data[i][9].toString().includes(threadId)) || (subject && data[i][2].toString().includes(subject))) {
              sheet.getRange(i + 1, 9).setValue(action === "verify_scam" ? "Verified as Scam" : "False Positive");
              if (action === "false_positive") sheet.getRange(i + 1, 6).setValue("None (False Positive)");
              break;
            }
          }
        }
      }

      return HtmlService.createHtmlOutput(`<!DOCTYPE html><html><head><meta name="viewport" content="width=device-width, initial-scale=1"></head><body style="font-family:sans-serif; text-align:center; padding-top:60px; background:#f4f6f9;"><div style="background:white; padding:30px; border-radius:10px; max-width:450px; margin:auto;"><h2 style="color:${action === "verify_scam" ? "#E74C3C" : "#2ECC71"};">${action === "verify_scam" ? "🚨 Verified as Scam" : "✅ Marked as False Positive"}</h2><p>You can now close this window and return to Discord.</p></div></body></html>`);
    }
  } catch (err) {
    return HtmlService.createHtmlOutput(`<h3 style="color:red;text-align:center;">Error: ${err.message}</h3>`);
  }
}

/**
 * Web App Endpoint: Handles POST requests from external frontend interfaces.
 */
function doPost(e) {
  try {
    const scriptProps = PropertiesService.getScriptProperties();
    const expectedSecret = scriptProps.getProperty("ADMIN_SECRET");
    const auditSheetId = scriptProps.getProperty("AUDIT_SHEET_ID");

    let data = {};
    if (e.postData && e.postData.contents) {
      const raw = e.postData.contents;
      if (raw.trim().startsWith("{")) {
        try { data = JSON.parse(raw); } catch (err) {}
      } else {
        raw.split("&").forEach(p => {
          const pair = p.split("=");
          if (pair.length === 2) data[decodeURIComponent(pair[0])] = decodeURIComponent(pair[1].replace(/\+/g, " "));
        });
      }
    }
    
    if (!data.token && e.parameter) data = e.parameter;

    if (!expectedSecret || data.token !== expectedSecret) {
      return HtmlService.createHtmlOutput("<h3 style='color:#E74C3C; font-family:sans-serif; text-align:center; margin-top:50px;'>🔒 403 Forbidden</h3>");
    }

    if (data.type === "discord_action") {
      const action = data.action;
      const threadId = data.threadId;

      if (!threadId || threadId.startsWith("test_")) {
        return HtmlService.createHtmlOutput(`<html><body><h2>✅ Test Action Processed Successfully</h2></body></html>`);
      }

      const thread = GmailApp.getThreadById(threadId);
      if (!thread) return HtmlService.createHtmlOutput("<h3>Error: Gmail thread not found.</h3>");

      const labelQuarantine = GmailApp.getUserLabelByName(CONFIG.LABEL_QUARANTINE) || GmailApp.createLabel(CONFIG.LABEL_QUARANTINE);
      let labelSecure = GmailApp.getUserLabelByName(CONFIG.LABEL_SECURE) || GmailApp.createLabel(CONFIG.LABEL_SECURE);
      const subject = thread.getFirstMessageSubject();

      if (action === "verify_scam") {
        try { thread.removeLabel(labelSecure); } catch (err) {}
        thread.addLabel(labelQuarantine);
        thread.moveToArchive();
      } else {
        try { thread.removeLabel(labelQuarantine); } catch (err) {}
        thread.addLabel(labelSecure);
        thread.moveToInbox();
      }

      if (auditSheetId) {
        const ss = SpreadsheetApp.openById(auditSheetId);
        const sheet = ss.getSheetByName("CalmGuard_Audit_Logs");
        if (sheet) {
          const sheetData = sheet.getDataRange().getValues();
          for (let i = sheetData.length - 1; i >= 1; i--) {
            if ((sheetData[i][9] && sheetData[i][9].toString().includes(threadId)) || (subject && sheetData[i][2].toString().includes(subject))) {
              sheet.getRange(i + 1, 9).setValue(action === "verify_scam" ? "Verified as Scam" : "False Positive");
              if (action === "false_positive") sheet.getRange(i + 1, 6).setValue("None (False Positive)");
              break;
            }
          }
        }
      }

      return HtmlService.createHtmlOutput(`<!DOCTYPE html><html><body style="font-family:Arial; text-align:center; margin-top:60px;"><h2 style="color:${action === "verify_scam" ? "#E74C3C" : "#2ECC71"};">${action === "verify_scam" ? "🚨 Verified as Scam" : "✅ Marked as False Positive"}</h2><p>You can close this tab and return to Discord.</p></body></html>`);
    }

    return ContentService.createTextOutput(JSON.stringify({ status: "ok" })).setMimeType(ContentService.MimeType.JSON);
  } catch (err) {
    return HtmlService.createHtmlOutput(`<h3 style='color:red;'>Failed: ${err.message}</h3>`);
  }
}

/**
 * Logs sandbox test results into a dedicated "CalmGuard_Sandbox_Logs" sheet tab.
 */
function logSandboxToAuditSheet(sheetId, analysis, emailMeta, testType, rawContent) {
  try {
    const ss = SpreadsheetApp.openById(sheetId);
    let sheet = ss.getSheetByName("CalmGuard_Sandbox_Logs");

    if (!sheet) {
      sheet = ss.insertSheet("CalmGuard_Sandbox_Logs");
      sheet.appendRow(["Timestamp", "Test Type", "Content Snippet", "Threat Level", "Confidence Score", "Phishing Type", "Uncertainty Note"]);
      sheet.setFrozenRows(1);
    }

    const timestamp = new Date().toLocaleString("en-GB", { timeZone: "Asia/Kuala_Lumpur" });
    sheet.appendRow([
      timestamp,
      testType.toUpperCase(),
      rawContent.substring(0, 100) + "...",
      analysis.threat_level || "UNKNOWN",
      (analysis.confidence_score || "N/A") + "%",
      analysis.phishing_type || "N/A",
      analysis.uncertainty_analysis || "None"
    ]);
  } catch (err) {
    Logger.log("Failed to write to Sandbox Audit Sheet: " + err.message);
  }
}