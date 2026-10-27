/**
 * CalmGuard AI - Discord Alert Dispatcher & Tool Providers
 */

function sendDiscordAlert(webhookUrl, analysis, emailMeta) {
  if (!webhookUrl) {
    Logger.log("Discord Webhook URL not provided. Skipping notification.");
    return;
  }

  const scriptProps = PropertiesService.getScriptProperties();
  const webAppUrl = scriptProps.getProperty("WEB_APP_URL") || ScriptApp.getService().getUrl();
  const adminSecret = scriptProps.getProperty("ADMIN_SECRET") || "";

  let embedColor = 0x2ECC71; 
  let statusBadge = "✅ [VERIFIED SAFE]";
  
  if (analysis.threat_level === "HIGH") {
    embedColor = 0xE74C3C;   
    statusBadge = "🚨 [HIGH RISK PHISHING]";
  } else if (analysis.threat_level === "MEDIUM") {
    embedColor = 0xE67E22;   
    statusBadge = "⚠️ [SUSPICIOUS / MEDIUM RISK]";
  }

  const detectedTacticsFormatted = (analysis.detected_tactics && analysis.detected_tactics.length > 0)
    ? analysis.detected_tactics.map(t => "• " + t).join("\n")
    : "No malicious tactics detected.";

  const safeStepsFormatted = (analysis.recommended_actions && analysis.recommended_actions.length > 0)
    ? analysis.recommended_actions.map(a => "• " + a).join("\n")
    : "No action required.";

  const evidence = analysis.evidence_breakdown || {};
  const evidenceFormatted = 
    "**Sender:** " + (evidence.sender_analysis || "N/A") + "\n" +
    "**Domain:** " + (evidence.domain_check || "N/A") + "\n" +
    "**URL:** " + (evidence.url_check || "N/A") + "\n" +
    "**Financial:** " + (evidence.financial_check || "N/A") + "\n" +
    "**Visual:** " + (evidence.visual_check || "N/A");

  const titleText = `${statusBadge} ${analysis.summary_title || "Email Threat Assessment"}`;

// --- DIRECT GMAIL SEARCH LINK FOR QUARANTINE ---
  const threadId = emailMeta.threadId || "";
  const tokenParam = adminSecret ? `&token=${encodeURIComponent(adminSecret)}` : "";

  // Opens Gmail directly to the quarantined emails search filter
  const quarantineViewUrl = "https://mail.google.com/mail/u/0/#search/label%3ACalmGuard%2FQuarantine";
  
  const falsePositiveUrl = `${webAppUrl}?action=false_positive&threadId=${encodeURIComponent(threadId)}${tokenParam}`;
  const verifyScamUrl = `${webAppUrl}?action=verify_scam&threadId=${encodeURIComponent(threadId)}${tokenParam}`;

  const auditSheetUrl = emailMeta.auditSheetId
    ? `https://docs.google.com/spreadsheets/d/${emailMeta.auditSheetId}/edit`
    : "https://docs.google.com/";

  const actionControls = 
    `📁 [**Show Quarantine List**](${quarantineViewUrl})\n` +
    `✅ [**Mark as False Positive**](${falsePositiveUrl})\n` +
    `🚨 [**Verify Scam**](${verifyScamUrl})\n` +
    `📊 [**Review Audit Log**](${auditSheetUrl})`;

  const payload = {
    username: "CalmGuard AI Defender",
    avatar_url: "https://cdn-icons-png.flaticon.com/512/2092/2092663.png",
    embeds: [
      {
        title: titleText.substring(0, 256),
        description: `**Threat Category:** ${analysis.phishing_type || "Threat Alert"}\n\n` +
                     `**🎮 HUMAN-IN-THE-LOOP ACTIONS:**\n${actionControls}`,
        color: embedColor,
        fields: [
          { name: "📧 Subject", value: (emailMeta.subject || "(No Subject)").substring(0, 1024), inline: false },
          { name: "👤 Sender", value: "`" + (emailMeta.sender || "Unknown").substring(0, 250) + "`", inline: true },
          { name: "🎯 Confidence", value: (analysis.confidence_score || 0) + "%", inline: true },
          { name: "🚩 Tactics", value: detectedTacticsFormatted.substring(0, 1024), inline: false },
          { name: "🔍 Evidence", value: evidenceFormatted.substring(0, 1024), inline: false },
          { name: "⚖️ Uncertainty", value: (analysis.uncertainty_analysis || "None").substring(0, 1024), inline: false },
          { name: "🛡️ Actions", value: safeStepsFormatted.substring(0, 1024), inline: false }
        ],
        footer: {
          text: "CalmGuard AI • Auto-Quarantined from Inbox • Action Required"
        },
        timestamp: new Date().toISOString()
      }
    ]
  };

  const options = {
    method: "post",
    contentType: "application/json",
    payload: JSON.stringify(payload),
    muteHttpExceptions: true
  };

  try {
    const response = UrlFetchApp.fetch(webhookUrl, options);
    Logger.log("Discord notification response: " + response.getResponseCode());
  } catch (error) {
    Logger.log("Failed to send Discord alert: " + error.message);
  }
}

/**
 * Test function to verify Discord alerts and direct Web App Action Links
 */
function testDiscordActionButtons() {
  const scriptProperties = PropertiesService.getScriptProperties();
  const discordWebhook = scriptProperties.getProperty("TARGET_DESTINATION");
  const auditSheetId = scriptProperties.getProperty("AUDIT_SHEET_ID");

  const testAnalysis = {
    is_phishing: true,
    threat_level: "HIGH",
    confidence_score: 96,
    phishing_type: "Fee Fraud / Financial Impersonation",
    summary_title: "Fake Tuition Fee Payment Notice",
    detected_tactics: ["Typosquatted domain", "Touch 'n Go QR code attached", "Manufactured urgency"],
    evidence_breakdown: {
      sender_analysis: "External account mimicking administrative bursary.",
      domain_check: "Domain 'utar-tuition-payment.xyz' flagged as malicious.",
      url_check: "QR code decoded to unauthorized checkout gateway.",
      financial_check: "Demanded direct transfer via non-official e-wallet channel.",
      visual_check: "Institutional emblem placed alongside unauthorized QR code."
    },
    uncertainty_analysis: "High confidence on malicious indicators. Lack of raw email transport headers.",
    recommended_actions: ["Do not transfer funds.", "Notify IT Security Helpdesk."]
  };

  const emailMeta = {
    subject: "URGENT: Outstanding Semester Balance Deactivation Notice - Action Required",
    sender: "bursary-support@utar-tuition-payment.xyz",
    threadId: "test_thread_12345",
    auditSheetId: auditSheetId,
    rowIndex: 2
  };

  sendDiscordAlert(discordWebhook, testAnalysis, emailMeta);
  Logger.log("Test Discord alert dispatched with direct Apps Script web app links.");
}