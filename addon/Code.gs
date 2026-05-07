const BACKEND_BASE_URL = "https://contend-dealer-flagpole.ngrok-free.dev";

function buildHomePage(e) {
  const section = CardService.newCardSection()
    .addWidget(
      CardService.newTextParagraph()
        .setText("Open an email in Gmail to analyze it.")
    );

  return CardService.newCardBuilder()
    .setHeader(
      CardService.newCardHeader()
        .setTitle("Mail Risk Analyzer")
        .setSubtitle("Email maliciousness analyzer")
    )
    .addSection(section)
    .build();
}

function analyzeCurrentEmail(e) {
  try {
    GmailApp.setCurrentMessageAccessToken(e.gmail.accessToken);

    const messageId = e.gmail.messageId;
    const message = GmailApp.getMessageById(messageId);

    const subject = message.getSubject();
    const sender = message.getFrom();
    const body = message.getPlainBody();

    const analysisResult = callBackend(subject, sender, body);

    return buildResultCard(analysisResult);

  } catch (error) {
    return buildErrorCard(error);
  }
}

function callBackend(subject, sender, body) {
  const url = BACKEND_BASE_URL + "/analyze-email";

  const payload = {
    subject: subject || "",
    sender: sender || "",
    body: body || ""
  };

  const response = UrlFetchApp.fetch(url, {
    method: "post",
    contentType: "application/json",
    payload: JSON.stringify(payload),
    muteHttpExceptions: true
  });

  const statusCode = response.getResponseCode();
  const responseText = response.getContentText();

  if (statusCode < 200 || statusCode >= 300) {
    throw new Error("Backend request failed. Status: " + statusCode + ". Response: " + responseText);
  }

  return JSON.parse(responseText);
}

function buildResultCard(result) {
  const section = CardService.newCardSection()
    .addWidget(
      CardService.newKeyValue()
        .setTopLabel("Verdict")
        .setContent(result.verdict || "Unknown")
    )
    .addWidget(
      CardService.newKeyValue()
        .setTopLabel("Score")
        .setContent((result.score || 0) + "/100")
    )
    .addWidget(
      CardService.newTextParagraph()
        .setText("<b>Reasoning</b>")
    );

  const reasons = result.reasons || [];

  if (reasons.length === 0) {
    section.addWidget(
      CardService.newTextParagraph()
        .setText("No reasoning was returned by the backend.")
    );
  } else {
    reasons.forEach(function(reason, index) {
      section.addWidget(
        CardService.newTextParagraph()
          .setText((index + 1) + ". " + reason)
      );
    });
  }

  return CardService.newCardBuilder()
    .setHeader(
      CardService.newCardHeader()
        .setTitle("Mail Risk Analyzer")
        .setSubtitle("Backend analysis result")
    )
    .addSection(section)
    .build();
}

function buildErrorCard(error) {
  const section = CardService.newCardSection()
    .addWidget(
      CardService.newTextParagraph()
        .setText("An error occurred while analyzing the email:<br><br>" + error.message)
    );

  return CardService.newCardBuilder()
    .setHeader(
      CardService.newCardHeader()
        .setTitle("Mail Risk Analyzer")
        .setSubtitle("Error")
    )
    .addSection(section)
    .build();
}