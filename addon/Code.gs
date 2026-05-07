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

    const section = CardService.newCardSection()
      .addWidget(
        CardService.newKeyValue()
          .setTopLabel("Subject")
          .setContent(subject || "No subject")
      )
      .addWidget(
        CardService.newKeyValue()
          .setTopLabel("Sender")
          .setContent(sender || "Unknown sender")
      )
      .addWidget(
        CardService.newTextParagraph()
          .setText("This confirms the add-on can read the currently opened email.")
      );

    return CardService.newCardBuilder()
      .setHeader(
        CardService.newCardHeader()
          .setTitle("Mail Risk Analyzer")
          .setSubtitle("Current email details")
      )
      .addSection(section)
      .build();

  } catch (error) {
    return buildErrorCard(error);
  }
}


function buildErrorCard(error) {
  const section = CardService.newCardSection()
    .addWidget(
      CardService.newTextParagraph()
        .setText("An error occurred while reading the email:<br><br>" + error.message)
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