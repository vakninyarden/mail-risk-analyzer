
  function buildHomePage(e) {
  const section = CardService.newCardSection()
    .addWidget(
      CardService.newTextParagraph()
        .setText("Open an email in Gmail to analyze it.")
    );

  return CardService.newCardBuilder()
    .setHeader(
      CardService.newCardHeader()
        .setTitle("Scam Detect")
        .setSubtitle("Email maliciousness analyzer")
    )
    .addSection(section)
    .build();
}


function analyzeCurrentEmail(e) {
  const section = CardService.newCardSection()
    .addWidget(
      CardService.newTextParagraph()
        .setText("Email analysis will appear here.")
    );

  return CardService.newCardBuilder()
    .setHeader(
      CardService.newCardHeader()
        .setTitle("Scam Detect")
        .setSubtitle("Analysis result")
    )
    .addSection(section)
    .build();
}

