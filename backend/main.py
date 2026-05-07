from fastapi import FastAPI
from pydantic import BaseModel
from typing import List

from analysis.engine import RiskEngine


app = FastAPI(title="Mail Risk Analyzer Backend")
risk_engine = RiskEngine()


class EmailAnalysisRequest(BaseModel):
    """Represents the email data received from the Gmail add-on."""
    subject: str
    sender: str
    body: str


class EmailAnalysisResponse(BaseModel):
    """Represents the analysis result returned to the Gmail add-on."""
    score: int
    verdict: str
    reasons: List[str]


@app.get("/health")
def health_check():
    """Return a simple health check response."""
    return {"status": "ok"}


@app.post("/analyze-email", response_model=EmailAnalysisResponse)
def analyze_email(request: EmailAnalysisRequest):
    """Analyze an email and return a risk result."""

    result = risk_engine.analyze(
        subject=request.subject,
        sender=request.sender,
        body=request.body,
    )

    return EmailAnalysisResponse(**result)