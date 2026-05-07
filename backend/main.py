from fastapi import FastAPI
from pydantic import BaseModel
from typing import List


app = FastAPI(title="Mail Risk Analyzer Backend")


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
    """Analyze an email and return a demo risk result."""

    return EmailAnalysisResponse(
        score=50,
        verdict="Suspicious",
        reasons=[
            "Demo analysis result",
            "The backend successfully received the email data"
        ]
    )