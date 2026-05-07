from fastapi import FastAPI

app = FastAPI(title="Mail Risk Analyzer Backend")


@app.get("/health")
def health_check():
    """Return a simple health check response."""
    return {"status": "ok"}