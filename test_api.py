from fastapi.testclient import TestClient
from app.main import app
client=TestClient(app)
def test_health():
    response=client.get("/health")
    assert response.status_code==200 and response.json()["status"]=="ok"
def test_protected_endpoint_requires_token():
    response=client.get("/api/projects")
    assert response.status_code==401
