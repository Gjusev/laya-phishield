"""Behavior tests for the HTTP API (agent injected, no checkpoint)."""

import pytest
from fastapi.testclient import TestClient

from laya_phishield.serve import create_app
from smoke_emails import CREDENTIAL_PHISH_EXEMPLAR, LEGIT_EMAILS


class FakeAgent:
    def system_one(self, state, questions):
        text = (state.get("subject", "") + " " + state.get("body_excerpt", "")).lower()
        phishy = "password" in text or "account has been" in text
        return {"answers": {qid: {"type": "noul", "noul": 0.85 if phishy else 0.08}
                            for qid in questions}}


@pytest.fixture()
def client():
    return TestClient(create_app(agent=FakeAgent()))


def test_scan_endpoint_returns_the_verdict(client):
    response = client.post("/scan", json={"raw": CREDENTIAL_PHISH_EXEMPLAR})
    assert response.status_code == 200
    body = response.json()
    assert body["label"] == "phishing"
    assert body["score"] > 0.9
    assert body["reasons"]
    assert "display_name_brand_mismatch" in body["flags"]


def test_scan_endpoint_flags_legit_mail_low(client):
    response = client.post("/scan", json={"raw": LEGIT_EMAILS[0]})
    assert response.status_code == 200
    body = response.json()
    assert body["label"] == "legitimate"
    assert body["score"] < 0.1


def test_scan_endpoint_rejects_missing_body(client):
    response = client.post("/scan", json={})
    assert response.status_code == 422


def test_health_endpoint_reports_model_loaded(client):
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}
