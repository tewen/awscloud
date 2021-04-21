import json
import pytest
import requests
import requests_mock
from free_look_email import app


@pytest.fixture()
def spam_failure_ses_event():
    with open("./events/ses-spam-failure.json") as f:
        data = json.load(f)
    return data


def test_spam_failure(spam_failure_ses_event):
    response = app.handler(spam_failure_ses_event, "")
    data = json.loads(response["body"])

    assert response["statusCode"] == 424
    assert "spam_verdict" in data
    assert data["spam_verdict"]["status"] == "FAILED"


@pytest.fixture()
def virus_failure_ses_event():
    with open("./events/ses-virus-failure.json") as f:
        data = json.load(f)
    return data


def test_virus_failure(virus_failure_ses_event):
    response = app.handler(virus_failure_ses_event, "")
    data = json.loads(response["body"])

    assert response["statusCode"] == 424
    assert "virus_verdict" in data
    assert data["virus_verdict"]["status"] == "FAILED"


@pytest.fixture()
def spf_failure_ses_event():
    with open("./events/ses-spf-failure.json") as f:
        data = json.load(f)
    return data


def test_spf_failure(spf_failure_ses_event):
    response = app.handler(spf_failure_ses_event, "")
    data = json.loads(response["body"])

    assert response["statusCode"] == 424
    assert "spf_verdict" in data
    assert data["spf_verdict"]["status"] == "FAILED"


@pytest.fixture()
def dkim_failure_ses_event():
    with open("./events/ses-dkim-failure.json") as f:
        data = json.load(f)
    return data


def test_dkim_failure(dkim_failure_ses_event):
    response = app.handler(dkim_failure_ses_event, "")
    data = json.loads(response["body"])

    assert response["statusCode"] == 424
    assert "dkim_verdict" in data
    assert data["dkim_verdict"]["status"] == "FAILED"


@pytest.fixture()
def dmarc_failure_ses_event():
    with open("./events/ses-dmarc-failure.json") as f:
        data = json.load(f)
    return data


def test_dmarc_failure(dmarc_failure_ses_event):
    response = app.handler(dmarc_failure_ses_event, "")
    data = json.loads(response["body"])

    assert response["statusCode"] == 424
    assert "dmarc_verdict" in data
    assert data["dmarc_verdict"]["status"] == "FAILED"


@pytest.fixture()
def ses_event():
    with open("./events/ses.json") as f:
        data = json.load(f)
    return data


def test_success(ses_event, requests_mock):
    requests_mock.post(
        "http://host.docker.internal:8000/api/rest/v3/free-look-email/",
        json=json.dumps({"mail": {}, "receipt": {}}),
    )

    response = app.handler(ses_event, "")
    data = json.loads(response["body"])

    assert response["statusCode"] == 200
    assert "mail" in data
    assert "receipt" in data
