import json
import requests
from requests.exceptions import ConnectionError, HTTPError, Timeout
from humps import decamelize
import time
from functools import wraps

# TODO - It would be preferable to have this in a separate decorators package nearby. This currently has problems with the tests. Will research.
def retry(
    ExceptionToCheck,
    tries=4,
    delay=3,
    backoff=2,
):
    """Retry calling the decorated function using an exponential backoff.
    http://www.saltycrane.com/blog/2009/11/trying-out-retry-decorator-python/
    original from: http://wiki.python.org/moin/PythonDecoratorLibrary#Retry
    :param ExceptionToCheck: the exception to check. may be a tuple of
    exceptions to check
    :type ExceptionToCheck: Exception or tuple
    :param tries: number of times to try (not retry) before giving up
    :type tries: int
    :param delay: initial delay between retries in seconds
    :type delay: int
    :param backoff: backoff multiplier e.g. value of 2 will double the delay
    each retry
    :type backoff: int
    """

    def deco_retry(f):
        @wraps(f)
        def f_retry(*args, **kwargs):
            mtries, mdelay = tries, delay
            while mtries > 1:
                try:
                    return f(*args, **kwargs)
                except ExceptionToCheck as e:
                    msg = "%s, Retrying in %d seconds..." % (str(e), mdelay)
                    print(msg)
                    time.sleep(mdelay)
                    mtries -= 1
                    mdelay *= backoff
            return f(*args, **kwargs)

        return f_retry  # true decorator

    return deco_retry


def get_email_record_from_event(event):
    return decamelize(event["Records"][0]["ses"]["mail"])


def get_email_receipt_from_event(event):
    return decamelize(event["Records"][0]["ses"]["receipt"])


def get_spam_verdict(receipt):
    return receipt["spam_verdict"]["status"]


def get_virus_verdict(receipt):
    return receipt["virus_verdict"]["status"]


def get_spf_verdict(receipt):
    return receipt["spf_verdict"]["status"]


def get_dkim_verdict(receipt):
    return receipt["dkim_verdict"]["status"]


def get_dmarc_verdict(receipt):
    return receipt["dmarc_verdict"]["status"]


def get_combined_log_message(email):
    subject = None
    for header in email["headers"]:
        if header["name"] == "Subject":
            subject = header["value"]

    return "Email with {subject}, from {source} to {destination}".format(
        subject=subject,
        source=email["source"],
        destination=email["destination"],
    )


def validation_failure(email, receipt, verdict):
    print(
        "{combined} failed with spam verdict {verdict}".format(
            combined=get_combined_log_message(email), verdict=verdict
        )
    )
    return {
        "statusCode": 424,
        "body": json.dumps(receipt),
    }


@retry(
    (
        ConnectionError,
        HTTPError,
        Timeout,
    ),
    tries=10,
    delay=5,
    backoff=3,
)
def send_to_court_listener(email, receipt):
    # TODO - Docker internal host here should be an environment variable.
    print(
        "{combined} sending to Court Listener API.".format(
            combined=get_combined_log_message(email)
        )
    )
    court_listener_response = requests.post(
        "http://host.docker.internal:8000/api/rest/v3/free-look-email/",
        json.dumps({"mail": email, "receipt": receipt}),
        headers={"Content-Type": "application/json"},
    )

    return {
        "statusCode": 200,
        "body": court_listener_response.json(),
    }


def handler(event, context):
    ses_email = get_email_record_from_event(event)
    ses_receipt = get_email_receipt_from_event(event)

    # NOTE - Not sure if we'll want every single check, we'll have to see what the standard PACER email comes in as.
    tests = (
        get_spam_verdict,
        get_virus_verdict,
        get_spf_verdict,
        get_dkim_verdict,
        get_dmarc_verdict,
    )
    for test in tests:
        verdict = test(ses_receipt)
        if verdict != "PASS":
            return validation_failure(ses_email, ses_receipt, verdict)

    return send_to_court_listener(ses_email, ses_receipt)
