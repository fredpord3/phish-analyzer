"""Test suite for lambda_handler. Mocks all external boundaries
(S3, SES, DynamoDB, Anthropic API, reputation HTTP calls).

Run with pytest (NOT `python test_lambda_handler.py` - the hardening tests at
the bottom are pytest functions that unittest.main() would silently skip):

    python -m pytest test_lambda_handler.py -v

Expected: 113 passed (106 unittest-style + 7 pytest-style hardening regressions).
Covers: parsing, enrichment, URL + attachment reputation, escalation, both
entry paths, Turnstile CAPTCHA gating, leet + Unicode homoglyph lookalikes
(including punycode senders), submitter history, the 2026-07-07 review
regressions (duplicate auth headers, URL punctuation strip, reputation
short-circuit, frozenset brand list, HTML body fallback, received chain in
prompt, system prompt injection hardening), and the hardening regressions
at the bottom.
"""

import os
import json
import base64
import unittest
from unittest import mock

os.environ.setdefault("ANTHROPIC_API_KEY", "test-key")
os.environ.setdefault("BUCKET_NAME", "test-bucket")
os.environ.setdefault("FROM_ADDRESS", "check@fredsprivacy.com")
os.environ.setdefault("REGION", "us-east-1")

import lambda_handler as lh


PLAIN_EML = b"""From: Alice Example <alice@example.com>
To: check@fredsprivacy.com
Subject: Is this phishing?
Return-Path: <bounce.alice@mailer.example.net>
Reply-To: support@other.example.org
Authentication-Results: mx.test; spf=pass smtp.mailfrom=example.com; dkim=fail; dmarc=pass (p=REJECT) header.from=example.com

Hello, please verify your account at https://bit.ly/abc123 today.
Also see https://93.184.216.34/login for details.
"""

HTML_EML = b"""From: PayPal Security <security@paypal-alerts.example>
To: victim@example.com
Subject: Urgent account verification
Authentication-Results: mx.test; spf=fail; dkim=fail; dmarc=fail header.from=paypal-alerts.example
MIME-Version: 1.0
Content-Type: text/html; charset="utf-8"

<html><body>
<p>Your account is locked. <a href="http://evil.example/login">paypal.com</a></p>
<p><a href="https://tracker.evil.example/click?u=1">Click here</a></p>
</body></html>
"""

FORWARD_EML = (
    b"From: Test User <testuser@example.com>\r\n"
    b"To: check@fredsprivacy.com\r\n"
    b"Subject: Fwd: check this\r\n"
    b"MIME-Version: 1.0\r\n"
    b"Content-Type: multipart/mixed; boundary=\"BOUND\"\r\n"
    b"\r\n"
    b"--BOUND\r\n"
    b"Content-Type: text/plain\r\n"
    b"\r\n"
    b"See attached.\r\n"
    b"--BOUND\r\n"
    b"Content-Type: message/rfc822\r\n"
    b"\r\n"
    b"From: scammer <win@lottery.example>\r\n"
    b"Subject: You won!\r\n"
    b"Content-Type: text/plain\r\n"
    b"\r\n"
    b"Claim your prize at https://lottery.example/claim\r\n"
    b"--BOUND--\r\n"
)


def make_verdict(verdict="likely_legitimate", confidence=90):
    return {
        "verdict": verdict,
        "confidence": confidence,
        "summary": "test summary",
        "indicators": [{"signal": "s", "detail": "d", "severity": "low"}],
        "recommendation": "do the thing",
    }


class FakeAnthropicResponse:
    def __init__(self, payload):
        block = mock.Mock()
        block.text = payload if isinstance(payload, str) else json.dumps(payload)
        self.content = [block]


class FakeTable:
    """In-memory stand-in for the DynamoDB rate-limit table."""
    def __init__(self):
        self.items = {}
        self.fail = False

    def update_item(self, Key, UpdateExpression, ExpressionAttributeValues, ReturnValues):
        if self.fail:
            raise RuntimeError("dynamo down")
        pk = Key["pk"]
        item = self.items.setdefault(pk, {"pk": pk, "request_count": 0})
        item["request_count"] += ExpressionAttributeValues[":incr"]
        item.setdefault("expires_at", ExpressionAttributeValues[":ttl"])
        return {"Attributes": dict(item)}

    def get_item(self, Key):
        if self.fail:
            raise RuntimeError("dynamo down")
        item = self.items.get(Key["pk"])
        return {"Item": item} if item else {}

    def put_item(self, Item):
        if self.fail:
            raise RuntimeError("dynamo down")
        self.items[Item["pk"]] = Item
        return {}


class FakeHttpResponse:
    def __init__(self, status, payload):
        self.status = status
        self.data = json.dumps(payload).encode()


class BaseTest(unittest.TestCase):
    def setUp(self):
        self.table = FakeTable()
        self.patches = [
            mock.patch.object(lh, "rate_limit_table", self.table),
            mock.patch.object(lh, "s3"),
            mock.patch.object(lh, "ses"),
            mock.patch.object(lh, "claude"),
            mock.patch.object(lh, "http"),
        ]
        self.mocks = {}
        for p in self.patches:
            m = p.start()
            self.addCleanup(p.stop)
            if hasattr(p, "attribute"):
                self.mocks[p.attribute] = m
        # default: model returns a legitimate verdict
        self.mocks["claude"].messages.create.return_value = FakeAnthropicResponse(make_verdict())
        # default: no reputation services configured
        for var in ("VIRUSTOTAL_API_KEY", "URLSCAN_API_KEY", "PHISHTANK_ENABLED",
                    "PHISHTANK_APP_KEY", "ENABLE_MODEL_ESCALATION", "ESCALATION_CONFIDENCE",
                    "ALLOWED_ORIGIN", "TURNSTILE_SECRET_KEY", "ENABLE_SUBMITTER_HISTORY"):
            os.environ.pop(var, None)


class TestParsing(BaseTest):
    def test_plain_email(self):
        import email
        from email import policy
        msg = email.message_from_bytes(PLAIN_EML, policy=policy.default)
        parsed = lh.parse_email(msg)
        self.assertEqual(parsed["from_addr"], "alice@example.com")
        self.assertEqual(parsed["from_domain"], "example.com")
        self.assertEqual(parsed["reply_to"], "support@other.example.org")
        self.assertIn("https://bit.ly/abc123", parsed["urls"])
        self.assertTrue(any(u.startswith("https://93.184.216.34") for u in parsed["urls"]))

    def test_html_email_extracts_hrefs(self):
        import email
        from email import policy
        msg = email.message_from_bytes(HTML_EML, policy=policy.default)
        parsed = lh.parse_email(msg)
        self.assertIn("http://evil.example/login", parsed["urls"])
        self.assertTrue(parsed["body"])  # derived from HTML

    def test_forwarded_rfc822_extraction(self):
        import email
        from email import policy
        msg = email.message_from_bytes(FORWARD_EML, policy=policy.default)
        target = lh.extract_target_email(msg)
        self.assertIsNotNone(target)
        parsed = lh.parse_email(target)
        self.assertEqual(parsed["from_addr"], "win@lottery.example")
        self.assertIn("https://lottery.example/claim", parsed["urls"])


class TestEnrichment(BaseTest):
    def _enrich(self, eml):
        import email
        from email import policy
        return lh.enrich(lh.parse_email(email.message_from_bytes(eml, policy=policy.default)))

    def test_dmarc_senior_signal(self):
        e = self._enrich(PLAIN_EML)
        self.assertEqual(e["dmarc"], "pass")
        self.assertEqual(e["dmarc_policy"], "reject")
        self.assertEqual(e["dkim"], "fail")
        kinds = [k for k, _ in e["signals"]]
        # dkim-fail-with-dmarc-pass must be an info note, not an auth alarm
        self.assertIn("info", kinds)
        notes = " ".join(n for _, n in e["signals"])
        self.assertIn("REJECT policy", notes)
        self.assertIn("shortener", notes)
        self.assertIn("IP literal", notes)

    def test_dmarc_fail_flags(self):
        e = self._enrich(HTML_EML)
        self.assertEqual(e["dmarc"], "fail")
        notes = " ".join(n for _, n in e["signals"])
        self.assertIn("DMARC FAILED", notes)
        self.assertEqual(len(e["link_mismatches"]), 1)
        self.assertEqual(e["link_mismatches"][0]["actual_host"], "evil.example")

    def test_link_mismatch_ignores_plain_anchors(self):
        mismatches = lh.extract_link_mismatches(
            '<a href="http://x.example/a">Click here</a>'
            '<a href="http://x.example/a">x.example</a>')
        self.assertEqual(len(mismatches), 0)  # matching host and plain text both skipped

    def test_lookalike_exact_brand_is_none(self):
        self.assertIsNone(lh.detect_lookalike_domain("paypal.com"))
        self.assertIsNone(lh.detect_lookalike_domain(""))


class TestReputation(BaseTest):
    def test_no_services_configured_returns_empty(self):
        self.assertEqual(lh.check_url_reputation(["https://a.example/x"]), [])
        lh.http.request.assert_not_called()

    def test_virustotal_malicious_flags(self):
        os.environ["VIRUSTOTAL_API_KEY"] = "vt-key"
        lh.http.request.return_value = FakeHttpResponse(200, {
            "data": {"attributes": {"last_analysis_stats": {"malicious": 5, "suspicious": 2}}}
        })
        results = lh.check_url_reputation(["https://bad.example/x"])
        self.assertEqual(len(results), 1)
        self.assertTrue(results[0]["flagged"])
        vt = [c for c in results[0]["checks"] if c["service"] == "virustotal"][0]
        self.assertEqual(vt["malicious_votes"], 5)

    def test_virustotal_404_means_unknown_not_flagged(self):
        os.environ["VIRUSTOTAL_API_KEY"] = "vt-key"
        lh.http.request.return_value = FakeHttpResponse(404, {})
        results = lh.check_url_reputation(["https://new.example/x"])
        self.assertFalse(results[0]["flagged"])

    def test_reputation_cache_hit_skips_lookup(self):
        os.environ["VIRUSTOTAL_API_KEY"] = "vt-key"
        url = "https://cached.example/x"
        cached = {"url": url, "checks": [], "flagged": True}
        lh._reputation_cache_put(url, cached)
        results = lh.check_url_reputation([url])
        self.assertEqual(results[0], cached)
        lh.http.request.assert_not_called()

    def test_urlscan_flags_on_prior_malicious_scans(self):
        os.environ["URLSCAN_API_KEY"] = "us-key"
        lh.http.request.return_value = FakeHttpResponse(200, {
            "results": [
                {"task": {"tags": ["phishing"]}},
                {"task": {"tags": ["possiblethreat"]}},
                {"task": {"tags": []}},
            ]
        })
        results = lh.check_url_reputation(["https://bad.example/x"])
        self.assertTrue(results[0]["flagged"])

    def test_urlscan_does_not_flag_on_weak_tags_only(self):
        os.environ["URLSCAN_API_KEY"] = "us-key"
        lh.http.request.return_value = FakeHttpResponse(200, {
            "results": [{"task": {"tags": ["possiblethreat"]}}]
        })
        results = lh.check_url_reputation(["https://maybe.example/x"])
        self.assertFalse(results[0]["flagged"])

    def test_phishtank_verified(self):
        os.environ["PHISHTANK_ENABLED"] = "true"
        lh.http.request.return_value = FakeHttpResponse(200, {
            "results": {"in_database": True, "valid": True, "verified": True}
        })
        results = lh.check_url_reputation(["https://phish.example/x"])
        self.assertTrue(results[0]["flagged"])

    def test_reputation_fails_open_on_network_error(self):
        os.environ["VIRUSTOTAL_API_KEY"] = "vt-key"
        lh.http.request.side_effect = RuntimeError("timeout")
        results = lh.check_url_reputation(["https://a.example/x"])
        self.assertEqual(len(results), 1)
        self.assertFalse(results[0]["flagged"])
        self.assertEqual(results[0]["checks"], [])

    def test_lookup_cap(self):
        os.environ["VIRUSTOTAL_API_KEY"] = "vt-key"
        lh.http.request.return_value = FakeHttpResponse(404, {})
        urls = [f"https://u{i}.example/" for i in range(10)]
        results = lh.check_url_reputation(urls)
        self.assertEqual(len(results), lh.REPUTATION_MAX_URLS)

    def test_reputation_signal_lands_in_enrichment(self):
        os.environ["VIRUSTOTAL_API_KEY"] = "vt-key"
        lh.http.request.return_value = FakeHttpResponse(200, {
            "data": {"attributes": {"last_analysis_stats": {"malicious": 9}}}
        })
        import email
        from email import policy
        parsed = lh.parse_email(email.message_from_bytes(PLAIN_EML, policy=policy.default))
        e = lh.enrich(parsed)
        self.assertGreater(e["url_rep_flagged_count"], 0)
        self.assertTrue(any(k == "reputation" for k, _ in e["signals"]))


class TestEscalation(BaseTest):
    def test_disabled_by_default(self):
        self.assertFalse(lh._should_escalate(make_verdict("suspicious", 60)))

    def test_suspicious_escalates(self):
        os.environ["ENABLE_MODEL_ESCALATION"] = "true"
        self.assertTrue(lh._should_escalate(make_verdict("suspicious", 60)))

    def test_low_confidence_definite_escalates(self):
        os.environ["ENABLE_MODEL_ESCALATION"] = "true"
        self.assertTrue(lh._should_escalate(make_verdict("likely_phishing", 55)))
        self.assertFalse(lh._should_escalate(make_verdict("likely_phishing", 85)))

    def test_unknown_never_escalates(self):
        os.environ["ENABLE_MODEL_ESCALATION"] = "true"
        self.assertFalse(lh._should_escalate(make_verdict("unknown", 0)))

    def test_full_escalation_path(self):
        os.environ["ENABLE_MODEL_ESCALATION"] = "true"
        haiku = FakeAnthropicResponse(make_verdict("suspicious", 55))
        sonnet = FakeAnthropicResponse(make_verdict("likely_phishing", 92))
        lh.claude.messages.create.side_effect = [haiku, sonnet]
        import email
        from email import policy
        parsed = lh.parse_email(email.message_from_bytes(HTML_EML, policy=policy.default))
        verdict = lh.analyze_with_claude(parsed, lh.enrich(parsed))
        self.assertEqual(verdict["verdict"], "likely_phishing")
        self.assertTrue(verdict["escalated"])
        self.assertEqual(verdict["model"], lh.ESCALATION_MODEL)
        self.assertEqual(lh.claude.messages.create.call_count, 2)
        models = [c.kwargs["model"] for c in lh.claude.messages.create.call_args_list]
        self.assertEqual(models, [lh.PRIMARY_MODEL, lh.ESCALATION_MODEL])

    def test_escalation_failure_keeps_haiku_verdict(self):
        os.environ["ENABLE_MODEL_ESCALATION"] = "true"
        haiku = FakeAnthropicResponse(make_verdict("suspicious", 55))
        lh.claude.messages.create.side_effect = [haiku, RuntimeError("sonnet down")]
        import email
        from email import policy
        parsed = lh.parse_email(email.message_from_bytes(PLAIN_EML, policy=policy.default))
        verdict = lh.analyze_with_claude(parsed, lh.enrich(parsed))
        self.assertEqual(verdict["verdict"], "suspicious")
        self.assertFalse(verdict["escalated"])
        self.assertEqual(verdict["model"], lh.PRIMARY_MODEL)

    def test_unparseable_model_output(self):
        lh.claude.messages.create.return_value = FakeAnthropicResponse("not json at all")
        import email
        from email import policy
        parsed = lh.parse_email(email.message_from_bytes(PLAIN_EML, policy=policy.default))
        verdict = lh.analyze_with_claude(parsed, lh.enrich(parsed))
        self.assertEqual(verdict["verdict"], "unknown")

    def test_code_fenced_output_still_parses(self):
        lh.claude.messages.create.return_value = FakeAnthropicResponse(
            "```json\n" + json.dumps(make_verdict()) + "\n```")
        import email
        from email import policy
        parsed = lh.parse_email(email.message_from_bytes(PLAIN_EML, policy=policy.default))
        verdict = lh.analyze_with_claude(parsed, lh.enrich(parsed))
        self.assertEqual(verdict["verdict"], "likely_legitimate")


class TestSesPath(BaseTest):
    def _event(self, sender="alice@example.com"):
        return {"Records": [{"ses": {"mail": {"messageId": "msg-1", "source": sender}}}]}

    def _stub_s3(self, raw):
        body = mock.Mock()
        body.read.return_value = raw
        lh.s3.get_object.return_value = {"Body": body}

    def test_happy_path_sends_reply(self):
        self._stub_s3(PLAIN_EML)
        result = lh.lambda_handler(self._event(), None)
        self.assertEqual(result["statusCode"], 200)
        self.assertEqual(result["messageId"], "msg-1")
        lh.ses.send_email.assert_called_once()
        kwargs = lh.ses.send_email.call_args.kwargs
        self.assertEqual(kwargs["Destination"]["ToAddresses"], ["alice@example.com"])
        self.assertIn("LIKELY LEGITIMATE", kwargs["Message"]["Body"]["Text"]["Data"])

    def test_own_domain_skipped(self):
        self._stub_s3(PLAIN_EML)
        result = lh.lambda_handler(self._event("anything@fredsprivacy.com"), None)
        self.assertEqual(result["reason"], "loop_or_bounce")
        lh.ses.send_email.assert_not_called()

    def test_bounce_sender_skipped(self):
        self._stub_s3(PLAIN_EML)
        result = lh.lambda_handler(self._event("mailer-daemon@gmail.com"), None)
        self.assertEqual(result["reason"], "loop_or_bounce")

    def test_noreply_is_analyzed(self):
        self._stub_s3(PLAIN_EML)
        result = lh.lambda_handler(self._event("noreply@bank.example"), None)
        self.assertNotIn("skipped", result)
        lh.ses.send_email.assert_called_once()

    def test_rate_limit_drops_silently(self):
        self._stub_s3(PLAIN_EML)
        for _ in range(lh.RATE_LIMIT_PER_HOUR):
            lh.lambda_handler(self._event(), None)
        lh.ses.send_email.reset_mock()
        result = lh.lambda_handler(self._event(), None)
        self.assertEqual(result["reason"], "rate_limited")
        lh.ses.send_email.assert_not_called()

    def test_rate_limit_fails_open(self):
        self._stub_s3(PLAIN_EML)
        self.table.fail = True
        result = lh.lambda_handler(self._event(), None)
        self.assertEqual(result["statusCode"], 200)
        lh.ses.send_email.assert_called_once()

    def test_forwarded_eml_analyzes_inner_message(self):
        self._stub_s3(FORWARD_EML)
        lh.lambda_handler(self._event("testuser@example.com"), None)
        body = lh.ses.send_email.call_args.kwargs["Message"]["Body"]["Text"]["Data"]
        self.assertIn("win@lottery.example", body)


class TestHttpPath(BaseTest):
    def _event(self, method="POST", body=None, b64=False, ip="203.0.113.9"):
        return {
            "requestContext": {"http": {"method": method, "sourceIp": ip}},
            "body": body,
            "isBase64Encoded": b64,
        }

    def test_options_cors(self):
        resp = lh.lambda_handler(self._event("OPTIONS"), None)
        self.assertEqual(resp["statusCode"], 204)
        self.assertIn("Access-Control-Allow-Origin", resp["headers"])

    def test_get_rejected(self):
        resp = lh.lambda_handler(self._event("GET"), None)
        self.assertEqual(resp["statusCode"], 405)

    def test_post_raw_eml(self):
        resp = lh.lambda_handler(self._event(body=PLAIN_EML.decode()), None)
        self.assertEqual(resp["statusCode"], 200)
        payload = json.loads(resp["body"])
        self.assertEqual(payload["verdict"], "likely_legitimate")
        self.assertEqual(payload["analyzed"]["from"], "alice@example.com")
        self.assertEqual(payload["analyzed"]["dmarc"], "pass")
        lh.ses.send_email.assert_not_called()  # HTTP path never emails

    def test_post_base64_eml(self):
        resp = lh.lambda_handler(
            self._event(body=base64.b64encode(HTML_EML).decode(), b64=True), None)
        self.assertEqual(resp["statusCode"], 200)
        payload = json.loads(resp["body"])
        self.assertEqual(payload["analyzed"]["dmarc"], "fail")

    def test_empty_body_400(self):
        resp = lh.lambda_handler(self._event(body="   "), None)
        self.assertEqual(resp["statusCode"], 400)

    def test_garbage_body_400(self):
        resp = lh.lambda_handler(self._event(body="just some random text with no headers"), None)
        self.assertEqual(resp["statusCode"], 400)

    def test_oversize_413(self):
        resp = lh.lambda_handler(self._event(body="From: a@b.c\n\n" + "x" * 600_000), None)
        self.assertEqual(resp["statusCode"], 413)

    def test_ip_rate_limit_429(self):
        for _ in range(lh.RATE_LIMIT_PER_HOUR):
            lh.lambda_handler(self._event(body=PLAIN_EML.decode()), None)
        resp = lh.lambda_handler(self._event(body=PLAIN_EML.decode()), None)
        self.assertEqual(resp["statusCode"], 429)

    def test_ip_and_sender_buckets_do_not_collide(self):
        # Same string as sender-email and as IP must count separately
        lh.check_rate_limit("sender#test@x.example")
        lh.check_rate_limit("ip#test@x.example")
        self.assertEqual(len(self.table.items), 2)

    def test_allowed_origin_env(self):
        os.environ["ALLOWED_ORIGIN"] = "https://fredsprivacy.com"
        resp = lh.lambda_handler(self._event("OPTIONS"), None)
        self.assertEqual(resp["headers"]["Access-Control-Allow-Origin"], "https://fredsprivacy.com")


class TestTurnstile(BaseTest):
    """Cloudflare Turnstile CAPTCHA gating on the web path only."""

    def _event(self, token=None, ip="203.0.113.9"):
        headers = {}
        if token is not None:
            headers["x-turnstile-token"] = token
        return {
            "requestContext": {"http": {"method": "POST", "sourceIp": ip}},
            "headers": headers,
            "body": PLAIN_EML.decode(),
            "isBase64Encoded": False,
        }

    def test_disabled_by_default_no_token_needed(self):
        resp = lh.lambda_handler(self._event(), None)
        self.assertEqual(resp["statusCode"], 200)
        lh.http.request.assert_not_called()  # no siteverify call when disabled

    def test_enabled_missing_token_403(self):
        os.environ["TURNSTILE_SECRET_KEY"] = "ts-secret"
        resp = lh.lambda_handler(self._event(), None)
        self.assertEqual(resp["statusCode"], 403)
        lh.http.request.assert_not_called()  # rejected before any network call
        lh.claude.messages.create.assert_not_called()  # and before any model cost

    def test_enabled_valid_token_passes(self):
        os.environ["TURNSTILE_SECRET_KEY"] = "ts-secret"
        lh.http.request.return_value = FakeHttpResponse(200, {"success": True})
        resp = lh.lambda_handler(self._event(token="tok-abc"), None)
        self.assertEqual(resp["statusCode"], 200)
        call = lh.http.request.call_args
        self.assertIn("challenges.cloudflare.com", call.args[1])
        self.assertEqual(call.kwargs["fields"]["response"], "tok-abc")
        self.assertEqual(call.kwargs["fields"]["secret"], "ts-secret")

    def test_enabled_invalid_token_403(self):
        os.environ["TURNSTILE_SECRET_KEY"] = "ts-secret"
        lh.http.request.return_value = FakeHttpResponse(
            200, {"success": False, "error-codes": ["invalid-input-response"]})
        resp = lh.lambda_handler(self._event(token="bad-tok"), None)
        self.assertEqual(resp["statusCode"], 403)
        lh.claude.messages.create.assert_not_called()

    def test_siteverify_outage_fails_open(self):
        os.environ["TURNSTILE_SECRET_KEY"] = "ts-secret"
        lh.http.request.side_effect = RuntimeError("cloudflare down")
        resp = lh.lambda_handler(self._event(token="tok-abc"), None)
        self.assertEqual(resp["statusCode"], 200)

    def test_oversized_token_403(self):
        os.environ["TURNSTILE_SECRET_KEY"] = "ts-secret"
        resp = lh.lambda_handler(self._event(token="x" * 3000), None)
        self.assertEqual(resp["statusCode"], 403)
        lh.http.request.assert_not_called()

    def test_failed_captcha_does_not_consume_rate_budget(self):
        os.environ["TURNSTILE_SECRET_KEY"] = "ts-secret"
        for _ in range(lh.RATE_LIMIT_PER_HOUR * 2):
            lh.lambda_handler(self._event(), None)  # all 403, no token
        self.assertEqual(len(self.table.items), 0)  # rate counter never touched

    def test_cors_allows_token_header(self):
        resp = lh.lambda_handler(
            {"requestContext": {"http": {"method": "OPTIONS", "sourceIp": "1.2.3.4"}}}, None)
        self.assertIn("X-Turnstile-Token", resp["headers"]["Access-Control-Allow-Headers"])

    def test_ses_path_never_gated_by_turnstile(self):
        os.environ["TURNSTILE_SECRET_KEY"] = "ts-secret"
        body = mock.Mock()
        body.read.return_value = PLAIN_EML
        lh.s3.get_object.return_value = {"Body": body}
        event = {"Records": [{"ses": {"mail": {"messageId": "m", "source": "alice@example.com"}}}]}
        result = lh.lambda_handler(event, None)
        self.assertEqual(result["statusCode"], 200)
        lh.ses.send_email.assert_called_once()


class TestLeetLookalike(BaseTest):
    """Digit-for-letter lookalikes that Unicode confusables data can't catch."""

    def test_digit_one_as_l(self):
        r = lh.detect_lookalike_domain("paypa1.com")
        self.assertIsNotNone(r)
        self.assertEqual(r["resembles"], "paypal.com")
        self.assertEqual(r["method"], "leet")

    def test_digit_zero_as_o(self):
        r = lh.detect_lookalike_domain("micr0soft.com")
        self.assertIsNotNone(r)
        self.assertEqual(r["resembles"], "microsoft.com")

    def test_digit_one_as_i(self):
        r = lh.detect_lookalike_domain("m1crosoft.com")
        self.assertIsNotNone(r)
        self.assertEqual(r["resembles"], "microsoft.com")

    def test_multiple_substitutions(self):
        r = lh.detect_lookalike_domain("g00gle.com")
        self.assertIsNotNone(r)
        self.assertEqual(r["resembles"], "google.com")

    def test_exact_brand_never_flagged(self):
        for brand in ("paypal.com", "microsoft.com", "usbank.com", "coinbase.com"):
            self.assertIsNone(lh.detect_lookalike_domain(brand))

    def test_digit_free_unrelated_domain_no_leet_hit(self):
        self.assertIsNone(lh.detect_leet_lookalike("example.com"))

    def test_leet_signal_lands_in_enrichment(self):
        eml = (b"From: PayPal <security@paypa1.com>\r\nSubject: verify\r\n"
               b"Content-Type: text/plain\r\n\r\nverify now\r\n")
        import email
        from email import policy
        parsed = lh.parse_email(email.message_from_bytes(eml, policy=policy.default))
        e = lh.enrich(parsed)
        self.assertEqual((e["lookalike"] or {}).get("resembles"), "paypal.com")
        self.assertTrue(any(k == "lookalike" for k, _ in e["signals"]))


class TestUnicodeLookalike(BaseTest):
    """Unicode homoglyph lookalikes: raw Unicode (HTTP upload path) and
    punycode (how IDN sender domains actually arrive over SMTP on the SES
    path).

    These tests turned the README's 'coverage unverified' into a known
    state. The original implementation passed brand domains as
    confusable_homoglyphs preferred_aliases; that parameter expects Unicode
    script aliases ('latin', 'cyrillic'), so the check matched nothing and
    never fired - silently, in both directions. Detection now decodes
    punycode, builds an ASCII skeleton of the domain (each non-ASCII char
    mapped to its ASCII confusable), and compares against WATCHED_BRANDS.
    """

    def test_cyrillic_homoglyphs_flagged(self):
        cases = [
            ("micros\u043eft.com", "microsoft.com"),   # Cyrillic о (U+043E)
            ("g\u043e\u043egle.com", "google.com"),    # two Cyrillic о
            ("p\u0430ypal.com", "paypal.com"),         # Cyrillic а (U+0430)
            ("\u0430pple.com", "apple.com"),           # leading Cyrillic а
            ("ch\u0430se.com", "chase.com"),           # Cyrillic а, bank domain
            ("amazon.\u0441om", "amazon.com"),         # Cyrillic с (U+0441) in TLD
            ("v\u0435nmo.com", "venmo.com"),           # Cyrillic е (U+0435)
            ("u\u0455bank.com", "usbank.com"),         # Cyrillic ѕ (U+0455, dze)
        ]
        for domain, brand in cases:
            with self.subTest(domain=domain):
                r = lh.detect_lookalike_domain(domain)
                self.assertIsNotNone(r, f"{domain!r} was not flagged")
                self.assertEqual(r["resembles"], brand)
                self.assertEqual(r["suspect"], domain)
                self.assertEqual(r["method"], "unicode")

    def test_greek_omicron_flagged(self):
        # Greek omicron (U+03BF) is visually identical to Latin o
        r = lh.detect_lookalike_domain("micros\u03bfft.com")
        self.assertIsNotNone(r)
        self.assertEqual(r["resembles"], "microsoft.com")
        self.assertEqual(r["method"], "unicode")

    def test_punycode_sender_flagged(self):
        """SMTP headers deliver IDN sender domains as punycode ('xn--'),
        never raw Unicode - so this is the form the SES path actually sees.
        Detection blind to punycode would be blind to the entire SES path."""
        cases = [
            ("xn--microsft-sbh.com", "micros\u043eft.com", "microsoft.com"),
            ("xn--pypal-4ve.com", "p\u0430ypal.com", "paypal.com"),
            ("xn--pple-43d.com", "\u0430pple.com", "apple.com"),
            ("xn--ggle-55da.com", "g\u043e\u043egle.com", "google.com"),
        ]
        for puny, uni, brand in cases:
            with self.subTest(punycode=puny):
                # Fixture sanity: the punycode really decodes to the spoof
                self.assertEqual(puny.encode("ascii").decode("idna"), uni)
                r = lh.detect_lookalike_domain(puny)
                self.assertIsNotNone(r, f"punycode {puny!r} ({uni!r}) not flagged")
                self.assertEqual(r["resembles"], brand)
                # Report what the header actually said, not the decoded form
                self.assertEqual(r["suspect"], puny)
                self.assertEqual(r["method"], "unicode")

    def test_punycode_decode_helper(self):
        self.assertEqual(lh._to_unicode_domain("xn--microsft-sbh.com"),
                         "micros\u043eft.com")
        self.assertEqual(lh._to_unicode_domain("microsoft.com"), "microsoft.com")

    def test_legit_international_domains_not_flagged(self):
        # Legitimate IDNs whose non-ASCII chars have no path to any watched
        # brand must never flag - ü and é have no ASCII confusable skeleton.
        for domain in ("m\u00fcnchen.de", "caf\u00e9-dumonde.com"):
            with self.subTest(domain=domain):
                self.assertIsNone(lh.detect_lookalike_domain(domain))

    def test_ascii_domains_skip_skeleton(self):
        """Pure-ASCII domains are the leet arm's territory; the skeleton
        must decline them so the unicode arm can never produce ASCII false
        positives."""
        self.assertIsNone(lh._ascii_skeleton("paypa1.com"))
        self.assertIsNone(lh._ascii_skeleton("google.com"))

    def test_mixed_digit_and_cyrillic_known_gap(self):
        """micr0sоft.com: digit 0 AND Cyrillic о together. The leet arm
        can't resolve it (the Cyrillic char survives digit translation) and
        the skeleton only rewrites non-ASCII chars, so the '0' remains and
        the skeleton isn't a brand. Known limitation, pinned here so a
        future fix flips this assertion deliberately, not silently."""
        self.assertIsNone(lh.detect_lookalike_domain("micr0s\u043eft.com"))

    def test_hostile_input_never_raises(self):
        """enrich() calls detection on attacker-controlled input; garbage
        punycode, zero-width chars, and oversized labels must not raise."""
        hostile = [
            "xn--",                          # bare punycode prefix
            "xn--zzzzzzzzzzzz.com",          # undecodable punycode
            "\u200b\u200b.com",              # zero-width spaces
            "a" * 300 + ".com",              # oversized label
            "\u0430" * 100 + ".com",         # long all-Cyrillic label
            "..", ".",
        ]
        for domain in hostile:
            with self.subTest(domain=repr(domain)):
                lh.detect_lookalike_domain(domain)   # return value irrelevant
                lh.detect_unicode_lookalike(domain)  # not crashing is the test

    def test_unicode_signal_lands_in_enrichment(self):
        """End-to-end parity with the leet enrichment test: a punycode
        homoglyph sender must surface as a lookalike signal via
        parse_email -> enrich, and log method='unicode'."""
        eml = (b"From: PayPal <security@xn--pypal-4ve.com>\r\nSubject: verify\r\n"
               b"Content-Type: text/plain\r\n\r\nverify now\r\n")
        import email
        from email import policy
        parsed = lh.parse_email(email.message_from_bytes(eml, policy=policy.default))
        e = lh.enrich(parsed)
        self.assertEqual((e["lookalike"] or {}).get("resembles"), "paypal.com")
        self.assertEqual((e["lookalike"] or {}).get("method"), "unicode")
        self.assertTrue(any(k == "lookalike" for k, _ in e["signals"]))


class TestAttachments(BaseTest):
    """Attachment extraction, risky-extension flagging, and hash reputation."""

    def _eml_with_attachment(self, filename, payload=b"MZ fake exe bytes"):
        from email.message import EmailMessage
        msg = EmailMessage()
        msg["From"] = "a@b.example"
        msg["Subject"] = "invoice"
        msg["Authentication-Results"] = "mx.test; dmarc=fail"
        msg.set_content("open the attachment")
        msg.add_attachment(payload, maintype="application",
                           subtype="octet-stream", filename=filename)
        return msg

    def test_attachment_extracted_and_hashed(self):
        import hashlib
        parsed = lh.parse_email(self._eml_with_attachment("invoice.exe", b"payload-bytes"))
        self.assertEqual(len(parsed["attachments"]), 1)
        att = parsed["attachments"][0]
        self.assertEqual(att["filename"], "invoice.exe")
        self.assertEqual(att["ext"], ".exe")
        self.assertEqual(att["size"], len(b"payload-bytes"))
        self.assertEqual(att["sha256"], hashlib.sha256(b"payload-bytes").hexdigest())

    def test_risky_extension_flagged_in_enrichment(self):
        parsed = lh.parse_email(self._eml_with_attachment("invoice.exe"))
        e = lh.enrich(parsed)
        self.assertEqual(e["risky_attachment_count"], 1)
        self.assertTrue(any(k == "attachment" for k, _ in e["signals"]))

    def test_benign_extension_not_flagged(self):
        parsed = lh.parse_email(self._eml_with_attachment("report.pdf"))
        e = lh.enrich(parsed)
        self.assertEqual(e["risky_attachment_count"], 0)
        self.assertFalse(any(k == "attachment" for k, _ in e["signals"]))

    def test_inline_bodies_are_not_attachments(self):
        import email
        from email import policy
        parsed = lh.parse_email(email.message_from_bytes(HTML_EML, policy=policy.default))
        self.assertEqual(parsed["attachments"], [])

    def test_forward_wrapper_not_counted_as_attachment(self):
        import email
        from email import policy
        msg = email.message_from_bytes(FORWARD_EML, policy=policy.default)
        target = lh.extract_target_email(msg)
        parsed = lh.parse_email(target)
        self.assertEqual(parsed["attachments"], [])

    def test_attachment_cap(self):
        from email.message import EmailMessage
        msg = EmailMessage()
        msg["From"] = "a@b.example"
        msg["Subject"] = "many"
        msg.set_content("x")
        for i in range(10):
            msg.add_attachment(b"x", maintype="application",
                               subtype="octet-stream", filename=f"f{i}.bin")
        parsed = lh.parse_email(msg)
        self.assertEqual(len(parsed["attachments"]), lh.ATTACHMENT_MAX_PARTS)

    def test_oversize_attachment_recorded_but_not_hashed(self):
        big = b"x" * (lh.ATTACHMENT_MAX_BYTES + 1)
        parsed = lh.parse_email(self._eml_with_attachment("huge.bin", big))
        att = parsed["attachments"][0]
        self.assertEqual(att["size"], len(big))
        self.assertIsNone(att["sha256"])

    def test_vt_filehash_flags_known_malware(self):
        os.environ["VIRUSTOTAL_API_KEY"] = "vt-key"
        lh.http.request.return_value = FakeHttpResponse(200, {
            "data": {"attributes": {"last_analysis_stats": {"malicious": 12}}}
        })
        parsed = lh.parse_email(self._eml_with_attachment("invoice.exe"))
        results = lh.check_attachment_reputation(parsed["attachments"])
        self.assertEqual(len(results), 1)
        self.assertTrue(results[0]["flagged"])
        call = lh.http.request.call_args
        self.assertIn("/api/v3/files/", call.args[1])
        self.assertIn(parsed["attachments"][0]["sha256"], call.args[1])

    def test_vt_filehash_404_unknown_not_flagged(self):
        os.environ["VIRUSTOTAL_API_KEY"] = "vt-key"
        lh.http.request.return_value = FakeHttpResponse(404, {})
        parsed = lh.parse_email(self._eml_with_attachment("new.exe"))
        results = lh.check_attachment_reputation(parsed["attachments"])
        self.assertFalse(results[0]["flagged"])

    def test_vt_filehash_cache_hit_skips_lookup(self):
        os.environ["VIRUSTOTAL_API_KEY"] = "vt-key"
        lh.http.request.return_value = FakeHttpResponse(200, {
            "data": {"attributes": {"last_analysis_stats": {"malicious": 1}}}
        })
        parsed = lh.parse_email(self._eml_with_attachment("invoice.exe"))
        lh.check_attachment_reputation(parsed["attachments"])
        lh.http.request.reset_mock()
        results = lh.check_attachment_reputation(parsed["attachments"])
        self.assertTrue(results[0]["flagged"])
        lh.http.request.assert_not_called()

    def test_no_vt_key_no_lookup(self):
        parsed = lh.parse_email(self._eml_with_attachment("invoice.exe"))
        self.assertEqual(lh.check_attachment_reputation(parsed["attachments"]), [])
        lh.http.request.assert_not_called()

    def test_flagged_attachment_reaches_signals_and_telemetry_fields(self):
        os.environ["VIRUSTOTAL_API_KEY"] = "vt-key"
        lh.http.request.return_value = FakeHttpResponse(200, {
            "data": {"attributes": {"last_analysis_stats": {"malicious": 12}}}
        })
        parsed = lh.parse_email(self._eml_with_attachment("invoice.exe"))
        e = lh.enrich(parsed)
        self.assertEqual(e["attachment_rep_flagged_count"], 1)
        notes = " ".join(n for _, n in e["signals"])
        self.assertIn("known malware", notes)


class TestHistory(BaseTest):
    """Per-submitter 'you've asked about this sender before' tracking."""

    def test_disabled_by_default(self):
        self.assertIsNone(lh.get_and_record_history("a@b.com", "example.com", "suspicious"))
        self.assertEqual(len(self.table.items), 0)

    def test_first_and_repeat_lookup(self):
        os.environ["ENABLE_SUBMITTER_HISTORY"] = "true"
        first = lh.get_and_record_history("user@x.example", "phish.example", "likely_phishing")
        self.assertEqual(first, {"prior_lookups": 0, "last_verdict": None})
        second = lh.get_and_record_history("user@x.example", "phish.example", "likely_phishing")
        self.assertEqual(second["prior_lookups"], 1)
        self.assertEqual(second["last_verdict"], "likely_phishing")

    def test_different_submitters_are_isolated(self):
        os.environ["ENABLE_SUBMITTER_HISTORY"] = "true"
        lh.get_and_record_history("user1@x.example", "sender.example", "suspicious")
        other = lh.get_and_record_history("user2@x.example", "sender.example", "suspicious")
        self.assertEqual(other["prior_lookups"], 0)

    def test_submitter_identity_stored_hashed_not_verbatim(self):
        os.environ["ENABLE_SUBMITTER_HISTORY"] = "true"
        lh.get_and_record_history("secret-user@x.example", "sender.example", "suspicious")
        for pk in self.table.items:
            self.assertNotIn("secret-user", pk)

    def test_fails_open_on_dynamo_error(self):
        os.environ["ENABLE_SUBMITTER_HISTORY"] = "true"
        self.table.fail = True
        result = lh.get_and_record_history("user@x.example", "sender.example", "suspicious")
        self.assertEqual(result["prior_lookups"], 0)  # degraded, not crashed

    def test_history_note_formatting(self):
        self.assertEqual(lh.format_history_note(None), "")
        self.assertEqual(lh.format_history_note({"prior_lookups": 0, "last_verdict": None}), "")
        note = lh.format_history_note({"prior_lookups": 1, "last_verdict": "likely_phishing"})
        self.assertIn("once before", note)
        self.assertIn("likely phishing", note)
        note = lh.format_history_note({"prior_lookups": 3, "last_verdict": "suspicious"})
        self.assertIn("3 times before", note)

    def test_ses_reply_includes_history_on_repeat(self):
        os.environ["ENABLE_SUBMITTER_HISTORY"] = "true"
        body = mock.Mock()
        body.read.return_value = PLAIN_EML
        lh.s3.get_object.return_value = {"Body": body}
        event = {"Records": [{"ses": {"mail": {"messageId": "m", "source": "alice@x.example"}}}]}
        lh.lambda_handler(event, None)
        first_reply = lh.ses.send_email.call_args.kwargs["Message"]["Body"]["Text"]["Data"]
        self.assertNotIn("asked about this sender", first_reply)
        lh.lambda_handler(event, None)
        second_reply = lh.ses.send_email.call_args.kwargs["Message"]["Body"]["Text"]["Data"]
        self.assertIn("asked about this sender once before", second_reply)

    def test_http_response_includes_history_field(self):
        os.environ["ENABLE_SUBMITTER_HISTORY"] = "true"
        event = {
            "requestContext": {"http": {"method": "POST", "sourceIp": "203.0.113.9"}},
            "body": PLAIN_EML.decode(), "isBase64Encoded": False,
        }
        lh.lambda_handler(event, None)
        resp = lh.lambda_handler(event, None)
        payload = json.loads(resp["body"])
        self.assertEqual(payload["history"]["prior_lookups"], 1)

    def test_http_history_null_when_disabled(self):
        event = {
            "requestContext": {"http": {"method": "POST", "sourceIp": "203.0.113.9"}},
            "body": PLAIN_EML.decode(), "isBase64Encoded": False,
        }
        resp = lh.lambda_handler(event, None)
        self.assertIsNone(json.loads(resp["body"])["history"])


# ---------------------------------------------------------------------------
# 2026-07-07 review-session regressions (duplicate auth headers, URL
# punctuation strip, reputation short-circuit, frozenset brand list, HTML
# body fallback, received chain in prompt, prompt injection hardening)
# ---------------------------------------------------------------------------

class TestMultipleAuthHeaders(BaseTest):
    """A phisher can pre-embed a forged Authentication-Results header in the
    phishing email itself, so an HTTP-path upload carries a fake dmarc=pass.
    Duplicate headers are flagged; the first (outermost - the one the real
    receiving MTA prepended) is the one that gets parsed."""

    RAW_TWO = (
        b"From: Alice <alice@example.com>\r\n"
        b"Subject: hi\r\n"
        b"Authentication-Results: mx.google.com; dmarc=pass header.from=example.com\r\n"
        b"Authentication-Results: forged.attacker; dmarc=pass header.from=paypal.com\r\n"
        b"Content-Type: text/plain\r\n\r\nhello\r\n"
    )
    RAW_ONE = (
        b"From: Bob <bob@example.com>\r\n"
        b"Subject: hi\r\n"
        b"Authentication-Results: mx.google.com; dmarc=pass\r\n"
        b"Content-Type: text/plain\r\n\r\nhello\r\n"
    )
    RAW_ZERO = (
        b"From: C <c@example.com>\r\n"
        b"Subject: hi\r\n"
        b"Content-Type: text/plain\r\n\r\nhello\r\n"
    )

    def _parse(self, raw):
        import email
        from email import policy
        return lh.parse_email(email.message_from_bytes(raw, policy=policy.default))

    def test_counts_all_auth_headers(self):
        self.assertEqual(self._parse(self.RAW_TWO)["auth_header_count"], 2)

    def test_first_header_is_the_one_parsed(self):
        parsed = self._parse(self.RAW_TWO)
        self.assertIn("mx.google.com", parsed["auth_results"])
        self.assertNotIn("forged.attacker", parsed["auth_results"])

    def test_enrich_flags_duplicates_as_first_signal(self):
        e = lh.enrich(self._parse(self.RAW_TWO))
        self.assertTrue(e["signals"], "expected at least one signal")
        kind, note = e["signals"][0]
        self.assertEqual(kind, "auth")
        self.assertIn("Multiple Authentication-Results", note)

    def test_single_header_not_flagged(self):
        parsed = self._parse(self.RAW_ONE)
        self.assertEqual(parsed["auth_header_count"], 1)
        self.assertFalse(any(
            "Multiple Authentication-Results" in note
            for _, note in lh.enrich(parsed)["signals"]
        ))

    def test_zero_headers_yields_empty_auth_results(self):
        parsed = self._parse(self.RAW_ZERO)
        self.assertEqual(parsed["auth_header_count"], 0)
        self.assertEqual(parsed["auth_results"], "")


class TestUrlPunctuationStrip(BaseTest):
    """URL_RE swallows trailing prose punctuation ('...example.com/x).'),
    which poisons reputation lookups and the 24h cache key. Stripped before
    dedupe so 'url' and 'url.' collapse to a single entry."""

    def _parse(self, raw):
        import email
        from email import policy
        return lh.parse_email(email.message_from_bytes(raw, policy=policy.default))

    def test_trailing_punctuation_stripped_and_deduped(self):
        raw = (
            b"From: D <d@x.com>\r\nSubject: s\r\nContent-Type: text/plain\r\n\r\n"
            b"Visit https://example.com/login. Or (https://example.com/login) or\r\n"
            b"https://example.com/login for details.\r\n"
        )
        parsed = self._parse(raw)
        self.assertEqual(parsed["urls"].count("https://example.com/login"), 1)
        for url in parsed["urls"]:
            self.assertFalse(url.endswith((".", ",", ")", ";", "!", "?")), url)

    def test_query_strings_survive(self):
        raw = (
            b"From: D <d@x.com>\r\nSubject: s\r\nContent-Type: text/plain\r\n\r\n"
            b"Track at https://track.example/pkg?id=42&x=1, thanks.\r\n"
        )
        self.assertIn("https://track.example/pkg?id=42&x=1", self._parse(raw)["urls"])


class TestReputationShortCircuit(BaseTest):
    """One confirmed threat-intel hit is decisive per the decision hierarchy;
    checking the remaining URLs only spends latency against the ~10s budget
    (worst case without it: 3 URLs x 3 services x 6s timeout, sequential).
    Must fire for cached flagged hits too - the same phishing URL arriving
    in waves means the cached case is the common one."""

    URLS = ["https://a.example/bad", "https://b.example/x", "https://c.example/y"]

    def test_fresh_flagged_hit_stops_iteration(self):
        os.environ["VIRUSTOTAL_API_KEY"] = "vt-key"
        lh.http.request.return_value = FakeHttpResponse(200, {
            "data": {"attributes": {"last_analysis_stats": {"malicious": 5}}}
        })
        results = lh.check_url_reputation(self.URLS)
        self.assertEqual(len(results), 1)
        self.assertTrue(results[0]["flagged"])
        # only VT is configured, so exactly one lookup happened
        self.assertEqual(lh.http.request.call_count, 1)

    def test_cached_flagged_hit_stops_iteration(self):
        os.environ["VIRUSTOTAL_API_KEY"] = "vt-key"
        cached = {"url": self.URLS[0], "checks": [], "flagged": True}
        lh._reputation_cache_put(self.URLS[0], cached)
        results = lh.check_url_reputation(self.URLS)
        self.assertEqual(len(results), 1)
        self.assertTrue(results[0]["flagged"])
        lh.http.request.assert_not_called()  # never reached the live lookups

    def test_no_flag_means_no_short_circuit(self):
        os.environ["VIRUSTOTAL_API_KEY"] = "vt-key"
        lh.http.request.return_value = FakeHttpResponse(404, {})
        results = lh.check_url_reputation(self.URLS)
        self.assertEqual(len(results), 3)
        self.assertFalse(any(r["flagged"] for r in results))


class TestWatchedBrandsExpansion(BaseTest):
    """WATCHED_BRANDS is a frozenset (O(1) membership, so list size is
    free) expanded with regional banks, telecom, and insurance."""

    def test_is_frozenset(self):
        self.assertIsInstance(lh.WATCHED_BRANDS, frozenset)

    def test_no_brand_contains_digits(self):
        # A digit-bearing brand would collide with itself in the leet
        # detector's digit-normalization step.
        for brand in lh.WATCHED_BRANDS:
            self.assertFalse(any(c.isdigit() for c in brand), brand)

    def test_new_brand_leet_detection(self):
        r = lh.detect_lookalike_domain("veriz0n.com")
        self.assertIsNotNone(r)
        self.assertEqual(r["resembles"], "verizon.com")
        self.assertEqual(r["method"], "leet")

    def test_new_brand_exact_match_is_legitimate(self):
        for brand in ("mtb.com", "key.com", "citizensbank.com", "spectrum.com"):
            self.assertIsNone(lh.detect_lookalike_domain(brand))


class TestHtmlBodyFallback(BaseTest):
    """HTML-only emails derive their text body via BeautifulSoup (entities
    decoded, script content dropped) with the old tag-strip regex as a last
    resort for HTML pathological enough to break the parser."""

    def test_html_only_body_extracted_without_script_content(self):
        import email
        from email import policy
        raw = (
            b"From: E <e@x.com>\r\nSubject: s\r\nContent-Type: text/html\r\n\r\n"
            b"<html><body><p>Dear&nbsp;user,</p><script>steal()</script>"
            b"<p>Act now</p></body></html>\r\n"
        )
        parsed = lh.parse_email(email.message_from_bytes(raw, policy=policy.default))
        self.assertNotIn("steal()", parsed["body"])
        self.assertIn("Act now", parsed["body"])


class TestPromptContent(BaseTest):
    """The Received chain feeds the model (previously parsed but unused),
    and the system prompt carries the injection-hardening language."""

    def _parse(self, raw):
        import email
        from email import policy
        return lh.parse_email(email.message_from_bytes(raw, policy=policy.default))

    def test_received_chain_appears_in_prompt(self):
        raw = (
            b"Received: from hop1.example.com by mx.test\r\n"
            b"From: F <f@x.com>\r\nSubject: s\r\nContent-Type: text/plain\r\n\r\nb\r\n"
        )
        parsed = self._parse(raw)
        prompt = lh.build_prompt(parsed, lh.enrich(parsed))
        self.assertIn("RECEIVED CHAIN", prompt)
        self.assertIn("hop1.example.com", prompt)

    def test_empty_received_chain_renders_none(self):
        raw = b"From: G <g@x.com>\r\nSubject: s\r\nContent-Type: text/plain\r\n\r\nb\r\n"
        parsed = self._parse(raw)
        prompt = lh.build_prompt(parsed, lh.enrich(parsed))
        self.assertIn("RECEIVED CHAIN", prompt)

    def test_system_prompt_contains_injection_hardening(self):
        self.assertIn("untrusted", lh.SYSTEM_PROMPT)
        self.assertIn("Never follow instructions", lh.SYSTEM_PROMPT)
        self.assertIn("phishing indicator", lh.SYSTEM_PROMPT)


# ---------------------------------------------------------------------------
# Hardening regression tests (charset fallback, URL ordering, p= vs sp=,
# CRLF subject stripping, verdict sanitization, .eml guard, HTTP 500 path)
#
# These are pytest-style functions (plain `assert`, no TestCase). They run
# under `python -m pytest` alongside the unittest classes above, but are NOT
# picked up by `python test_lambda_handler.py` / unittest.main() - which is
# why the module docstring says to use pytest.
# ---------------------------------------------------------------------------

import email as _email
from email import policy as _policy
from email.message import EmailMessage as _EmailMessage


def test_hostile_charset_degrades_instead_of_crashing():
    """An attacker-set unknown charset must not kill parse_email; the body
    should fall back to replacement decoding and URLs still be extracted."""
    raw = (b"From: a@b.com\r\nSubject: hi\r\n"
           b'Content-Type: text/plain; charset="x-unknown-999"\r\n\r\n'
           b"Click https://evil.example/login now\r\n")
    msg = _email.message_from_bytes(raw, policy=_policy.default)
    parsed = lh.parse_email(msg)
    assert "evil.example" in parsed["body"]
    assert parsed["urls"] == ["https://evil.example/login"]


def test_url_extraction_first_seen_order_and_dedupe():
    """URL list must be deterministic first-seen order, deduped - so the
    [:20] cap and the 3-URL reputation cap always hit the same URLs."""
    raw = (b"From: a@b.com\r\nSubject: hi\r\nContent-Type: text/plain\r\n\r\n"
           b"https://a.example/1 https://b.example/2 "
           b"https://a.example/1 https://c.example/3\r\n")
    parsed = lh.parse_email(_email.message_from_bytes(raw, policy=_policy.default))
    assert parsed["urls"] == [
        "https://a.example/1", "https://b.example/2", "https://c.example/3",
    ]


def test_dmarc_policy_p_not_confused_with_sp():
    """Gmail reports both p= and sp= in Authentication-Results. 'p=none
    sp=reject' must parse as policy 'none', never 'reject'."""
    base = {"reply_to": "", "from_addr": "a@b.com", "return_path": "",
            "from_domain": "b.com", "urls": [], "html_body": ""}
    e = lh.enrich({**base, "auth_results":
                   "mx.google.com; dmarc=pass (p=NONE sp=REJECT dis=NONE)"})
    assert e["dmarc_policy"] == "none"
    e = lh.enrich({**base, "auth_results":
                   "mx.google.com; dmarc=pass (p=REJECT sp=NONE dis=NONE)"})
    assert e["dmarc_policy"] == "reject"
    e = lh.enrich({**base, "auth_results": "dmarc=pass (p=QUARANTINE sp=REJECT)"})
    assert e["dmarc_policy"] == "quarantine"


def test_reply_subject_strips_crlf_header_injection():
    """CR/LF in an echoed subject is a header-injection vector; it must be
    collapsed to spaces, with a fallback when the subject is missing."""
    s = lh._sanitize_reply_subject("Invoice\r\nBcc: victim@example.com\nX-Evil: 1")
    assert "\r" not in s and "\n" not in s
    assert s == "Invoice Bcc: victim@example.com X-Evil: 1"
    assert lh._sanitize_reply_subject(None) == "phishing check"
    assert lh._sanitize_reply_subject("") == "phishing check"


def test_verdict_sanitization_clamps_and_coerces():
    """Model output is untrusted: confidence clamped 0-100, non-dict
    indicator entries dropped, text fields coerced to strings."""
    v = lh._sanitize_verdict({
        "verdict": "suspicious", "confidence": "150",
        "indicators": ["not-a-dict", {"signal": 42, "severity": None}],
        "summary": None, "recommendation": 7,
    })
    assert v["confidence"] == 100
    assert v["indicators"] == [{"signal": "42", "detail": "", "severity": "med"}]
    assert v["summary"] == "" and v["recommendation"] == "7"

    v = lh._sanitize_verdict({"verdict": "likely_phishing",
                              "confidence": -5, "indicators": "nope"})
    assert v["confidence"] == 0 and v["indicators"] == []

    v = lh._sanitize_verdict({"verdict": "likely_legitimate", "confidence": 92,
                              "indicators": [{"signal": "a", "detail": "b",
                                              "severity": "low"}]})
    assert v["confidence"] == 92 and len(v["indicators"]) == 1


def test_malformed_eml_attachment_skipped_not_crashed():
    """A .eml attachment whose payload decodes to None/empty must be skipped;
    email.message_from_bytes(None) would otherwise raise on hostile input."""
    outer = _EmailMessage()
    outer["From"] = "user@example.com"
    outer["Subject"] = "fwd"
    outer.set_content("see attached")
    outer.add_attachment(b"", maintype="application",
                         subtype="octet-stream", filename="broken.eml")
    assert lh.extract_target_email(outer) is None


def test_http_pipeline_error_returns_structured_500_with_cors():
    """An unexpected pipeline exception on the web path must return JSON
    with CORS headers, not Lambda's bare 502 (which browsers surface as an
    opaque network error)."""
    event = {
        "requestContext": {"http": {"method": "POST", "sourceIp": "1.2.3.4"}},
        "body": "From: a@b.com\r\nSubject: t\r\n\r\nbody",
        "isBase64Encoded": False,
    }
    with mock.patch.object(lh, "check_rate_limit", return_value=True), \
         mock.patch.object(lh, "parse_email", side_effect=RuntimeError("boom")):
        resp = lh.handle_http_event(event)
    assert resp["statusCode"] == 500
    assert "Access-Control-Allow-Origin" in resp["headers"]
    assert "error" in resp["body"]


if __name__ == "__main__":
    unittest.main(verbosity=2)
