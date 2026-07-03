"""Test suite for lambda_handler. Mocks all external boundaries
(S3, SES, DynamoDB, Anthropic API, reputation HTTP calls)."""

import os
import json
import email
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
                    "ALLOWED_ORIGIN"):
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


class TestHardeningFixes(BaseTest):
    """Regression tests for the security/robustness review fixes."""

    def _enrich_base(self, auth_results):
        return lh.enrich({
            "auth_results": auth_results, "reply_to": "", "from_addr": "a@example.com",
            "from_domain": "example.com", "return_path": "", "urls": [],
            "html_body": "", "body": "",
        })

    def test_sp_reject_not_mistaken_for_p_reject(self):
        # Gmail reports both policies: "(p=NONE sp=REJECT dis=NONE)".
        # Substring matching would misread this as a REJECT policy.
        e = self._enrich_base("mx.google.com; dmarc=pass (p=NONE sp=REJECT dis=NONE)")
        self.assertEqual(e["dmarc_policy"], "none")

    def test_real_p_reject_still_detected(self):
        e = self._enrich_base("mx.test; dmarc=pass (p=REJECT sp=REJECT)")
        self.assertEqual(e["dmarc_policy"], "reject")

    def test_hostile_charset_does_not_crash(self):
        raw = (b"From: a@example.com\r\nSubject: hi\r\n"
               b"Content-Type: text/plain; charset=\"x-unknown-999\"\r\n\r\n"
               b"hello https://example.com/x\r\n")
        msg = email.message_from_bytes(raw, policy=lh.policy.default)
        parsed = lh.parse_email(msg)
        self.assertIn("hello", parsed["body"])
        self.assertEqual(parsed["urls"], ["https://example.com/x"])

    def test_hostile_charset_http_returns_200(self):
        raw = ("From: a@example.com\r\nSubject: hi\r\n"
               "Content-Type: text/plain; charset=\"x-unknown-999\"\r\n\r\nhello\r\n")
        event = {"requestContext": {"http": {"method": "POST", "sourceIp": "1.2.3.4"}},
                 "body": raw, "isBase64Encoded": False}
        resp = lh.lambda_handler(event, None)
        self.assertEqual(resp["statusCode"], 200)

    def test_sanitize_verdict_drops_non_dict_indicators(self):
        v = lh._sanitize_verdict({"verdict": "suspicious", "confidence": 55,
                                  "indicators": ["junk", {"signal": "s"}],
                                  "summary": "s", "recommendation": "r"})
        self.assertEqual(v["indicators"], [{"signal": "s"}])

    def test_sanitize_verdict_clamps_confidence(self):
        self.assertEqual(lh._sanitize_verdict({"verdict": "unknown", "confidence": 250})["confidence"], 100)
        self.assertEqual(lh._sanitize_verdict({"verdict": "unknown", "confidence": "not-a-number"})["confidence"], 0)

    def test_url_order_is_first_seen(self):
        raw = (b"From: a@example.com\r\nSubject: t\r\nContent-Type: text/plain\r\n\r\n"
               b"https://one.example/a https://two.example/b https://one.example/a\r\n")
        msg = email.message_from_bytes(raw, policy=lh.policy.default)
        self.assertEqual(lh.parse_email(msg)["urls"],
                         ["https://one.example/a", "https://two.example/b"])

    def test_reply_subject_strips_newlines(self):
        raw = PLAIN_EML.replace(b"Subject: Is this phishing?",
                                b"Subject: =?utf-8?B?VXJnZW50CkJjYzogeEBleGFtcGxlLmNvbQ==?=")
        self.mocks["s3"].get_object.return_value = {"Body": mock.Mock(read=mock.Mock(return_value=raw))}
        event = {"Records": [{"ses": {"mail": {"messageId": "m1", "source": "alice@example.com"}}}]}
        lh.lambda_handler(event, None)
        sent_subject = self.mocks["ses"].send_email.call_args.kwargs["Message"]["Subject"]["Data"]
        self.assertNotIn("\n", sent_subject)
        self.assertNotIn("\r", sent_subject)


if __name__ == "__main__":
    unittest.main(verbosity=2)
