"""
Phishing Email Analyzer - Lambda handler

Two entry paths, one pipeline:

  1. SES path:  SES receives mail -> drops .eml in S3 -> triggers this Lambda ->
                parse -> enrich -> ask Claude -> reply via SES.
  2. HTTP path: Lambda Function URL receives a raw .eml POSTed from the web
                frontend -> same parse/enrich/analyze pipeline -> JSON response.

Env vars expected:
  ANTHROPIC_API_KEY   - your Claude API key
  BUCKET_NAME         - S3 bucket where SES drops raw emails
  FROM_ADDRESS        - verified SES sender, e.g. "no-reply@yourdomain.com"
  REGION              - AWS region for SES (e.g. "us-east-1")

Optional env vars:
  VIRUSTOTAL_API_KEY        - enables VirusTotal URL reputation lookups
  URLSCAN_API_KEY           - enables urlscan.io domain reputation lookups
  PHISHTANK_ENABLED         - "true" enables PhishTank lookups (keyless)
  PHISHTANK_APP_KEY         - optional PhishTank app key (raises rate limits)
  ENABLE_MODEL_ESCALATION   - "true" enables Haiku -> Sonnet escalation on
                              low-confidence verdicts (default "false")
  ESCALATION_CONFIDENCE     - confidence threshold below which escalation
                              triggers (default 70)
  ALLOWED_ORIGIN            - CORS origin for the HTTP path (default "*";
                              set to "https://fredsprivacy.com" in production)
  TURNSTILE_SECRET_KEY      - Cloudflare Turnstile secret. When set, the HTTP
                              path requires a valid Turnstile token in the
                              X-Turnstile-Token request header. Unset = the
                              CAPTCHA check is disabled (SES path is never
                              affected).
  ENABLE_SUBMITTER_HISTORY  - "true" enables per-submitter history ("you've
                              asked about this sender before"), stored in the
                              shared DynamoDB table with a 90-day TTL
                              (default "false")
"""

import os
import re
import json
import time
import email
import base64
import hashlib
import logging
import boto3
import urllib3
from email import policy
from email.utils import parseaddr
from urllib.parse import urlparse, urlencode
import anthropic
from bs4 import BeautifulSoup
from confusable_homoglyphs import confusables

logger = logging.getLogger()
logger.setLevel(logging.INFO)

s3 = boto3.client("s3")
ses = boto3.client("ses", region_name=os.environ.get("REGION", "us-east-1"))
claude = anthropic.Anthropic(api_key=os.environ["ANTHROPIC_API_KEY"])

dynamodb = boto3.resource("dynamodb", region_name=os.environ.get("REGION", "us-east-1"))
rate_limit_table = dynamodb.Table("phish-analyzer-rate-limits")

# Shared HTTP pool for reputation lookups. Tight timeouts: reputation is a
# nice-to-have signal, and the whole pipeline promises a verdict in ~10s.
http = urllib3.PoolManager(timeout=urllib3.Timeout(connect=2.0, read=4.0), retries=False)

RATE_LIMIT_PER_HOUR = 10
RATE_LIMIT_WINDOW_SECONDS = 3600

# Model routing
PRIMARY_MODEL = "claude-haiku-4-5"
ESCALATION_MODEL = "claude-sonnet-4-6"

# URL reputation
REPUTATION_MAX_URLS = 3          # cap external lookups per email
REPUTATION_CACHE_TTL = 86400     # cache verdicts for 24h in DynamoDB

# HTTP path
MAX_HTTP_BODY_BYTES = 500_000    # ~500 KB is generous for an .eml

URL_RE = re.compile(r"https?://[^\s<>\"']+", re.IGNORECASE)

# Attachment analysis
ATTACHMENT_MAX_PARTS = 5         # cap how many attachments get hashed/checked
ATTACHMENT_MAX_BYTES = 5_000_000 # skip hashing anything bigger than 5 MB
# Extensions that are executable or commonly abused for HTML-smuggling /
# script droppers. Flagged deterministically regardless of hash reputation.
RISKY_ATTACHMENT_EXTS = {
    ".exe", ".scr", ".pif", ".com", ".msi", ".bat", ".cmd", ".ps1",
    ".js", ".jse", ".vbs", ".vbe", ".wsf", ".hta", ".jar", ".iso",
    ".img", ".lnk", ".html", ".htm", ".shtml", ".svg", ".xll",
}

# Per-submitter history
HISTORY_TTL_SECONDS = 90 * 86400  # remember sender lookups for 90 days

# Cloudflare Turnstile server-side verification endpoint
TURNSTILE_VERIFY_URL = "https://challenges.cloudflare.com/turnstile/v0/siteverify"

# Brands worth checking for lookalike/homoglyph impersonation.
# Tune to your threat model - add the brands your users actually interact with.
# Note: every inbound email's sender domain is compared against each entry,
# so keep the list focused on brands that actually get impersonated - each
# addition is a small per-email cost in the confusables check.
WATCHED_BRANDS = [
    # Tech / cloud
    "microsoft.com", "google.com", "apple.com", "amazon.com",
    "docusign.com", "dropbox.com", "adobe.com", "netflix.com",
    "facebook.com", "instagram.com", "linkedin.com", "github.com",
    "zoom.us", "okta.com",
    # Banks / finance
    "paypal.com", "chase.com", "bankofamerica.com", "wellsfargo.com",
    "citi.com", "capitalone.com", "usbank.com", "americanexpress.com",
    "fidelity.com", "schwab.com", "venmo.com", "coinbase.com",
    "intuit.com", "adp.com",
    # Shipping / logistics / gov-adjacent (constant phishing lures)
    "fedex.com", "ups.com", "usps.com", "dhl.com", "irs.gov", "ssa.gov",
    # Retail
    "ebay.com", "walmart.com", "costco.com", "target.com",
]


def lambda_handler(event, context):
    """Dispatch: SES event or Function URL HTTP event, same pipeline underneath."""
    if isinstance(event, dict) and event.get("requestContext", {}).get("http"):
        return handle_http_event(event)
    return handle_ses_event(event)


# ---------------------------------------------------------------------------
# SES path (email in, email reply out)
# ---------------------------------------------------------------------------

def handle_ses_event(event):
    # SES action triggers Lambda with the S3 object key for the raw email.
    record = event["Records"][0]["ses"]
    message_id = record["mail"]["messageId"]
    sender = record["mail"]["source"]

    raw = s3.get_object(Bucket=os.environ["BUCKET_NAME"], Key=f"inbound/{message_id}")["Body"].read()
    submission = email.message_from_bytes(raw, policy=policy.default)

    # Loop prevention: don't analyze our own replies, bounces, or auto-responders.
    # Without this, a reply that bounces or gets auto-replied to could trigger
    # another analysis, which sends another reply, creating an infinite loop.
    if is_loop_or_bounce(sender, submission):
        logger.info("Skipping submission from %s (loop/bounce/auto-responder)", sender)
        return {"statusCode": 200, "skipped": True, "reason": "loop_or_bounce"}

    # Rate limiting: cap how many analyses a single sender can trigger per hour.
    # Runs before any parsing, enrichment, or Claude call, so an abusive volume
    # never incurs API cost. Rate-limited senders are dropped silently (no reply),
    # consistent with the loop/bounce handling above - a bounce reply would itself
    # be a new abuse vector.
    if not check_rate_limit(f"sender#{(sender or '').strip().lower()}"):
        logger.info("Rate limit exceeded for %s - dropping without reply", sender)
        return {"statusCode": 200, "skipped": True, "reason": "rate_limited"}

    target = extract_target_email(submission) or submission

    parsed = parse_email(target)
    enrichment = enrich(parsed)
    verdict = analyze_with_claude(parsed, enrichment)

    log_verdict(parsed, enrichment, verdict, message_id, source="ses")

    # Optional history note ("you've asked about this sender before"),
    # keyed to the submitting address. Fail-open; None when disabled.
    history = get_and_record_history(sender, parsed["from_domain"], verdict.get("verdict"))

    reply_body = format_reply(verdict, parsed, enrichment, history=history)
    # Strip CR/LF from the echoed subject: RFC 2047 encoded-words in a hostile
    # submission can decode to contain newlines, and control characters in an
    # outbound subject are rejected by SES at best, a header-injection vector
    # at worst.
    subject = _sanitize_reply_subject(submission.get("Subject"))
    send_reply(to=sender, subject=f"Re: {subject}", body=reply_body)

    return {"statusCode": 200, "messageId": message_id}


def _sanitize_reply_subject(subject):
    """Make a user-supplied subject safe to echo into an outbound SES header.

    RFC 2047 encoded-words in a hostile submission can decode to contain
    CR/LF, and control characters in an outbound subject are rejected by SES
    at best, a header-injection vector at worst. Collapse any newline runs to
    a single space and fall back to a default if the subject is missing/empty.
    """
    return re.sub(r"[\r\n]+", " ", str(subject or "phishing check"))


# ---------------------------------------------------------------------------
# HTTP path (Lambda Function URL: raw .eml in, JSON verdict out)
# ---------------------------------------------------------------------------

def handle_http_event(event):
    """Handle a POSTed .eml from the web frontend.

    Same pipeline as the SES path, minus the email reply. Rate limited per
    source IP using the same DynamoDB counter (keyed "ip#<addr>" so IP and
    sender-email buckets can never collide).
    """
    http_ctx = event["requestContext"]["http"]
    method = http_ctx.get("method", "").upper()

    if method == "OPTIONS":
        return _http_response(204, None)
    if method != "POST":
        return _http_response(405, {"error": "Use POST with the raw email (.eml) as the request body."})

    source_ip = http_ctx.get("sourceIp", "unknown")

    # Turnstile check runs before the rate limiter on purpose: a bot probing
    # without a token shouldn't be able to burn through the hourly budget of
    # a legitimate user behind the same NAT/office IP.
    turnstile = verify_turnstile(event, source_ip)
    if not turnstile["ok"]:
        logger.info("Turnstile rejected request from %s reason=%s", source_ip, turnstile["reason"])
        return _http_response(403, {"error": "Human verification failed. Refresh the page and try again."})

    if not check_rate_limit(f"ip#{source_ip}"):
        logger.info("HTTP rate limit exceeded for %s", source_ip)
        return _http_response(429, {"error": "Rate limit exceeded. Try again in an hour."})

    body = event.get("body") or ""
    if event.get("isBase64Encoded"):
        try:
            raw = base64.b64decode(body)
        except Exception:
            return _http_response(400, {"error": "Request body could not be decoded."})
    else:
        raw = body.encode("utf-8", errors="replace")

    if not raw.strip():
        return _http_response(400, {"error": "Empty request body. POST the raw email (.eml) content."})
    if len(raw) > MAX_HTTP_BODY_BYTES:
        return _http_response(413, {"error": "Email too large (500 KB limit)."})

    try:
        submission = email.message_from_bytes(raw, policy=policy.default)
    except Exception:
        return _http_response(400, {"error": "Could not parse the upload as an email message."})

    # A minimal sanity check that this is actually an email and not random text:
    # require at least one of the headers every real message carries.
    if not (submission.get("From") or submission.get("Subject") or submission.get("Received")):
        return _http_response(400, {"error": "That doesn't look like an email. Upload the original .eml file."})

    # Wrap the pipeline so an unexpected error returns structured JSON with
    # CORS headers instead of Lambda's bare 502 (which has no CORS headers,
    # so the browser surfaces it as an opaque network error).
    try:
        target = extract_target_email(submission) or submission
        parsed = parse_email(target)
        enrichment = enrich(parsed)
        verdict = analyze_with_claude(parsed, enrichment)
    except Exception:
        logger.exception("http_pipeline_error")
        return _http_response(500, {"error": "Analysis failed unexpectedly. Please try again later."})

    log_verdict(parsed, enrichment, verdict, message_id=f"http-{int(time.time())}", source="http")

    # Web-path history is keyed to the source IP - the closest thing to a
    # stable submitter identity a browser upload has. None when disabled.
    history = get_and_record_history(source_ip, parsed["from_domain"], verdict.get("verdict"))

    return _http_response(200, {
        "verdict": verdict.get("verdict", "unknown"),
        "confidence": verdict.get("confidence", 0),
        "summary": verdict.get("summary", ""),
        "indicators": verdict.get("indicators", []),
        "recommendation": verdict.get("recommendation", ""),
        "model": verdict.get("model", PRIMARY_MODEL),
        "escalated": verdict.get("escalated", False),
        "history": history,
        "analyzed": {
            "from": parsed["from_addr"],
            "subject": parsed["subject"],
            "url_count": len(parsed["urls"]),
            "attachment_count": len(parsed.get("attachments") or []),
            "spf": enrichment["spf"],
            "dkim": enrichment["dkim"],
            "dmarc": enrichment["dmarc"],
        },
    })


def verify_turnstile(event, source_ip):
    """Server-side Cloudflare Turnstile verification for the web path.

    Enabled by setting TURNSTILE_SECRET_KEY. The frontend widget produces a
    single-use token which the page sends in the X-Turnstile-Token header;
    this function validates it against Cloudflare's siteverify endpoint.

    Returns {"ok": bool, "reason": str}.

    Failure semantics:
    - Turnstile disabled (no secret configured): always ok. The SES path is
      never gated - CAPTCHA only makes sense for browsers.
    - Token missing or Cloudflare says invalid: NOT ok -> caller returns 403.
    - The siteverify call itself errors (timeout, Cloudflare outage): fail
      OPEN, consistent with every other external dependency in this pipeline.
      The IP rate limiter still backstops abuse, and a Cloudflare blip should
      not take the analyzer down. Logged loudly either way.
    """
    secret = os.environ.get("TURNSTILE_SECRET_KEY")
    if not secret:
        return {"ok": True, "reason": "disabled"}

    # Function URL events lowercase all header names
    headers = event.get("headers") or {}
    token = (headers.get("x-turnstile-token") or "").strip()
    if not token:
        return {"ok": False, "reason": "missing_token"}
    if len(token) > 2048:  # Turnstile tokens are well under this; cap hostile input
        return {"ok": False, "reason": "oversized_token"}

    try:
        resp = http.request(
            "POST",
            TURNSTILE_VERIFY_URL,
            fields={"secret": secret, "response": token, "remoteip": source_ip},
        )
        if resp.status != 200:
            logger.error("turnstile_verify_http_error status=%s - failing open", resp.status)
            return {"ok": True, "reason": "verify_unavailable_fail_open"}
        data = json.loads(resp.data.decode())
        if data.get("success"):
            return {"ok": True, "reason": "verified"}
        return {"ok": False, "reason": ",".join(data.get("error-codes") or ["invalid"])}
    except Exception as e:
        logger.error("turnstile_verify_error: %s - failing open", e)
        return {"ok": True, "reason": "verify_error_fail_open"}


def _http_response(status, payload):
    headers = {
        "Access-Control-Allow-Origin": os.environ.get("ALLOWED_ORIGIN", "*"),
        "Access-Control-Allow-Methods": "POST, OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type, X-Turnstile-Token",
        "Access-Control-Max-Age": "86400",
    }
    if payload is None:
        return {"statusCode": status, "headers": headers, "body": ""}
    headers["Content-Type"] = "application/json"
    return {"statusCode": status, "headers": headers, "body": json.dumps(payload)}


# ---------------------------------------------------------------------------
# Input filters
# ---------------------------------------------------------------------------

def is_loop_or_bounce(sender, submission):
    """Detect submissions we shouldn't analyze: our own replies, bounces,
    and auto-responders. Prevents reply storms.

    Checks (in order of reliability):
    1. Sender matches our own FROM_ADDRESS or domain (catches our own replies)
    2. True bounce/system sender patterns (mailer-daemon, postmaster, bounces)
    3. RFC 3834 Auto-Submitted header (legitimate auto-responders set this)
    4. Precedence header set to bulk/junk/list (bulk mail markers)

    Intentionally does NOT block "no-reply@" / "noreply@" / "donotreply@" -
    those are extremely common legitimate transactional sender patterns
    (banks, SaaS, airlines). Blocking them prevents the analyzer from ever
    seeing the very emails users most often want analyzed.
    """
    sender_lower = (sender or "").lower()

    # Catch our own replies and any address on our own domain
    from_address = os.environ.get("FROM_ADDRESS", "").lower()
    if from_address:
        if sender_lower == from_address:
            return True
        if "@" in from_address:
            our_domain = from_address.split("@")[-1]
            if sender_lower.endswith(f"@{our_domain}"):
                return True

    # True bounce/system sender patterns only. noreply variants are NOT
    # included here - see docstring.
    for pattern in ("mailer-daemon@", "postmaster@", "bounces@", "bounce@"):
        if pattern in sender_lower:
            return True

    # RFC 3834: legitimate auto-responders mark themselves with this header
    auto_submitted = submission.get("Auto-Submitted", "").lower()
    if auto_submitted and auto_submitted != "no":
        return True

    # Bulk/automated mail markers
    precedence = submission.get("Precedence", "").lower()
    if precedence in ("bulk", "junk", "list", "auto_reply"):
        return True

    return False


def check_rate_limit(rate_key):
    """Returns True if the key is under the hourly limit, False if it should be dropped.

    rate_key is a namespaced identifier: "sender#user@example.com" for the SES
    path, "ip#1.2.3.4" for the HTTP path. Namespacing keeps the two spaces from
    ever colliding in the shared table.

    Uses a single atomic DynamoDB UpdateItem with an ADD counter, keyed by
    rate_key + fixed hourly bucket. TTL on the item auto-expires old windows,
    so there's no separate reset logic to maintain.

    Fails open (allows the email through) if DynamoDB itself errors, so a
    transient AWS issue never silently blocks legitimate mail - but it logs
    loudly when that happens so it shows up in CloudWatch.
    """
    now = int(time.time())
    hour_bucket = now // RATE_LIMIT_WINDOW_SECONDS
    pk = f"{rate_key}#{hour_bucket}"
    expires_at = now + RATE_LIMIT_WINDOW_SECONDS + 60

    try:
        response = rate_limit_table.update_item(
            Key={"pk": pk},
            UpdateExpression="ADD request_count :incr SET expires_at = if_not_exists(expires_at, :ttl)",
            ExpressionAttributeValues={":incr": 1, ":ttl": expires_at},
            ReturnValues="UPDATED_NEW",
        )
        current_count = response["Attributes"]["request_count"]
        return current_count <= RATE_LIMIT_PER_HOUR
    except Exception as e:
        logger.error("rate_limit_check_failed key=%s error=%s", rate_key, e)
        return True


# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------

def _safe_get_content(part):
    """Extract text from a message part without letting a hostile or broken
    charset kill the pipeline.

    part.get_content() raises LookupError on charsets Python doesn't know
    (e.g. charset="x-unknown-999"), which an attacker can set at will in a
    submitted email. Fall back to decoding the raw payload with
    errors="replace" - a few mangled characters beat a failed analysis.
    """
    try:
        return part.get_content()
    except Exception:
        try:
            raw = part.get_payload(decode=True) or b""
            return raw.decode("utf-8", errors="replace")
        except Exception:
            return ""


def extract_target_email(msg):
    """If user forwarded as a .eml attachment, return that message instead."""
    for part in msg.walk():
        if part.get_content_type() == "message/rfc822":
            payload = part.get_payload()
            if isinstance(payload, list) and payload:
                return payload[0]
        filename = part.get_filename() or ""
        if filename.lower().endswith(".eml"):
            # get_payload(decode=True) returns None for malformed attachments;
            # message_from_bytes(None) would raise, and this input is
            # attacker-controlled. Skip the broken part instead of crashing.
            payload = part.get_payload(decode=True)
            if not payload:
                logger.warning("eml_attachment_payload_empty filename=%s", filename)
                continue
            try:
                return email.message_from_bytes(payload, policy=policy.default)
            except Exception as e:
                logger.warning("eml_attachment_parse_failed: %s", e)
                continue
    return None


def extract_attachments(msg):
    """Collect metadata + SHA-256 for real attachments on the analyzed message.

    Only parts that present as attachments count: an explicit attachment
    content-disposition or a filename. The inline text/html bodies and
    message/rfc822 forward wrappers are the *message*, not attachments, and
    are skipped. Capped at ATTACHMENT_MAX_PARTS parts, and anything over
    ATTACHMENT_MAX_BYTES is recorded but not hashed (hashing a hostile 100 MB
    blob inside a Lambda time/memory budget is its own denial of service).

    Everything here is defensive: this input is attacker-controlled, so any
    part that fails to decode is recorded with what we know and skipped.
    """
    attachments = []
    try:
        for part in msg.walk():
            if len(attachments) >= ATTACHMENT_MAX_PARTS:
                break
            ct = part.get_content_type()
            if part.is_multipart() or ct == "message/rfc822":
                continue
            filename = part.get_filename() or ""
            disposition = (part.get_content_disposition() or "").lower()
            if disposition != "attachment" and not filename:
                continue  # inline body part, not an attachment

            entry = {
                "filename": filename[:200],
                "content_type": ct,
                "size": None,
                "sha256": None,
                "ext": os.path.splitext(filename.lower())[1] if filename else "",
            }
            try:
                payload = part.get_payload(decode=True)
                if payload:
                    entry["size"] = len(payload)
                    if len(payload) <= ATTACHMENT_MAX_BYTES:
                        entry["sha256"] = hashlib.sha256(payload).hexdigest()
            except Exception as e:
                logger.warning("attachment_decode_failed filename=%s: %s", filename, e)
            attachments.append(entry)
    except Exception as e:
        logger.warning("attachment_walk_failed: %s", e)
    return attachments


def parse_email(msg):
    """Pull the fields that actually matter for phishing analysis."""
    from_name, from_addr = parseaddr(msg.get("From", ""))
    _, return_path = parseaddr(msg.get("Return-Path", ""))
    _, reply_to = parseaddr(msg.get("Reply-To", ""))

    auth_results = msg.get("Authentication-Results", "")

    body = ""
    html_body = ""
    if msg.is_multipart():
        for part in msg.walk():
            ct = part.get_content_type()
            if ct == "text/plain" and not body:
                body = _safe_get_content(part)
            elif ct == "text/html" and not html_body:
                html_body = _safe_get_content(part)
    else:
        ct = msg.get_content_type()
        if ct == "text/plain":
            body = _safe_get_content(msg)
        elif ct == "text/html":
            html_body = _safe_get_content(msg)

    # If we only have HTML, derive a text version for the prompt
    if not body and html_body:
        body = re.sub(r"<[^>]+>", " ", html_body)

    body = (body or "").strip()[:8000]
    html_body = (html_body or "").strip()[:50000]

    # Pull URLs from both the text body and HTML hrefs. HTML-only emails
    # (most marketing mail, lots of phishing kits) hide their real targets
    # in <a href="..."> tags that the text-body regex never sees.
    # dict.fromkeys dedupes while preserving first-seen order, so the [:20]
    # cap and the "first 3 get reputation-checked" cap are deterministic -
    # a set would let insertion-order randomness decide which URLs survive.
    found = URL_RE.findall(body)
    if html_body:
        try:
            soup = BeautifulSoup(html_body, "html.parser")
            for a in soup.find_all("a", href=True):
                href = (a.get("href") or "").strip()
                if href.startswith(("http://", "https://")):
                    found.append(href)
        except Exception as e:
            logger.warning("html_url_extraction_failed: %s", e)
    urls = list(dict.fromkeys(found))[:20]

    return {
        "from_name": from_name,
        "from_addr": from_addr,
        "from_domain": from_addr.split("@")[-1].lower() if "@" in from_addr else "",
        "return_path": return_path,
        "reply_to": reply_to,
        "subject": msg.get("Subject", ""),
        "auth_results": auth_results,
        "received_chain": msg.get_all("Received", [])[:5],
        "body": body,
        "html_body": html_body,
        "urls": urls,
        "attachments": extract_attachments(msg),
    }


# ---------------------------------------------------------------------------
# Deterministic enrichment
# ---------------------------------------------------------------------------

def extract_link_mismatches(html_body):
    """Find <a> tags where anchor text resembles a domain but href points elsewhere.

    Classic phishing pattern: <a href="http://evil.example/login">paypal.com</a>
    Legitimate marketing email almost never does this; phishing kits do it constantly.
    Only flag when anchor text actually looks like a domain (contains a dot, no spaces).
    """
    if not html_body:
        return []
    try:
        soup = BeautifulSoup(html_body, "html.parser")
    except Exception:
        return []

    mismatches = []
    for a in soup.find_all("a", href=True):
        href = (a.get("href") or "").strip()
        if not href.startswith(("http://", "https://")):
            continue

        anchor_text = a.get_text().strip()
        # Plain anchors like "Click here" or "Login" don't qualify - too noisy.
        # Only interested when the visible text itself looks like a hostname.
        if not anchor_text or " " in anchor_text or "." not in anchor_text:
            continue

        href_host = (urlparse(href).hostname or "").lower()
        if not href_host:
            continue

        # Normalize the anchor text to compare against the actual href hostname
        anchor_host = anchor_text.lower()
        for prefix in ("https://", "http://"):
            if anchor_host.startswith(prefix):
                anchor_host = anchor_host[len(prefix):]
        anchor_host = anchor_host.split("/")[0]

        if anchor_host and anchor_host != href_host:
            mismatches.append({
                "anchor_text": anchor_text[:200],
                "actual_host": href_host,
                "severity": "HIGH",
            })

    return mismatches


# Digit -> letter substitutions phishers actually use. '1' is ambiguous
# (both 'l' and 'i'), so it's handled separately with both variants.
_LEET_UNAMBIGUOUS = str.maketrans({
    "0": "o", "3": "e", "4": "a", "5": "s", "7": "t", "8": "b", "9": "g", "2": "z",
})


def _leet_candidates(domain):
    """Expand a domain's digit substitutions into plausible letter-only forms.

    'paypa1.com' -> {'paypal.com', 'paypai.com'}; 'micr0soft.com' ->
    {'microsoft.com'}. '1' expands to both 'l' and 'i' variants (all-l and
    all-i, which covers real-world abuse without a combinatorial blowup).
    Returns an empty set when the domain contains no digits - no point
    comparing a digit-free domain against itself.
    """
    if not any(ch.isdigit() for ch in domain):
        return set()
    base = domain.translate(_LEET_UNAMBIGUOUS)
    return {base.replace("1", "l"), base.replace("1", "i")}


def detect_leet_lookalike(from_domain):
    """ASCII digit-swap lookalikes (paypa1.com, micr0soft.com).

    Complements the Unicode confusables check below: digit/letter pairs like
    1/l and 0/o are NOT Unicode confusables, so confusable_homoglyphs never
    catches them (a documented limitation until now). Deterministic and
    dependency-free: normalize digits to letters and compare against the
    watched-brand list. Exact brand matches never reach this function -
    detect_lookalike_domain returns early for those.
    """
    for candidate in _leet_candidates(from_domain):
        if candidate != from_domain and candidate in WATCHED_BRANDS:
            return {"suspect": from_domain, "resembles": candidate, "method": "leet"}
    return None


def detect_lookalike_domain(from_domain):
    """Check if from_domain is a lookalike of a watched brand.

    Two detectors, cheapest first:
    1. Leet/digit substitution ('paypa1.com', 'micr0soft.com') - pure ASCII
       swaps that Unicode confusables data does not cover.
    2. Unicode homoglyphs/confusables (Cyrillic 'а' for Latin 'a', etc.)
       via confusable_homoglyphs.

    Exact matches against the watched brand list return None - those are
    the real thing.
    """
    if not from_domain:
        return None
    if from_domain in WATCHED_BRANDS:
        return None  # exact match, legitimate

    leet = detect_leet_lookalike(from_domain)
    if leet:
        return leet

    for brand in WATCHED_BRANDS:
        try:
            if confusables.is_confusable(from_domain, greedy=True, preferred_aliases=[brand]):
                return {"suspect": from_domain, "resembles": brand, "method": "unicode"}
        except Exception:
            continue
    return None


# ---------------------------------------------------------------------------
# URL reputation (VirusTotal / urlscan.io / PhishTank)
# ---------------------------------------------------------------------------

def _reputation_cache_get(url):
    """24h DynamoDB cache for reputation results. Shares the rate-limit table
    (it's just a pk + TTL key-value store). Fail-open: cache errors mean a
    fresh lookup, never a dropped signal."""
    pk = f"urlrep#{hashlib.sha256(url.encode()).hexdigest()[:32]}"
    try:
        item = rate_limit_table.get_item(Key={"pk": pk}).get("Item")
        if item and "result" in item:
            return json.loads(item["result"])
    except Exception as e:
        logger.warning("reputation_cache_get_failed: %s", e)
    return None


def _reputation_cache_put(url, result):
    pk = f"urlrep#{hashlib.sha256(url.encode()).hexdigest()[:32]}"
    try:
        rate_limit_table.put_item(Item={
            "pk": pk,
            "result": json.dumps(result),
            "expires_at": int(time.time()) + REPUTATION_CACHE_TTL,
        })
    except Exception as e:
        logger.warning("reputation_cache_put_failed: %s", e)


def _check_virustotal(url):
    """VirusTotal v3 URL report. Returns dict or None if unavailable/unknown.

    Uses the report-lookup endpoint (not submission), so it only sees URLs
    VT has already scanned - fine for reputation purposes, and it means one
    GET instead of a submit-then-poll cycle that would blow the latency budget.
    """
    api_key = os.environ.get("VIRUSTOTAL_API_KEY")
    if not api_key:
        return None
    url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
    try:
        resp = http.request(
            "GET",
            f"https://www.virustotal.com/api/v3/urls/{url_id}",
            headers={
                "x-apikey": api_key,
                "User-Agent": "phish-analyzer/1.0 (+https://fredsprivacy.com)",
            },
        )
        if resp.status == 404:
            return {"service": "virustotal", "known": False}
        if resp.status != 200:
            logger.warning("virustotal_lookup_failed status=%s", resp.status)
            return None
        stats = (json.loads(resp.data.decode())
                 .get("data", {}).get("attributes", {})
                 .get("last_analysis_stats", {}))
        malicious = int(stats.get("malicious", 0))
        suspicious = int(stats.get("suspicious", 0))
        return {
            "service": "virustotal",
            "known": True,
            "malicious_votes": malicious,
            "suspicious_votes": suspicious,
            "flagged": malicious > 0 or suspicious > 1,
        }
    except Exception as e:
        logger.warning("virustotal_lookup_error: %s", e)
        return None


def _check_urlscan(url):
    """urlscan.io search for prior malicious verdicts on the URL's domain.

    Uses the search API against completed public scans rather than submitting
    a new scan - a live scan takes ~30s to finish, which doesn't fit the
    verdict latency budget. Domain-level signal, not URL-level, so treat as
    supporting evidence rather than proof.

    NOTE: the free API tier does not allow server-side filtering on
    "verdicts.malicious" (returns 403 "Your current plan does not allow you
    to search field 'verdicts.malicious'"). So we pull back recent public
    scans for the domain unfiltered and inspect each result's "tags" field
    client-side instead - urlscan tags scans it considers malicious with
    "phishing" or "malicious"; "possiblethreat" is weaker/community-flagged
    and treated as supporting-only rather than a hard flag.
    """
    api_key = os.environ.get("URLSCAN_API_KEY")
    if not api_key:
        return None
    host = (urlparse(url).hostname or "").lower()
    if not host:
        return None
    try:
        query = urlencode({"q": f'page.domain:"{host}"', "size": 5})
        resp = http.request(
            "GET",
            f"https://urlscan.io/api/v1/search/?{query}",
            headers={
                "API-Key": api_key,
                "User-Agent": "phish-analyzer/1.0 (+https://fredsprivacy.com)",
            },
        )
        if resp.status != 200:
            logger.warning("urlscan_lookup_failed status=%s", resp.status)
            return None
        data = json.loads(resp.data.decode())
        entries = data.get("results", [])

        strong_tags = {"phishing", "malicious"}
        weak_tags = {"possiblethreat"}
        strong_hits = 0
        weak_hits = 0
        for entry in entries:
            tags = {t.lower() for t in (entry.get("task", {}).get("tags") or [])}
            if tags & strong_tags:
                strong_hits += 1
            elif tags & weak_tags:
                weak_hits += 1

        return {
            "service": "urlscan",
            "domain": host,
            "scans_checked": len(entries),
            "malicious_tag_count": strong_hits,
            "possible_threat_count": weak_hits,
            "flagged": strong_hits > 0,
        }
    except Exception as e:
        logger.warning("urlscan_lookup_error: %s", e)
        return None


def _check_phishtank(url):
    """PhishTank verified-phish database lookup. Keyless works at low volume;
    an app key raises rate limits. Only positive matches matter here -
    absence from PhishTank proves nothing."""
    if os.environ.get("PHISHTANK_ENABLED", "false").lower() != "true":
        return None
    fields = {"url": url, "format": "json"}
    app_key = os.environ.get("PHISHTANK_APP_KEY")
    if app_key:
        fields["app_key"] = app_key
    try:
        resp = http.request(
            "POST",
            "https://checkurl.phishtank.com/checkurl/",
            fields=fields,
            headers={"User-Agent": "phishtank/phish-analyzer"},
        )
        if resp.status != 200:
            logger.warning("phishtank_lookup_failed status=%s", resp.status)
            return None
        results = json.loads(resp.data.decode()).get("results", {})
        in_db = bool(results.get("in_database"))
        verified = bool(results.get("verified")) and bool(results.get("valid"))
        return {
            "service": "phishtank",
            "in_database": in_db,
            "verified_phish": verified,
            "flagged": verified,
        }
    except Exception as e:
        logger.warning("phishtank_lookup_error: %s", e)
        return None


def _check_virustotal_filehash(sha256):
    """VirusTotal v3 file report by SHA-256. Returns dict or None.

    Report lookup only - the file itself is NEVER uploaded anywhere. Hash
    lookups leak nothing about the content (a hash is not reversible), which
    matters for a tool that handles other people's email attachments.
    """
    api_key = os.environ.get("VIRUSTOTAL_API_KEY")
    if not api_key:
        return None
    try:
        resp = http.request(
            "GET",
            f"https://www.virustotal.com/api/v3/files/{sha256}",
            headers={
                "x-apikey": api_key,
                "User-Agent": "phish-analyzer/1.0 (+https://fredsprivacy.com)",
            },
        )
        if resp.status == 404:
            return {"service": "virustotal", "known": False, "flagged": False}
        if resp.status != 200:
            logger.warning("virustotal_filehash_failed status=%s", resp.status)
            return None
        stats = (json.loads(resp.data.decode())
                 .get("data", {}).get("attributes", {})
                 .get("last_analysis_stats", {}))
        malicious = int(stats.get("malicious", 0))
        suspicious = int(stats.get("suspicious", 0))
        return {
            "service": "virustotal",
            "known": True,
            "malicious_votes": malicious,
            "suspicious_votes": suspicious,
            "flagged": malicious > 0 or suspicious > 1,
        }
    except Exception as e:
        logger.warning("virustotal_filehash_error: %s", e)
        return None


def check_attachment_reputation(attachments):
    """Hash-based threat-intel on attachments, same asymmetric-evidence rules
    as URLs: a hit is strong evidence, absence proves nothing (novel malware
    is never in the database). Cached in DynamoDB under a 'filehash#' prefix
    (namespaced away from 'urlrep#' and the rate-limit keys), 24h TTL,
    fully fail-open.
    """
    if not os.environ.get("VIRUSTOTAL_API_KEY"):
        return []
    results = []
    for att in attachments:
        sha256 = att.get("sha256")
        if not sha256:
            continue
        cache_key = f"filehash#{sha256}"
        cached = None
        try:
            item = rate_limit_table.get_item(Key={"pk": cache_key}).get("Item")
            if item and "result" in item:
                cached = json.loads(item["result"])
        except Exception as e:
            logger.warning("filehash_cache_get_failed: %s", e)
        if cached is not None:
            results.append(cached)
            continue

        check = _check_virustotal_filehash(sha256)
        entry = {
            "filename": att.get("filename"),
            "sha256": sha256,
            "checks": [check] if check else [],
            "flagged": bool(check and check.get("flagged")),
        }
        try:
            rate_limit_table.put_item(Item={
                "pk": cache_key,
                "result": json.dumps(entry),
                "expires_at": int(time.time()) + REPUTATION_CACHE_TTL,
            })
        except Exception as e:
            logger.warning("filehash_cache_put_failed: %s", e)
        results.append(entry)
    return results


def check_url_reputation(urls):
    """Run configured reputation services against up to REPUTATION_MAX_URLS.

    Returns a list of per-URL result dicts. Everything here fails open:
    a dead API, a missing key, or a timeout just means fewer signals, never
    a failed analysis. Results are cached in DynamoDB for 24h because the
    same phishing URL tends to arrive in waves, and VirusTotal's free tier
    allows only 4 requests/minute.
    """
    services_configured = (
        bool(os.environ.get("VIRUSTOTAL_API_KEY"))
        or bool(os.environ.get("URLSCAN_API_KEY"))
        or os.environ.get("PHISHTANK_ENABLED", "false").lower() == "true"
    )
    if not services_configured or not urls:
        return []

    results = []
    for url in urls[:REPUTATION_MAX_URLS]:
        cached = _reputation_cache_get(url)
        if cached is not None:
            results.append(cached)
            continue

        checks = [c for c in (
            _check_phishtank(url),
            _check_virustotal(url),
            _check_urlscan(url),
        ) if c is not None]

        entry = {
            "url": url,
            "checks": checks,
            "flagged": any(c.get("flagged") for c in checks),
        }
        _reputation_cache_put(url, entry)
        results.append(entry)

    return results


def enrich(parsed):
    """Deterministic signals - cheap, reliable, weight heavily in the verdict.

    Key insight: DMARC is the authoritative legitimacy signal because it
    represents the sender's own DNS policy. A DMARC pass means EITHER SPF
    OR DKIM aligned and passed - so DKIM failure alone (when DMARC still
    passes) is common for legitimate mail forwarding, HR platforms, and
    email service providers. We weight DMARC heavily and avoid penalizing
    DKIM-fail-with-DMARC-pass patterns.
    """
    signals = []
    ar = parsed["auth_results"].lower()

    # Parse the individual auth results
    dmarc_pass = "dmarc=pass" in ar
    dmarc_fail = "dmarc=fail" in ar
    # Word boundary (\b) so "p=reject" never false-matches inside "sp=reject"
    # (the SUBDOMAIN policy Gmail reports alongside p=, e.g. "p=NONE sp=REJECT").
    # Without it, a domain with p=none sp=reject would be misread as REJECT.
    dmarc_reject_policy = bool(re.search(r"\bp=reject", ar))
    dmarc_quarantine_policy = bool(re.search(r"\bp=quarantine", ar))
    spf_pass = "spf=pass" in ar
    spf_fail = "spf=fail" in ar or "spf=softfail" in ar
    dkim_pass = "dkim=pass" in ar
    dkim_fail = "dkim=fail" in ar

    # Strong legitimacy signals first
    if dmarc_pass and dmarc_reject_policy:
        signals.append(("auth", "DMARC passed with REJECT policy - strong legitimacy signal (sender's own DNS policy validates this message)"))
    elif dmarc_pass and dmarc_quarantine_policy:
        signals.append(("auth", "DMARC passed with QUARANTINE policy - good legitimacy signal"))
    elif dmarc_pass:
        signals.append(("auth", "DMARC passed (basic legitimacy)"))

    if spf_pass and dkim_pass:
        signals.append(("auth", "Both SPF and DKIM passed cryptographically"))
    elif spf_pass:
        signals.append(("auth", "SPF passed"))

    # Concerning signals - but contextualized by whether DMARC offsets them
    if dmarc_fail:
        signals.append(("auth", "DMARC FAILED - serious spoofing concern (sender's own DNS policy rejected this message)"))

    if dkim_fail and dmarc_pass:
        # Common with mail forwarding, HR platforms, ESPs - note but don't alarm
        signals.append(("info", "DKIM signature failed but DMARC still passed (common with mail forwarding or third-party senders like SuccessFactors, Salesforce; not inherently suspicious)"))
    elif dkim_fail and not dmarc_pass:
        signals.append(("auth", "DKIM failed without DMARC pass to offset - possible spoofing"))

    if spf_fail and dmarc_pass:
        signals.append(("info", "SPF failed but DMARC passed via DKIM alignment"))
    elif spf_fail and not dmarc_pass:
        signals.append(("auth", "SPF failed without DMARC pass to offset - possible spoofing"))

    if parsed["reply_to"] and parsed["reply_to"].lower() != parsed["from_addr"].lower():
        from_d = parsed["from_addr"].split("@")[-1].lower()
        reply_d = parsed["reply_to"].split("@")[-1].lower()
        if from_d != reply_d:
            signals.append(("mismatch", f"Reply-To domain ({reply_d}) differs from From ({from_d})"))

    if parsed["return_path"] and "@" in parsed["return_path"]:
        rp_d = parsed["return_path"].split("@")[-1].lower()
        if parsed["from_domain"] and rp_d != parsed["from_domain"]:
            signals.append(("mismatch", f"Return-Path domain ({rp_d}) differs from From ({parsed['from_domain']})"))

    suspicious_urls = []
    for url in parsed["urls"]:
        try:
            host = urlparse(url).netloc.lower()
            if host in {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd"}:
                suspicious_urls.append(f"{url} (shortener)")
            elif re.match(r"^\d+\.\d+\.\d+\.\d+", host):
                suspicious_urls.append(f"{url} (IP literal)")
        except Exception:
            pass

    if suspicious_urls:
        signals.append(("urls", f"Suspicious URLs: {', '.join(suspicious_urls[:5])}"))

    # Lookalike domain detection: sender domain that visually resembles a watched brand
    lookalike = detect_lookalike_domain(parsed["from_domain"])
    if lookalike:
        signals.append(("lookalike",
                        f"Sender domain '{lookalike['suspect']}' visually resembles watched brand '{lookalike['resembles']}' - possible homoglyph impersonation"))

    # Link mismatch detection: anchor text resembling a brand domain but href elsewhere
    link_mismatches = extract_link_mismatches(parsed.get("html_body", ""))
    if link_mismatches:
        examples = "; ".join(
            f"'{m['anchor_text']}' -> {m['actual_host']}" for m in link_mismatches[:3]
        )
        signals.append(("link_mismatch",
                        f"Anchor text resembles a domain but link goes elsewhere: {examples}"))

    # URL reputation: threat-intel lookups against VirusTotal / urlscan / PhishTank.
    # Positive hits are strong evidence; absence of hits proves nothing (new
    # phishing URLs won't be in any database yet), and the prompt says so.
    url_reputation = check_url_reputation(parsed["urls"])
    flagged_urls = [r for r in url_reputation if r.get("flagged")]
    if flagged_urls:
        details = []
        for r in flagged_urls[:3]:
            services = ", ".join(sorted({c["service"] for c in r.get("checks", []) if c.get("flagged")}))
            details.append(f"{r['url']} (flagged by {services})")
        signals.append(("reputation",
                        f"URL flagged by threat intelligence: {'; '.join(details)}"))
    elif url_reputation:
        signals.append(("info",
                        "URL reputation checked against configured threat-intel services; no known-malicious hits (note: new phishing URLs are often not yet in any database)"))

    # Attachment signals: risky extensions are deterministic evidence on
    # their own; hash reputation follows the same asymmetric rule as URLs.
    attachments = parsed.get("attachments") or []
    risky_atts = [a for a in attachments if a.get("ext") in RISKY_ATTACHMENT_EXTS]
    if risky_atts:
        names = ", ".join(a.get("filename") or a.get("content_type") or "?" for a in risky_atts[:3])
        signals.append(("attachment",
                        f"Attachment with executable/script/smuggling-prone file type: {names} - "
                        f"legitimate senders rarely attach these; treat as high risk"))

    attachment_reputation = check_attachment_reputation(attachments)
    flagged_atts = [r for r in attachment_reputation if r.get("flagged")]
    if flagged_atts:
        names = ", ".join(r.get("filename") or r.get("sha256", "")[:12] for r in flagged_atts[:3])
        signals.append(("reputation",
                        f"Attachment hash flagged by VirusTotal as known malware: {names}"))
    elif attachment_reputation:
        signals.append(("info",
                        "Attachment hashes checked against VirusTotal; no known-malware hits "
                        "(note: novel malware is often not yet in any database)"))

    return {
        "signals": signals,
        "dmarc": "pass" if dmarc_pass else ("fail" if dmarc_fail else "none"),
        "dkim": "pass" if dkim_pass else ("fail" if dkim_fail else "none"),
        "spf":  "pass" if spf_pass  else ("fail" if spf_fail  else "none"),
        "dmarc_policy": "reject" if dmarc_reject_policy else ("quarantine" if dmarc_quarantine_policy else "none"),
        "link_mismatches": link_mismatches,
        "lookalike": lookalike,
        "url_reputation": url_reputation,
        "url_rep_flagged_count": len(flagged_urls),
        "attachments": attachments,
        "attachment_reputation": attachment_reputation,
        "attachment_rep_flagged_count": len(flagged_atts),
        "risky_attachment_count": len(risky_atts),
    }


# ---------------------------------------------------------------------------
# Per-submitter history ("you've asked about this sender before")
# ---------------------------------------------------------------------------

def get_and_record_history(submitter, sender_domain, verdict_tier):
    """Track how often a given submitter has asked about a given sender domain.

    Returns {"prior_lookups": int, "last_verdict": str|None} - the state
    BEFORE this submission - or None when disabled/inapplicable, so callers
    can distinguish "first time" (prior_lookups=0) from "feature off".

    Privacy: the submitter identity (email address on the SES path, source IP
    on the web path) is stored only as a truncated SHA-256, never verbatim -
    consistent with the verdict-log policy of never persisting full sender
    addresses. Keys live in the shared DynamoDB table under a 'history#'
    prefix with a 90-day TTL.

    Simple get-then-put rather than an atomic counter: this is a courtesy
    note, not a security control, and a lost increment under a race is
    harmless. Fully fail-open - a DynamoDB error means no history note,
    never a failed analysis.
    """
    if os.environ.get("ENABLE_SUBMITTER_HISTORY", "false").lower() != "true":
        return None
    if not submitter or not sender_domain:
        return None

    submitter_hash = hashlib.sha256(submitter.strip().lower().encode()).hexdigest()[:32]
    pk = f"history#{submitter_hash}#{sender_domain}"

    prior = {"prior_lookups": 0, "last_verdict": None}
    try:
        item = rate_limit_table.get_item(Key={"pk": pk}).get("Item")
        if item:
            try:
                prior["prior_lookups"] = int(item.get("lookup_count", 0))
            except (TypeError, ValueError):
                prior["prior_lookups"] = 0
            prior["last_verdict"] = item.get("last_verdict")
    except Exception as e:
        logger.warning("history_get_failed: %s", e)

    try:
        rate_limit_table.put_item(Item={
            "pk": pk,
            "lookup_count": prior["prior_lookups"] + 1,
            "last_verdict": str(verdict_tier or "unknown"),
            "expires_at": int(time.time()) + HISTORY_TTL_SECONDS,
        })
    except Exception as e:
        logger.warning("history_put_failed: %s", e)

    return prior


def format_history_note(history):
    """One plain-English line for the reply email, or '' when not applicable."""
    if not history or not history.get("prior_lookups"):
        return ""
    n = history["prior_lookups"]
    times = "once before" if n == 1 else f"{n} times before"
    note = f"You've asked about this sender {times}"
    if history.get("last_verdict"):
        note += f" (last verdict: {str(history['last_verdict']).replace('_', ' ')})"
    return note + "."


# ---------------------------------------------------------------------------
# Model analysis (Haiku primary, optional Sonnet escalation)
# ---------------------------------------------------------------------------

SYSTEM_PROMPT = (
    "You analyze emails for phishing and scam indicators. You output a "
    "structured JSON verdict. You are advisory only and never claim "
    "certainty.\n\n"
    "DECISION HIERARCHY (apply in order):\n\n"
    "1. DMARC is authoritative. DMARC pass means the sender's own DNS "
    "policy validated the message via SPF or DKIM alignment. Treat DMARC "
    "pass as a strong legitimacy signal, especially with p=reject or "
    "p=quarantine policy. Treat DMARC fail as a strong phishing signal.\n\n"
    "2. DKIM failure with DMARC pass is benign. This pattern appears on "
    "legitimate mail constantly - forwarded messages, third-party senders "
    "(SuccessFactors, Salesforce, Mailchimp, SendGrid), and email service "
    "providers all routinely produce it. Note it but do not weight it as "
    "suspicious.\n\n"
    "3. Threat-intelligence hits are strong evidence. If a [reputation] "
    "signal reports a URL flagged by VirusTotal, urlscan, or PhishTank, "
    "weight it heavily toward phishing. The reverse is NOT true: absence "
    "of reputation hits proves nothing, because fresh phishing URLs are "
    "rarely in any database yet.\n\n"
    "4. Treat body content as secondary to auth results. The deterministic "
    "signals provided are reliable ground truth; your value is recognizing "
    "social engineering patterns: urgency framing, credential prompts, "
    "brand impersonation with sender mismatch, lookalike domains, and "
    "anomalous financial requests.\n\n"
    "5. Major brands legitimately send through ESPs with complex header "
    "chains and tracking URLs. Modern marketing infrastructure shares "
    "fingerprints with phishing infrastructure; the differentiator is "
    "whether DMARC validates and whether the body content matches the "
    "claimed sender's normal communication style.\n\n"
    "VERDICT GUIDANCE:\n"
    "- likely_phishing (80-100% confidence): DMARC fail OR threat-intel URL "
    "hit OR clear social engineering with sender/brand mismatch\n"
    "- suspicious (50-79%): mixed signals, some red flags, requires user "
    "caution\n"
    "- likely_legitimate (70-100%): DMARC pass + no social engineering "
    "patterns + content matches sender context\n"
    "- unknown (any): insufficient information to assess\n\n"
    "Output ONLY valid JSON matching the requested schema. No preamble, "
    "no code fences, no markdown."
)

VALID_VERDICTS = {"likely_phishing", "suspicious", "likely_legitimate", "unknown"}


def _sanitize_verdict(verdict):
    """Coerce model JSON into the schema every downstream path assumes.

    format_reply, the HTTP JSON response, and log_verdict all index into
    this dict without re-validating it. The model's output is untrusted:
    confidence can come back as a string, a float, or out of range, and
    indicators can contain non-dict entries. Clamp and coerce here so a
    sloppy model response degrades the verdict instead of crashing the
    reply path after the API call has already been paid for.
    """
    try:
        conf = int(verdict.get("confidence", 0))
    except (TypeError, ValueError):
        conf = 0
    verdict["confidence"] = max(0, min(100, conf))

    indicators = verdict.get("indicators")
    if not isinstance(indicators, list):
        indicators = []
    clean = []
    for item in indicators:
        if not isinstance(item, dict):
            continue
        clean.append({
            "signal": str(item.get("signal") or "")[:200],
            "detail": str(item.get("detail") or "")[:500],
            "severity": str(item.get("severity") or "med")[:10],
        })
    verdict["indicators"] = clean

    verdict["summary"] = str(verdict.get("summary") or "")
    verdict["recommendation"] = str(verdict.get("recommendation") or "")
    return verdict


def _call_model(model, prompt):
    """One model call, returns a parsed verdict dict or None on unparseable output."""
    resp = claude.messages.create(
        model=model,
        max_tokens=1024,
        system=SYSTEM_PROMPT,
        messages=[{"role": "user", "content": prompt}],
    )
    text = resp.content[0].text.strip()
    text = re.sub(r"^```(?:json)?\s*|\s*```$", "", text)
    try:
        verdict = json.loads(text)
    except json.JSONDecodeError:
        return None
    if not isinstance(verdict, dict) or verdict.get("verdict") not in VALID_VERDICTS:
        return None
    return _sanitize_verdict(verdict)


def _should_escalate(verdict):
    """Escalate Haiku -> Sonnet when the cheap model isn't sure.

    Triggers on a 'suspicious' verdict (the explicitly-unsure tier) or any
    definite verdict below the confidence threshold. Never escalates
    'unknown' - that means the input was insufficient, and a bigger model
    can't fix missing information.
    """
    if os.environ.get("ENABLE_MODEL_ESCALATION", "false").lower() != "true":
        return False
    v = verdict.get("verdict")
    if v == "suspicious":
        return True
    try:
        threshold = int(os.environ.get("ESCALATION_CONFIDENCE", "70"))
    except ValueError:
        threshold = 70
    if v in ("likely_phishing", "likely_legitimate"):
        try:
            return int(verdict.get("confidence", 0)) < threshold
        except (TypeError, ValueError):
            return True
    return False


def analyze_with_claude(parsed, enrichment):
    """Ask Claude for a structured verdict. Haiku first; optionally escalate
    low-confidence verdicts to Sonnet when ENABLE_MODEL_ESCALATION is on."""
    prompt = build_prompt(parsed, enrichment)

    unparseable = {
        "verdict": "unknown",
        "confidence": 0,
        "summary": "Analyzer could not produce a structured verdict.",
        "indicators": [],
        "recommendation": "Treat with caution; do not click links or reply.",
    }

    try:
        verdict = _call_model(PRIMARY_MODEL, prompt)
        if verdict is None:
            unparseable["model"] = PRIMARY_MODEL
            return unparseable
        verdict["model"] = PRIMARY_MODEL
        verdict["escalated"] = False

        if _should_escalate(verdict):
            logger.info("Escalating to %s (haiku verdict=%s confidence=%s)",
                        ESCALATION_MODEL, verdict.get("verdict"), verdict.get("confidence"))
            try:
                escalated = _call_model(ESCALATION_MODEL, prompt)
                if escalated is not None:
                    escalated["model"] = ESCALATION_MODEL
                    escalated["escalated"] = True
                    return escalated
                # Sonnet output unparseable - keep the Haiku verdict
                logger.warning("Escalation produced unparseable output; keeping Haiku verdict")
            except Exception:
                # Escalation is best-effort. If Sonnet errors, the Haiku
                # verdict is still a real verdict - use it.
                logger.exception("Escalation call failed; keeping Haiku verdict")

        return verdict

    except anthropic.APIStatusError as e:
        # Spend cap hit, rate limit, or other API status error
        logger.error("Anthropic API error: status=%s message=%s", e.status_code, e.message)
        return {
            "verdict": "unknown",
            "confidence": 0,
            "summary": "Analysis service is temporarily unavailable. Please try again later.",
            "indicators": [],
            "recommendation": "Treat with caution. Do not click links or reply until you can verify the sender through another channel.",
            "model": PRIMARY_MODEL,
        }
    except Exception:
        # Catch-all for unexpected errors so the user still gets a reply.
        # logger.exception captures the traceback automatically.
        logger.exception("Unexpected error in analyze_with_claude")
        return {
            "verdict": "unknown",
            "confidence": 0,
            "summary": "An unexpected error occurred during analysis.",
            "indicators": [],
            "recommendation": "Treat with caution. Do not click links or reply until you can verify the sender through another channel.",
            "model": PRIMARY_MODEL,
        }


def build_prompt(parsed, enrichment):
    deterministic = "\n".join(f"  - [{kind}] {note}" for kind, note in enrichment["signals"]) \
        or "  (none detected)"

    return f"""Analyze this email for phishing/scam indicators.

DETERMINISTIC SIGNALS (already extracted, treat as ground truth):
{deterministic}

HEADERS:
  From:         {parsed['from_name']} <{parsed['from_addr']}>
  Reply-To:     {parsed['reply_to'] or '(none)'}
  Return-Path:  {parsed['return_path'] or '(none)'}
  Subject:      {parsed['subject']}
  Auth-Results: {parsed['auth_results'][:500] or '(none)'}

URLS FOUND IN BODY:
{chr(10).join('  - ' + u for u in parsed['urls']) or '  (none)'}

ATTACHMENTS:
{chr(10).join('  - ' + (a.get('filename') or '(unnamed)') + ' (' + (a.get('content_type') or '?') + ', ' + str(a.get('size') or '?') + ' bytes)' for a in (parsed.get('attachments') or [])) or '  (none)'}

BODY (truncated to 8000 chars):
\"\"\"
{parsed['body']}
\"\"\"

Return JSON with this exact shape:
{{
  "verdict": "likely_phishing" | "suspicious" | "likely_legitimate" | "unknown",
  "confidence": 0-100,
  "summary": "1-2 sentence plain-English explanation for a non-technical user",
  "indicators": [
    {{"signal": "short label", "detail": "why it matters", "severity": "low|med|high"}}
  ],
  "recommendation": "concrete action for the user"
}}

Do not include any text outside the JSON object."""


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------

def format_reply(verdict, parsed, enrichment, history=None):
    v = verdict.get("verdict", "unknown")
    conf = verdict.get("confidence", 0)

    emoji = {"likely_phishing": "[!]", "suspicious": "[?]",
             "likely_legitimate": "[OK]", "unknown": "[?]"}.get(v, "[?]")

    indicators_txt = "\n".join(
        f"  - [{i.get('severity','?').upper()}] {i.get('signal','')}: {i.get('detail','')}"
        for i in verdict.get("indicators", [])
    ) or "  (none reported)"

    history_line = format_history_note(history)
    history_block = f"\n{history_line}\n" if history_line else ""

    return f"""{emoji} Verdict: {v.replace('_',' ').upper()}  ({conf}% confidence)

{verdict.get('summary','')}
{history_block}
What we looked at:
  Analyzed sender: {parsed['from_addr']}
  Subject: {parsed['subject']}
  URLs found: {len(parsed['urls'])}
  Attachments: {len(parsed.get('attachments') or [])}

Indicators:
{indicators_txt}

Recommendation:
  {verdict.get('recommendation','When in doubt, do not click links or reply.')}

---
This is an automated advisory analysis from Fred's Privacy, not a guarantee.
Authoritative threats should be reported to your IT/security team. Do not
forward emails containing personal data you wouldn't want analyzed by an AI.
"""


def log_verdict(parsed, enrichment, verdict, message_id, source="ses"):
    """One structured JSON log line per verdict for CloudWatch Insights and
    downstream Wazuh ingestion.

    The line is emitted as "PHISH_VERDICT {json}". Lambda prefixes every
    logger line with "[INFO]\\t<timestamp>\\t<request-id>\\t", so the JSON is
    never at the start of the CloudWatch message. The fixed marker gives the
    Wazuh decoder (and any other log shipper) a stable anchor: prematch on
    "PHISH_VERDICT " and JSON-decode everything after it.
    """
    try:
        return_path_domain = ""
        rp = parsed.get("return_path") or ""
        if "@" in rp:
            return_path_domain = rp.split("@")[-1].lower()

        lookalike = enrichment.get("lookalike") or {}

        payload = {
            "event": "verdict",
            "ts": int(time.time()),
            "source": source,
            "message_id": message_id,
            "sender_domain": parsed.get("from_domain"),
            "return_path_domain": return_path_domain,
            "spf": enrichment.get("spf"),
            "dkim": enrichment.get("dkim"),
            "dmarc": enrichment.get("dmarc"),
            "dmarc_policy": enrichment.get("dmarc_policy"),
            "url_count": len(parsed.get("urls") or []),
            "link_mismatch_count": len(enrichment.get("link_mismatches") or []),
            "lookalike_brand": lookalike.get("resembles"),
            "lookalike_method": lookalike.get("method"),
            "url_rep_flagged_count": enrichment.get("url_rep_flagged_count", 0),
            "attachment_count": len(parsed.get("attachments") or []),
            "risky_attachment_count": enrichment.get("risky_attachment_count", 0),
            "attachment_rep_flagged_count": enrichment.get("attachment_rep_flagged_count", 0),
            "model": verdict.get("model"),
            "escalated": verdict.get("escalated", False),
            "verdict": verdict.get("verdict"),
            "confidence": verdict.get("confidence"),
            "indicator_count": len(verdict.get("indicators") or []),
        }
        logger.info("PHISH_VERDICT %s", json.dumps(payload, default=str))
    except Exception as e:
        logger.warning("log_verdict_failed: %s", e)


def send_reply(to, subject, body):
    ses.send_email(
        Source=os.environ["FROM_ADDRESS"],
        Destination={"ToAddresses": [to]},
        Message={
            "Subject": {"Data": subject[:200]},
            "Body": {"Text": {"Data": body}},
        },
    )
