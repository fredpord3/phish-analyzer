"""
Phishing Email Analyzer - Lambda handler (MVP)

Flow: SES receives mail -> drops .eml in S3 -> triggers this Lambda ->
parse -> enrich -> ask Claude -> reply via SES.

Env vars expected:
  ANTHROPIC_API_KEY   - your Claude API key
  BUCKET_NAME         - S3 bucket where SES drops raw emails
  FROM_ADDRESS        - verified SES sender, e.g. "no-reply@yourdomain.com"
  REGION              - AWS region for SES (e.g. "us-east-1")
"""

import os
import re
import json
import time
import email
import logging
import boto3
from email import policy
from email.utils import parseaddr
from urllib.parse import urlparse
import anthropic
from bs4 import BeautifulSoup
from confusable_homoglyphs import confusables

logger = logging.getLogger()
logger.setLevel(logging.INFO)

s3 = boto3.client("s3")
ses = boto3.client("ses", region_name=os.environ.get("REGION", "us-east-1"))
claude = anthropic.Anthropic(api_key=os.environ["ANTHROPIC_API_KEY"])

URL_RE = re.compile(r"https?://[^\s<>\"']+", re.IGNORECASE)

# Brands worth checking for lookalike/homoglyph impersonation.
# Tune to your threat model - add the brands your users actually interact with.
WATCHED_BRANDS = [
    "microsoft.com", "google.com", "apple.com", "amazon.com",
    "paypal.com", "chase.com", "bankofamerica.com", "wellsfargo.com",
    "docusign.com", "dropbox.com",
]


def lambda_handler(event, context):
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

    target = extract_target_email(submission) or submission

    parsed = parse_email(target)
    enrichment = enrich(parsed)
    verdict = analyze_with_claude(parsed, enrichment)

    log_verdict(parsed, enrichment, verdict, message_id)

    reply_body = format_reply(verdict, parsed, enrichment)
    send_reply(to=sender, subject=f"Re: {submission.get('Subject', 'phishing check')}",
               body=reply_body)

    return {"statusCode": 200, "messageId": message_id}


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


def extract_target_email(msg):
    """If user forwarded as a .eml attachment, return that message instead."""
    for part in msg.walk():
        if part.get_content_type() == "message/rfc822":
            payload = part.get_payload()
            if isinstance(payload, list) and payload:
                return payload[0]
        filename = part.get_filename() or ""
        if filename.lower().endswith(".eml"):
            return email.message_from_bytes(part.get_payload(decode=True), policy=policy.default)
    return None


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
                body = part.get_content()
            elif ct == "text/html" and not html_body:
                html_body = part.get_content()
    else:
        ct = msg.get_content_type()
        if ct == "text/plain":
            body = msg.get_content()
        elif ct == "text/html":
            html_body = msg.get_content()

    # If we only have HTML, derive a text version for the prompt
    if not body and html_body:
        body = re.sub(r"<[^>]+>", " ", html_body)

    body = (body or "").strip()[:8000]
    html_body = (html_body or "").strip()[:50000]

    # Pull URLs from both the text body and HTML hrefs. HTML-only emails
    # (most marketing mail, lots of phishing kits) hide their real targets
    # in <a href="..."> tags that the text-body regex never sees.
    urls = set(URL_RE.findall(body))
    if html_body:
        try:
            soup = BeautifulSoup(html_body, "html.parser")
            for a in soup.find_all("a", href=True):
                href = (a.get("href") or "").strip()
                if href.startswith(("http://", "https://")):
                    urls.add(href)
        except Exception as e:
            logger.warning("html_url_extraction_failed: %s", e)
    urls = list(urls)[:20]

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
    }


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


def detect_lookalike_domain(from_domain):
    """Check if from_domain is a homoglyph/confusable of a watched brand.

    Catches Unicode lookalike attacks (e.g. 'paypa1.com', 'micr0soft.com',
    or Cyrillic 'а' substituted for Latin 'a'). Exact matches against the
    watched brand list are returned as None - those are the real thing.
    """
    if not from_domain:
        return None
    for brand in WATCHED_BRANDS:
        if from_domain == brand:
            return None  # exact match, legitimate
        try:
            if confusables.is_confusable(from_domain, greedy=True, preferred_aliases=[brand]):
                return {"suspect": from_domain, "resembles": brand}
        except Exception:
            continue
    return None


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
    dmarc_reject_policy = "p=reject" in ar
    dmarc_quarantine_policy = "p=quarantine" in ar
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

    return {
        "signals": signals,
        "dmarc": "pass" if dmarc_pass else ("fail" if dmarc_fail else "none"),
        "dkim": "pass" if dkim_pass else ("fail" if dkim_fail else "none"),
        "spf":  "pass" if spf_pass  else ("fail" if spf_fail  else "none"),
        "dmarc_policy": "reject" if dmarc_reject_policy else ("quarantine" if dmarc_quarantine_policy else "none"),
        "link_mismatches": link_mismatches,
        "lookalike": lookalike,
    }


def analyze_with_claude(parsed, enrichment):
    """Ask Claude for a structured verdict. Force JSON output."""
    prompt = build_prompt(parsed, enrichment)

    try:
        resp = claude.messages.create(
            model="claude-haiku-4-5",
            max_tokens=1024,
            system=(
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
                "3. Treat body content as secondary to auth results. The deterministic "
                "signals provided are reliable ground truth; your value is recognizing "
                "social engineering patterns: urgency framing, credential prompts, "
                "brand impersonation with sender mismatch, lookalike domains, and "
                "anomalous financial requests.\n\n"
                "4. Major brands legitimately send through ESPs with complex header "
                "chains and tracking URLs. Modern marketing infrastructure shares "
                "fingerprints with phishing infrastructure; the differentiator is "
                "whether DMARC validates and whether the body content matches the "
                "claimed sender's normal communication style.\n\n"
                "VERDICT GUIDANCE:\n"
                "- likely_phishing (80-100% confidence): DMARC fail OR clear social "
                "engineering with sender/brand mismatch\n"
                "- suspicious (50-79%): mixed signals, some red flags, requires user "
                "caution\n"
                "- likely_legitimate (70-100%): DMARC pass + no social engineering "
                "patterns + content matches sender context\n"
                "- unknown (any): insufficient information to assess\n\n"
                "Output ONLY valid JSON matching the requested schema. No preamble, "
                "no code fences, no markdown."
            ),
            messages=[{"role": "user", "content": prompt}],
        )

        text = resp.content[0].text.strip()
        text = re.sub(r"^```(?:json)?\s*|\s*```$", "", text)

        try:
            return json.loads(text)
        except json.JSONDecodeError:
            return {
                "verdict": "unknown",
                "confidence": 0,
                "summary": "Analyzer could not produce a structured verdict.",
                "indicators": [],
                "recommendation": "Treat with caution; do not click links or reply.",
            }

    except anthropic.APIStatusError as e:
        # Spend cap hit, rate limit, or other API status error
        logger.error("Anthropic API error: status=%s message=%s", e.status_code, e.message)
        return {
            "verdict": "unknown",
            "confidence": 0,
            "summary": "Analysis service is temporarily unavailable. Please try again later.",
            "indicators": [],
            "recommendation": "Treat with caution. Do not click links or reply until you can verify the sender through another channel.",
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


def format_reply(verdict, parsed, enrichment):
    v = verdict.get("verdict", "unknown")
    conf = verdict.get("confidence", 0)

    emoji = {"likely_phishing": "[!]", "suspicious": "[?]",
             "likely_legitimate": "[OK]", "unknown": "[?]"}.get(v, "[?]")

    indicators_txt = "\n".join(
        f"  - [{i.get('severity','?').upper()}] {i.get('signal','')}: {i.get('detail','')}"
        for i in verdict.get("indicators", [])
    ) or "  (none reported)"

    return f"""{emoji} Verdict: {v.replace('_',' ').upper()}  ({conf}% confidence)

{verdict.get('summary','')}

What we looked at:
  Analyzed sender: {parsed['from_addr']}
  Subject: {parsed['subject']}
  URLs found: {len(parsed['urls'])}

Indicators:
{indicators_txt}

Recommendation:
  {verdict.get('recommendation','When in doubt, do not click links or reply.')}

---
This is an automated advisory analysis from Fred's Privacy, not a guarantee.
Authoritative threats should be reported to your IT/security team. Do not
forward emails containing personal data you wouldn't want analyzed by an AI.
"""


def log_verdict(parsed, enrichment, verdict, message_id):
    """One structured JSON log line per verdict for CloudWatch Insights."""
    try:
        return_path_domain = ""
        rp = parsed.get("return_path") or ""
        if "@" in rp:
            return_path_domain = rp.split("@")[-1].lower()

        lookalike = enrichment.get("lookalike") or {}

        payload = {
            "event": "verdict",
            "ts": int(time.time()),
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
            "verdict": verdict.get("verdict"),
            "confidence": verdict.get("confidence"),
            "indicator_count": len(verdict.get("indicators") or []),
        }
        logger.info(json.dumps(payload, default=str))
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
