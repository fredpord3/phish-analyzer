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
import email
import boto3
from email import policy
from email.utils import parseaddr
from urllib.parse import urlparse
import anthropic

s3 = boto3.client("s3")
ses = boto3.client("ses", region_name=os.environ.get("REGION", "us-east-1"))
claude = anthropic.Anthropic(api_key=os.environ["ANTHROPIC_API_KEY"])

URL_RE = re.compile(r"https?://[^\s<>\"']+", re.IGNORECASE)


def lambda_handler(event, context):
    # SES action triggers Lambda with the S3 object key for the raw email.
    record = event["Records"][0]["ses"]
    message_id = record["mail"]["messageId"]
    sender = record["mail"]["source"]

    raw = s3.get_object(Bucket=os.environ["BUCKET_NAME"], Key=message_id)["Body"].read()
    submission = email.message_from_bytes(raw, policy=policy.default)

    target = extract_target_email(submission) or submission

    parsed = parse_email(target)
    enrichment = enrich(parsed)
    verdict = analyze_with_claude(parsed, enrichment)

    reply_body = format_reply(verdict, parsed, enrichment)
    send_reply(to=sender, subject=f"Re: {submission.get('Subject', 'phishing check')}",
               body=reply_body)

    return {"statusCode": 200, "messageId": message_id}


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
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() == "text/plain":
                body = part.get_content()
                break
        if not body:
            for part in msg.walk():
                if part.get_content_type() == "text/html":
                    html = part.get_content()
                    body = re.sub(r"<[^>]+>", " ", html)
                    break
    else:
        body = msg.get_content() if msg.get_content_maintype() == "text" else ""

    body = (body or "").strip()[:8000]

    urls = list(set(URL_RE.findall(body)))

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
        "urls": urls[:20],
    }


def enrich(parsed):
    """Deterministic signals - cheap, reliable, weight heavily in the verdict."""
    signals = []
    ar = parsed["auth_results"].lower()

    if "spf=fail" in ar or "spf=softfail" in ar:
        signals.append(("auth", "SPF failed or softfailed"))
    if "dkim=fail" in ar:
        signals.append(("auth", "DKIM signature failed"))
    if "dmarc=fail" in ar:
        signals.append(("auth", "DMARC failed"))
    if "spf=pass" in ar and "dkim=pass" in ar and "dmarc=pass" in ar:
        signals.append(("auth", "All auth checks passed"))

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

    return {"signals": signals}


def analyze_with_claude(parsed, enrichment):
    """Ask Claude for a structured verdict. Force JSON output."""
    prompt = build_prompt(parsed, enrichment)

    resp = claude.messages.create(
        model="claude-haiku-4-5",
        max_tokens=1024,
        system=(
            "You are a phishing/scam email analyst. You evaluate emails and return a "
            "JSON verdict. You are advisory only - never claim certainty. Weight "
            "authentication results (SPF/DKIM/DMARC) and header mismatches heavily; "
            "weight body content moderately. Output ONLY valid JSON, no preamble, no "
            "code fences."
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

Be conservative. Prefer "suspicious" over "likely_legitimate" when in doubt.
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


def send_reply(to, subject, body):
    ses.send_email(
        Source=os.environ["FROM_ADDRESS"],
        Destination={"ToAddresses": [to]},
        Message={
            "Subject": {"Data": subject[:200]},
            "Body": {"Text": {"Data": body}},
        },
    )
