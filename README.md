# Phish Analyzer

Serverless phishing email analyzer. Forward a suspicious email, get back a structured verdict with confidence score, indicators of compromise, and a recommendation in under ten seconds.

Combines deterministic header analysis (SPF, DKIM, DMARC, URL extraction, sender alignment) with LLM-based content review using Claude Haiku 4.5.

## Architecture

```mermaid
flowchart LR
    A[User forwards .eml] --> B[SES Inbound]
    B --> C[S3 raw email]
    B --> D[Lambda - Python 3.13]
    C --> D
    D --> E[Parse + enrich headers]
    E --> F[Claude Haiku 4.5]
    F --> G[Structured JSON verdict]
    G --> H[SES Outbound reply]
    D --> I[CloudWatch verdict logs]
```

## How it works

1. User forwards a suspicious email as a `.eml` attachment to the check address.
2. Amazon SES receives the message and writes the raw RFC 822 source to S3 under the `inbound/` prefix.
3. SES triggers Lambda with message metadata; Lambda pulls the source from S3.
4. Lambda extracts deterministic signals: SPF/DKIM/DMARC results from the Authentication-Results header, From vs Return-Path alignment, Reply-To mismatches, and URLs from both text and HTML parts.
5. Lambda passes parsed content and enriched signals to Claude with a structured prompt that defines a verdict hierarchy and explicitly handles ESP scenarios.
6. Claude returns JSON with a verdict tier, a 0-100 confidence score, indicators of compromise, and a user-facing explanation.
7. Lambda formats the verdict into an email reply and sends it back via SES.

## Tech stack

- AWS Lambda (Python 3.13) for serverless compute
- Amazon SES for inbound mail receiving and outbound replies
- Amazon S3 for raw email storage
- Anthropic Claude (Haiku 4.5) for content analysis
- Cloudflare DNS for MX records and DKIM CNAMEs

## Design decisions

### Why hybrid Python plus LLM?

Python handles facts: what the headers literally say, what domains literally match, whether a URL's hostname differs from its anchor text. Cheap, deterministic, fast.

Claude handles judgment: what the body content means in context, whether framing matches known social engineering patterns (urgency, authority impersonation, payment redirection), what a non-technical user should do next.

Either layer alone produces weaker output. Python alone cannot reason about intent. Claude alone can be talked out of header anomalies by well-crafted prose, or can confidently misread headers it has no business interpreting. Splitting the work lets each layer handle what it is best at.

### Why Haiku, not Sonnet?

Cost per verdict matters when the input surface is open to the internet. Sonnet 4.6 runs roughly 2.8x the cost of Haiku 4.5 even with prompt caching, and output tokens dominate the bill since the JSON response is the bulk of the spend. Testing showed Haiku produces equivalent verdicts on the false-positive cases that drove the largest accuracy gains. Where Haiku was wrong, the fix was in the prompt or the enrichment logic, not the model.

Hybrid routing (Haiku default, Sonnet only on low-confidence verdicts) is on the roadmap if real-world accuracy requires it.

### Why structured verdicts?

The reply email is rendered from a JSON schema, not free-form text. This means:

- The verdict tier is always one of three known values: `likely_phish`, `suspicious`, `likely_legitimate`
- Confidence scores are bounded 0-100
- Indicators are a list, not a paragraph

Free-form output is unparseable at scale. Structured output lets the same verdict feed an email reply, a CloudWatch log entry, a future SIEM ingestion pipeline, and a future dashboard without re-parsing model prose.

## Case studies: false positives and what they taught me

Two real emails that the analyzer initially flagged as suspicious but were legitimate. Each one drove a meaningful architectural change.

### Case 1: JetBlue recruiting email (SAP SuccessFactors)

A legitimate JetBlue recruiting email sent through SAP SuccessFactors was flagged as `suspicious` with DKIM failure cited as the primary indicator of compromise.

**Why the original logic was wrong.** The message had DMARC pass with `p=REJECT`. That is a stronger trust signal than raw DKIM alignment. If a domain owner publishes `p=REJECT`, any non-aligned mail is dropped by receiving servers before it reaches an inbox. The fact that the message arrived at all means it passed alignment downstream of the original SuccessFactors hop. Flagging DKIM failure as HIGH severity in that scenario treats authentication headers as a flat checklist instead of a hierarchy.

**Fix.** Rewrote the enrichment scoring to treat DMARC outcome as the senior signal. DMARC pass with strict policy now downgrades DKIM-failure severity from HIGH to INFO and adds an explicit "legitimate ESP pattern" note for the model. DKIM failure with DMARC fail or no DMARC policy remains HIGH.

**Lesson.** Authentication header signals are not independent. Treating them as a flat checklist produces false positives on most legitimate corporate email, because most corporate email is sent through an ESP.

### Case 2: Sonic.com marketing email (Salesforce Marketing Cloud)

Same pattern. Legitimate marketing email from Sonic, sent through Salesforce Marketing Cloud, with a non-aligned DKIM signature but DMARC pass under the published policy. Initial verdict: `suspicious`.

**Fix.** Same code path as Case 1.

**Lesson.** ESPs are the rule, not the exception, for corporate mail. An analyzer that does not understand the ESP pattern will alarm on most of an enterprise inbox, which is the failure mode that kills user trust faster than missing a real phish.

## Security and cost controls

- IAM scoped to least privilege; deny policy blocks EC2, Bedrock, SageMaker, and other compute services unrelated to the function's purpose
- Anthropic API spend capped at $10 per month with alerts at $6 and $8
- AWS budgets at $0.01 (zero-spend tripwire) and $5 (operational ceiling) with email alerts
- All credentials live in Lambda environment variables; nothing in source
- Loop prevention rejects submissions from the check address itself, RFC 3834 auto-responders, `mailer-daemon` and `postmaster` bounces, and `Precedence: bulk/junk/list` headers
- Errors caught at the API and SES boundaries; a Claude API failure returns a "service temporarily unavailable, treat with caution" reply rather than crashing the function

## Status

MVP complete and deployed. Currently running in SES sandbox (recipient address whitelist) pending rate limiting work before requesting production access.

## Roadmap

**Near term**
- Verdict logging to CloudWatch Insights for trend analysis
- HTML link mismatch detection via BeautifulSoup (anchor text vs href hostname)
- Lookalike domain detection via `confusable_homoglyphs`
- Rate limiting via DynamoDB per-sender counter with TTL

**Medium term**
- SES production access (requires rate limiting first)
- URL reputation enrichment via VirusTotal, URLScan.io, and PhishTank
- Wazuh SIEM integration: CloudWatch Logs to Kinesis Firehose to Wazuh ingestion, with a dashboard for verdict distribution and indicator trends
- Landing page and submission portal at fredsprivacy.com

**Long term**
- Hybrid model routing (Haiku default, Sonnet on low-confidence verdicts)
- Web frontend for drag-and-drop `.eml` uploads

## License

MIT
