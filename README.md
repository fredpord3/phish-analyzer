# Phish Analyzer

A serverless phishing email analyzer that combines deterministic header analysis
with LLM-based content review.

## How it works

1. User forwards a suspicious email (as `.eml` attachment) to a check address
2. Amazon SES receives the message and drops the raw email into S3
3. SES invokes a Lambda function with the message metadata
4. Lambda parses the email, extracts deterministic signals (SPF/DKIM/DMARC,
   sender mismatches, suspicious URLs), and passes everything to Claude
5. Claude returns a structured JSON verdict with confidence score, indicators,
   and recommendation
6. Lambda formats the verdict into an email reply and sends it back via SES

## Architecture

Internet -> SES (inbound) -> S3 -> Lambda -> Claude API -> SES (outbound) -> User

## Tech stack

- AWS Lambda (Python 3.13) for serverless compute
- Amazon SES for inbound mail receiving and outbound replies
- Amazon S3 for raw email storage
- Anthropic Claude (Haiku 4.5) for content analysis
- Cloudflare DNS for MX records and DKIM CNAMEs

## Why hybrid (Python + LLM)?

- Python handles **facts** — what the headers literally say, what domains
  literally match. Cheap, deterministic, never wrong about ground truth.
- Claude handles **judgment** — what the body content means, whether
  framing matches known social engineering patterns, what a reasonable
  user should do.

Either layer alone produces weaker output. The split lets each handle
what it's best at.

## Security and cost protections

- IAM scoped to least privilege (deny policy blocks EC2/Bedrock/SageMaker)
- Anthropic API spend capped at $10/month (hard ceiling)
- AWS budget alerts at $0.01 and $5
- All credentials in Lambda environment variables, never in source

## Status

MVP complete. Known issues:
- Over-weights DKIM failures; doesn't sufficiently credit DMARC pass with
  REJECT policy. Causes false positives on legitimate corporate HR /
  marketing emails sent through ESPs (SuccessFactors, Salesforce, etc.)
- No rate limiting (recipient address kept private to prevent abuse)

## Roadmap

- Tune DKIM/DMARC weighting based on DMARC alignment
- Rate limiting via DynamoDB per-sender counter
- Web frontend for non-technical users
- URL reputation enrichment (VirusTotal, URLScan.io)
- Lookalike domain detection
- Integration with SIEM (Wazuh) for trend analysis

## License

MIT
