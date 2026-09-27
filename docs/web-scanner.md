# Authorized web security scanner

PR 6 adds a same-origin web scanner for explicitly authorized targets.

## Authorization boundary

1. An administrator approves an endpoint and enables the `web-scanner` module policy.
2. A user selects an active authorization scope whose target covers the start URL.
3. The API rechecks endpoint approval, scope freshness, module allowance, policy caps, target, crawl depth, page limit, request rate, active checks, form submission, and ZAP import.
4. The desktop runs the scan locally and uploads only redacted finding metadata.

Cross-origin redirects, links, and forms are ignored. Query values are redacted before central storage. Response bodies, submitted form bodies, cookie values, and raw page content are not central API fields.

## Checks

- Crawling discovers same-origin links, forms, inputs, headers, cookies, and URL parameters.
- Passive checks report missing HTTPS, HSTS, CSP, content-type sniffing protection, and cookie security attributes.
- Active checks are disabled unless module policy allows them. They use bounded canary probes only: quoted-parameter SQL error indicators, reflected marker indicators, and optional safe form-marker persistence indicators.
- Authentication and session findings are limited to observable behavior such as transport and cookie attributes. Stoá does not claim automatic broken-authentication coverage.

## ZAP integration

The optional ZAP adapter imports existing alert metadata only from a local `127.0.0.1` or `localhost` ZAP API. It does not start spidering, active scanning, authentication attacks, or exploit delivery.

## Reports and fixtures

The UI shows redacted findings and exports server-generated JSON or text reports. Automated tests use a local loopback HTTP fixture with intentional headers, reflection, SQL-error text, and canary persistence. They do not contact public targets.
