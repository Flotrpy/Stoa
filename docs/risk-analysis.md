# Risk-analysis tools

## Phishing model card

- Model: `stoa-phishing-2026.09.1`
- Pipeline: scikit-learn `DictVectorizer` plus logistic regression with a fixed random seed.
- Provenance: synthetic, hand-reviewed defensive URL and page-fact fixtures; no customer or user
  data. The fixtures cover safe documentation/portal pages and deliberately suspicious IP,
  Punycode, redirect, cross-origin form, and resource-ratio examples.
- Output: a calibrated model probability blended with a bounded heuristic score. The UI always
  shows the concrete heuristics alongside the score.
- Thresholds: low below 0.40, medium from 0.40, high from 0.70.
- Evaluation: deterministic held-out behavior tests cover representative safe and suspicious
  fixtures. This small synthetic set is not evidence of population-level accuracy.
- Limitations: no automatic WHOIS/domain-age lookup; redirects, certificate facts, page titles,
  brand context, form destinations, and content counts must be supplied by an authorized caller.
  The result is triage guidance, never a verdict. Forms and credentials are never submitted.

## Offline password lab

The lab accepts only local hexadecimal MD5, SHA-256, and SHA-512 demonstration hashes. These fast
digests are included for education and legacy-risk discovery; they are not recommended password
storage formats. Candidate dictionaries, rule expansions, hashes, and any recovered candidate stay
in process on the endpoint and are never placed in API schemas, telemetry, reports, or logs.

Audits enforce attempt and wall-clock limits, support cancellation/progress callbacks, cap generated
candidate length and alphabet size, and provide remediation toward unique passphrases with Argon2id,
scrypt, or bcrypt. There is no network target, login client, credential capture, or online mode.
