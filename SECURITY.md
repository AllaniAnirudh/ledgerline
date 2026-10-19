# Security Policy

## Reporting a vulnerability

Email allanianirudh05@gmail.com with a description of the issue and steps to reproduce it. You will get a reply within 7 days. Do not open a public issue for a suspected vulnerability.

## Scope and honest limitations

Ledgerline is a trust boundary, so its own threat model is stated plainly in `docs/VISION.md` section 4. The current honest limitations:

- v0 holds the signing key and the ledger on the gateway host. Against a compromised gateway host, tamper-evidence does not hold. The gateway is the trust root; protect it accordingly.
- Offline bundles prove self-consistency (the chain is intact), not authenticity (who wrote it). External anchoring is Phase 2.
- The `Hold` decision currently denies with a ledger record. There is no approval UX yet, so nothing held can be approved.
- Redaction at capture is pattern-based and leaky by nature. Treat ledger contents as sensitive.

If you find a gap between what the docs promise and what the code does, that is a security issue. Report it.
