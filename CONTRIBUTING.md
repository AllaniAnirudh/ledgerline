# Contributing to Ledgerline

## Ground rules

- This is a design-first project. Structural changes start as discussion in `docs/VISION.md` before code.
- All contributions use the Developer Certificate of Origin: sign off your commits (`git commit -s`).
- Apache 2.0. By contributing you agree your work is licensed under the same terms.

## Workflow

1. Open an issue describing the change.
2. Keep PRs small and focused. One concern per PR.
3. `go build ./...`, `go vet ./...`, and `go test ./...` must pass. CI runs them on every push and pull request.
4. Write in plain, short sentences. No AI slop in docs or comments.

## What we need most

Right now: hardening the shipped Phase 1 wedge (the MCP gateway, the approval UX, PTY co-capture, and the replay viewer), and the Phase 2 design work: chain signing and anchoring, redaction at capture, and SIEM export. See `docs/VISION.md` section 12.
