# Contributing to Ledgerline

## Ground rules

- This is a design-first project. Structural changes start as discussion in `docs/VISION.md` before code.
- All contributions use the Developer Certificate of Origin: sign off your commits (`git commit -s`).
- Apache 2.0. By contributing you agree your work is licensed under the same terms.

## Workflow

1. Open an issue describing the change.
2. Keep PRs small and focused. One concern per PR.
3. `go build ./...` and `go vet ./...` must pass.
4. Write in plain, short sentences. No AI slop in docs or comments.

## What we need most

Right now: the Phase 1 wedge. MCP gateway hardening, the approval UX for held calls, PTY co-capture from Backseat, and the replay viewer. See `docs/VISION.md` section 12.
