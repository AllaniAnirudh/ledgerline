# Contributing to Ledgerline

## Ground rules

- This is a design-first project. Structural changes start as discussion in `docs/VISION.md`. Code comes after discussion.
- All contributions use the Developer Certificate of Origin. Sign off your commits (`git commit -s`).
- Apache 2.0. By contributing, you agree your work uses the same license.

## Workflow

1. Open an issue describing the change.
2. Keep PRs small and focused. One concern per PR.
3. `go build ./...`, `go vet ./...`, and `go test ./...` must pass. CI runs them on every push. CI runs them on every pull request.
4. Write in plain, short sentences. Use ASD-STE100 Simplified Technical English. No AI slop in docs or comments.

## What we need most

Right now, we need two things. First, harden the shipped Phase 1 wedge. The wedge covers the MCP gateway, the approval UX, PTY co-capture, and the replay viewer. Second, do the Phase 2 design work. This covers chain signing and anchoring, redaction at capture, and SIEM export. See `docs/VISION.md` section 12.
