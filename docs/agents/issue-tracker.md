# Issue tracker: GitHub

Issues and specifications for this repository live in GitHub Issues. Use the
`gh` CLI for all issue operations and infer the repository from `git remote`.

## Conventions

- Read: `gh issue view <number> --comments`
- List: `gh issue list` with the appropriate state and label filters
- Create: `gh issue create`
- Comment: `gh issue comment`
- Label: `gh issue edit --add-label` / `--remove-label`
- Close: `gh issue close`

When a skill says to publish something to the issue tracker, create or update
the corresponding GitHub issue.

## Pull requests as a triage surface

**PRs as a request surface: no.**

Pull requests are not included in triage discovery. An explicitly named PR may
still be inspected when requested.
