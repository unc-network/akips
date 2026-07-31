# AI Assistance in this Project

This document records how AI tooling is used in the `akips` project, what it
has and has not touched, and why an AI co-author appears in the GitHub
contributor list.

## Position

This project is **human led**. The maintainer sets the direction, decides what
gets changed, and reviews everything before it is committed. AI is used the way
a maintainer might use a knowledgeable assistant: to review existing code, to
research and cross-check facts, to draft changes to supporting files, and to
propose options. It is not used to autonomously design or evolve the library.

## Most of this project predates any AI involvement

- The first commit landed on **2023-09-20**.
- AI assistance began on **2026-07-31**, nearly three years later.
- Every release from **v0.1.4 through v0.5.1** (September 2023 to November 2025)
  was written without AI involvement of any kind.

Every public method in the client, every response parser, every regular
expression, and every unit test was written by hand before any AI touched this
repository.

## What AI has actually changed

As of this writing, AI-assisted commits have not altered the behavior of the
library. The complete diff to the `akips/` package since AI involvement began is
a single line: the `__version__` string, updated as part of a version bump.

```console
$ git diff 646ba4a..HEAD -- akips/
-__version__ = "0.5.1"
+__version__ = "0.6.0.dev2"
```

The work has been confined to the scaffolding around the library:

| Area | Examples |
| --- | --- |
| Continuous integration | Workflow cleanups, automatic tagging on merge to main, a guard preventing pre-release versions reaching production PyPI, moving actions onto supported Node runtimes, reshaping the test matrix |
| Dependencies | Updating the lock file to clear security advisories, raising the Python floor to 3.10, replacing the unmaintained pylama with ruff |
| Documentation | Backfilling `CHANGELOG.md` from git history, updating the release process notes and contributing guide |
| Packaging metadata | Version bumps, trove classifiers |

## How the collaboration works

The maintainer poses a problem or asks for a review. The AI investigates,
reports what it finds, and proposes options with trade-offs. The maintainer
decides. Decisions made by the maintainer during this work have included
staying on 0.6.0 rather than declaring 1.0.0, dropping Python 3.9 support,
replacing the linter, and adding the pre-release publishing guard.

Where a proposal was wrong or incomplete, it was corrected before landing.
Claims of fact are checked against primary sources rather than asserted from
memory: advisories are confirmed with `pip-audit` against the actual lock file,
action runtimes are read from the actions' own manifests, and shell logic
embedded in workflows is extracted and executed locally before being committed.

Every AI-assisted change passes the same gates as any other change: ruff, black,
and the full pytest matrix.

## Why Claude appears in the contributor list

AI-assisted commits carry a trailer identifying the model:

```
Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
```

GitHub reads `Co-Authored-By` trailers and lists the co-author as a repository
contributor, which is why an AI account appears there. This is **disclosure, not
authorship**. The maintainer is the author of every commit and is accountable
for its content. The trailer is present so that AI involvement is auditable
rather than invisible:

```console
# every commit with AI involvement
$ git log --grep="Co-Authored-By: Claude"
```

At present 13 of 172 commits carry this trailer.

## Working rules

- Changes to the library source in `akips/` are reviewed line by line before
  being committed, and the bar for accepting them is higher than for tooling
  and documentation.
- AI does not publish releases. Publishing is gated behind CI checks and a
  human merge to `main`.
- Credentials and secrets are never shared with AI tooling.
- Anything an AI asserts about an external system, a version number, or a
  security advisory is verified against that system before it is acted on.

## Questions

If you have concerns about how AI is used here, please open an issue at
<https://github.com/unc-network/akips/issues>.
