# Marshalyard

**A safety-first, local-first, reversible file organiser.** Marshal moves files into folders according to rules you write in a TOML file, and it refuses to do anything it cannot prove is safe.

> **Status: pre-alpha, under active development.** The design is frozen and the domain model, configuration validator, planner foundations and an in-memory filesystem are implemented and tested. The command-line interface is **not built yet**, so there is nothing to install or run. See [Roadmap](#roadmap).

[![CI](https://github.com/Hamed-Bahrommani/Marhsalyard-Extended-from-the-CS50p-final-project/actions/workflows/ci.yml/badge.svg)](https://github.com/Hamed-Bahrommani/Marhsalyard-Extended-from-the-CS50p-final-project/actions/workflows/ci.yml)

The Python package, repository and command are named **`marshalyard`**, because `marshal` is already a module in Python's standard library.

## Why

Most file organisers move first and apologise later. Marshal is built around one rule:

> **Whenever Marshal cannot establish that an operation is safe, it refuses the operation and explains why.**

That single principle shapes everything below.

## What it will do

You describe where files should go:

```toml
version = 1

[settings]
roots = ["~/Downloads", "~/Documents/Sorted"]
min_age = "10m"

[[rule]]
name = "invoices-by-year"
source = "~/Downloads"
extensions = ["pdf"]
name_glob = "invoice*"
destination = "~/Documents/Sorted/Invoices/{modified:%Y}"

[[rule]]
name = "images"
source = "~/Downloads"
extensions = ["jpg", "jpeg", "png"]
destination = "~/Documents/Sorted/Images/{ext}"
```

Then, in seven planned commands:

| Command | Purpose |
|---|---|
| `check` | Validate the configuration; report every problem with its location |
| `plan` | Show exactly what would move, and what was left alone and why |
| `apply` | Execute a plan you have reviewed |
| `history` | List past runs |
| `explain` | Say why a particular file was or wasn't planned |
| `undo` | Build a plan that reverses a run |
| `recover` | Reconcile a run that was interrupted |

## Design principles

- **Plans are immutable and reviewable.** A plan has a content-derived id. What you approve is exactly what runs.
- **Only renames.** Marshal never copies, deletes, overwrites or edits file contents. Filenames are preserved; templates only build directories.
- **Never overwrites.** Moves use the operating system's no-replace rename (`renameat2(RENAME_NOREPLACE)` on Linux, `os.rename` on Windows). If no-replace is unavailable it fails closed; there is no fallback to an ordinary rename.
- **Everything is journalled.** Every operation's state is recorded in a local SQLite journal with validated, monotonic transitions.
- **Recovery never touches your files.** After a crash, `recover` only reads the disk and updates the journal. It resolves an interrupted move as done or not-started when the evidence is unambiguous, and flags anything else as unresolved. It never guesses.
- **Undo is a plan, not magic.** Undo generates a normal, reviewable plan. Files you have modified since are left in place and reported.
- **Ambiguity blocks.** A file matching two rules, a hard-linked file, a file still being written, a destination that already exists: each is reported and skipped, never "best-effort" moved.

## Guarantees and non-guarantees

**Verification strength.** Marshal never modifies file contents; it only renames. Before recovery or undo, files up to 64 MiB are verified by SHA-256 plus metadata. Larger files are verified by identity, size and modification time only, which cannot prove the contents are unchanged. Reports state which strength applied.

**Not guaranteed (documented limits):**

1. Only process-level crashes are covered. Power loss, kernel crashes and filesystem corruption are out of scope.
2. A third party changing the source file or a parent directory in the instant between the final check and the rename is not prevented. On Linux, directory-swap windows are closed by file-descriptor-relative walks; swapping the final file name, and (on Windows) the directory-swap window, remain documented residual risks.
3. Fingerprint consistency is best-effort. A modification that preserves identity, size and modification time is undetectable.
4. There is **no automatic rollback** if a later operation fails. Use `undo`.
5. Moves across devices are refused. Empty directories created for a destination are left in place, even after undo.

## Supported platforms

NTFS on Windows; ext4, xfs, btrfs and tmpfs on Linux; Python 3.11 or newer. Network filesystems and cloud-synced folders are **not** covered by any claim. macOS is outside version 1.

## Development

```
python -m pip install -r requirements.txt
python -m pytest -q
```

Continuous integration runs the suite on Windows and Linux, on Python 3.11 and 3.14.

| Path | Contents |
|---|---|
| `docs/SPEC.md` | The frozen v1 specification |
| `marshalyard/` | The package: models, configuration, canonical hashing, transitions, filesystem port and in-memory filesystem |
| `tests/` | Unit and property-style tests |
| `project.py`, `test_project.py` | A thin top-level entry point and its tests |

The specification is the source of truth. If the code and the spec disagree, the spec is amended first, then the code.

## Roadmap

| Milestone | Scope | Status |
|---|---|---|
| M1 | Domain model, TOML configuration and validation, canonical hashing, state transitions | Done |
| M2 | Filesystem port, in-memory fake with fault and race injection, scanner, matching, planner | Done |
| M3 | Real filesystem, fingerprinting, no-replace move strategies, Windows verification | Planned |
| M4 | SQLite journal, executor, preflight, locking | Planned |
| M5 | Recovery and exhaustive fault-injection tests | Planned |
| M6 | Undo | Planned |
| M7 | Command-line interface | Planned |
| M8 | Documentation pass and release | Planned |


## License

MIT. See [LICENSE](LICENSE).