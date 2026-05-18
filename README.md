# depfusion

Dependency-confusion candidate finder. Pulls JS / sourcemap URLs in memory,
extracts npm package references, filters Node builtins / invalid names / path
aliases, and queries the npm registry to classify each name as
**registered** / **claimable** / **unknown**.

Built for large URL lists (hundreds of thousands of targets): results are
**streamed to disk as they are produced**, so an interrupted run
(Ctrl-C / kill / crash) still leaves complete partial output.

## Install

```sh
go install github.com/OctaYus/depfusion@latest
```

## Usage

```sh
depfusion -f urls.txt -o out -workers 40
```

| Flag | Default | Meaning |
|---|---|---|
| `-f` | — | Input file, one URL per line (required) |
| `-o` | — | Output directory (required) |
| `-workers` | `40` | Concurrent workers |
| `-timeout` | `20` | Per-request timeout (seconds) |
| `-insecure` | `true` | Skip TLS verification — handles wildcard / underscore host cert mismatches |
| `-no-probe-map` | `false` | Don't auto-append `.map` to each URL |
| `-no-follow-inline-map` | `false` | Don't follow `//# sourceMappingURL=` pointers |

## Output (`<out>/`)

| File | Contents |
|---|---|
| `claimable.txt` | `name<TAB>url` — clean 404 on npm, **submission candidates** |
| `registered.txt` | `name<TAB>url` — exists on npm |
| `unknown.txt` | `name<TAB>url` — registry check failed, **verify manually** |
| `results.jsonl` | One JSON object per URL (streamed) |
| `scope_report.txt` | Per-scope tally; `<-- HIGH SIGNAL` = scope with only claimable packages |

## What it filters

- Node builtins (`fs`, `path`, `crypto`, `node:fs`, …) — 404 on npm but unclaimable
- Invalid npm names (relative paths, URLs, webpack aliases like `@/components`)
- Scoped packages reduced correctly to `@scope/pkg`

## Caveat

A clean 404 is a *candidate*, not a confirmed takeover. npm sometimes
security-holds previously-unpublished names. Before reporting, verify with
`npm view <name>` and `npm publish --dry-run` on a throwaway package.

Use only against assets you are authorized to test.

## License

MIT
