# Sketch2md release pilot

This pilot proves that RepoLens can generate release notices from policy data and artifact
evidence, then hand those outputs to a product release flow. The commands are written for
Sketch2md, but the pattern applies to any OpenNext-style app that produces a Worker bundle.

## Product repo flow

```bash
npm run build
repolens scan --work-root .repolens/work
repolens resolve --work-root .repolens/work
repolens flag --work-root .repolens/work
repolens shortlist --work-root .repolens/work
repolens report --work-root .repolens/work
repolens release --work-root .repolens/work \
  --artifact .open-next/worker.js \
  --target cloudflare-worker
```

Release outputs land in `.repolens/work/release/`:

- `release.policy.json`
- `release.review.md`
- `release.licenses.json`
- `release.notices.md`
- `release.notices.txt`

Copy `release.notices.md` to `THIRD_PARTY_NOTICES.generated.md` for release review. Keep a
hand-written `THIRD_PARTY_NOTICES.md` as the human overview if the product already has
one. For a public JSON surface, publish only entries the policy marks public:

```bash
jq '[.entries[] | select(.actions.public_notice == "required")]' \
  .repolens/work/release/release.licenses.json \
  > public/legal/third-party-notices.json
```

Do not publish entries whose policy action keeps them bundled/internal only.

## Offline rehearsal

Run this inside RepoLens without the Sketch2md repo:

```bash
python3 scripts/release_pilot_demo.py
```

The command builds a synthetic work root under `/tmp`, runs `repolens release` against a
fake `dist/worker.js`, and prints the five generated artifact paths.

Expected outcomes:

| Fixture class | Expected result |
| --- | --- |
| delivered `CC-BY-4.0` style package | attribution notice generated; gate passes |
| delivered MIT package | bundled notice generated; public notice not required by default |
| `(AFL-2.1 OR BSD-3-Clause)` style package | OR branch resolves through the permissive BSD branch |
| lockfile-only optional LGPL package | monitored in `release.review.md`, not emitted in notices |
| delivered GPL package | blocked in `release.policy.json` |

The artifact scanner only upgrades records to `delivered` on positive bundle or sourcemap
markers. Marker absence is not proof of absence, so unmatched packages remain
`not_scanned`.
