# Delivered vs Installed Dependencies

## Problem

RepoLens currently has enough license data to surface risky packages, but it does not make
the package presence state prominent enough. That creates noisy commercial-risk reviews when
a package is present in a lockfile or optional dependency path, but is not installed or
delivered in the actual deployed artifact.

The important distinction is:

- Delivered dependencies must stand out because they are part of what the product ships,
  serves, distributes, or deploys.
- Installed dependencies still matter, but they are a different risk tier when they are
  only present in a build, CI, development, or package-manager install tree.
- Non-installed future-risk dependencies must be mentioned separately. They should not be
  hidden, but they also should not look equivalent to shipped LGPL/GPL code.

This is especially visible for web apps and serverless deployments. A package can appear in a
lockfile as an optional platform dependency and still not be installed on the current host or
included in a Cloudflare Worker, Docker image, desktop app, npm package, or other delivered
artifact.

## Goals

- Make delivered and installed dependency status first-class data in discovery, shortlist,
  and reports.
- Keep delivered dependencies visually and structurally separate from lockfile-only or
  future-risk packages.
- Prevent final documentation from implying that non-delivered optional packages are shipped
  compliance obligations.
- Preserve future-risk visibility so a later platform, feature, or deployment change can
  reopen review.
- Avoid trusting absence unless the relevant deployment artifact was scanned.

## Non-Goals

- Do not provide legal advice or decide LGPL/GPL obligations automatically.
- Do not suppress commercially unfriendly licenses just because they are not currently
  delivered.
- Do not claim a package is not delivered when RepoLens has not scanned the relevant artifact.
- Do not solve every package-manager edge case in the first implementation slice.

## Definitions

Delivered dependency:
  A dependency present in the actual shipped or deployed artifact, such as a Worker bundle,
  container image, desktop package, mobile app, published npm package, static site output, or
  server runtime bundle.

Installed dependency:
  A dependency present in the local, CI, build, or deployment install tree. It may be runtime,
  build-time, development, optional, or transitive, but it is not automatically delivered.

Lockfile-only dependency:
  A dependency present in package-manager metadata, but not installed in the scanned install
  tree and not found in the scanned delivery artifact.

Future-risk dependency:
  A non-delivered package that could become installed or delivered under another platform,
  CPU/libc target, optional feature, dependency version, or deployment configuration.

## Discovery

Discovery should preserve package-manager relation data instead of flattening everything into
one runtime bucket.

For npm-style inputs, RepoLens should keep:

- Direct vs transitive relation.
- `prod`, `dev`, `peer`, `optional`, and `devOptional` state.
- Dependency path, such as `next -> sharp -> @img/sharp-libvips-linux-x64`.
- Platform metadata, including `os`, `cpu`, and `libc` where available.
- Source of the observation: lockfile, package manifest, install tree, SBOM, or artifact scan.
- Target context: Cloudflare Worker, Node server, Docker image, npm package, desktop app, or
  other deployment kind when known.

Discovery must not label a lockfile-only optional package as delivered runtime code. If the
artifact has not been scanned, the state should be `not_scanned`, not `not_delivered`.

## Resolve And Flag

License policy should still classify LGPL, GPL, AGPL, unknown, and other risky licenses, but
the review severity should be ordered by presence:

1. Delivered: action required.
2. Installed runtime: review before release.
3. Installed build/dev: review with context.
4. Lockfile-only or optional future risk: monitor and reopen if presence changes.

This keeps copyleft code in a delivered artifact prominent while avoiding false equivalence
with platform packages that are not installed or shipped.

Recommended fields:

```json
{
  "presence": {
    "install_state": "installed | not_installed | lockfile_only | unknown",
    "delivery_state": "delivered | not_delivered | not_scanned | unknown",
    "delivery_artifact": {
      "kind": "cloudflare-worker",
      "path": ".open-next/worker.js",
      "hash": "..."
    },
    "relation": "direct | transitive | peer | optional | dev | devOptional",
    "path": ["next", "sharp", "@img/sharp-libvips-linux-x64"],
    "platform_match": "target | host | cross_platform | no | unknown",
    "reopen_on_delivery_change": true
  }
}
```

The exact schema can change, but these concepts should survive through shortlist and report
generation.

## Shortlist

The shortlist should split packages into separate top-level sections:

```text
DELIVERED / SHIPPED - ACTION REQUIRED
INSTALLED BUT NOT DELIVERED - REVIEW
LOCKFILE-ONLY / OPTIONAL FUTURE RISK - MONITOR
```

Each row should show why it is in that section:

- Artifact: `present`, `not present`, or `not scanned`.
- Install tree: `present`, `not present`, `lockfile only`, or `unknown`.
- Relation: direct, transitive, optional, dev, peer, or mixed.
- Dependency path.
- Target: the deployment target that was scanned or assumed.

Groups must not hide mixed states. If one row is delivered and another is lockfile-only
future risk, they belong in different sections even if they share the same license family or
root package.

Approving a future-risk item must not silently approve it later if it becomes delivered. A
change from `lockfile_only` or `not_delivered` to `delivered` should reopen the item and move
it into the delivered section.

## Final Documentation

This is the most important place to separate the concepts.

The main finalized report should foreground delivered dependencies. If LGPL/GPL/AGPL code is
in the shipped artifact, it should be impossible to miss. It should not be buried among
lockfile-only optional packages.

Non-delivered future risks should move to a clearly labeled appendix or secondary section,
for example:

```text
Not currently delivered - monitored license risks
```

Rows in that section should use language like:

```text
Not currently delivered. Monitor because a platform, feature, dependency, or deployment
change could install or include this package later.
```

The report must avoid implying compliance sign-off for latent optional dependencies. It can
say they were reviewed as non-delivered risks, but it should not present them as equivalent to
delivered obligations or as permanently approved.

If the artifact was not scanned, the final report should say that explicitly:

```text
Delivery artifact was not scanned; RepoLens cannot determine whether this dependency is
delivered.
```

## Release Disclosure Artifacts

RepoLens should produce release-ready disclosure artifacts, not just review reports. A
product should be able to consume these artifacts during PR prep, CI, or a local release
build.

Suggested outputs:

- `release.licenses.json`: machine-readable manifest for all delivered dependencies, their
  licenses, attribution requirements, source package URL, version, delivery artifact, and
  policy result.
- `release.notices.md`: human-readable third-party notices for dependencies that need
  attribution or disclosure.
- `release.notices.txt`: plain-text variant for products that need a bundled notice file.
- `release.review.md`: operator-facing summary of blocks, warnings, monitored future risks,
  and artifact-scan coverage.
- `release.policy.json`: deterministic gate result that CI can read without parsing
  Markdown.

The generated release files should keep separate categories:

- Delivered disclosure: included in product notices and surfaced to users when required.
- Delivered blocking: release must stop until the dependency is removed, replaced, approved,
  or handled through an explicit legal process.
- Installed-only review: kept in engineering review output, not user-facing notices unless
  policy says otherwise.
- Future-risk monitor: recorded in review output, but not presented as shipped disclosure.

RepoLens should make disclosure-friendly licenses non-scary but visible. For example,
`CC-BY-4.0` is not the same problem as delivered GPL/LGPL, but it can require attribution.
The right action is usually to generate the attribution line and include it in the product
notice surface, not to block release.

## Sketch2md Proof Of Concept

Sketch2md is a good proof-of-concept because it already has an `/about` page and a
hand-written `THIRD_PARTY_NOTICES.md`, while its lockfile shows several different risk
classes:

- `caniuse-lite` is `CC-BY-4.0`. If it is delivered in the Worker or browser artifact,
  RepoLens should generate a disclosure or attribution entry for Sketch2md.
- `json-schema` is `(AFL-2.1 OR BSD-3-Clause)`. RepoLens should resolve and display that as
  a permissive-choice item rather than making it look like copyleft risk.
- Sharp/libvips platform packages appear as optional dependencies with LGPL expressions in
  the lockfile. They should block only if the release artifact actually delivers them. If
  they are lockfile-only or installed-only for the current Worker release, they belong in
  monitored future-risk output.

A Sketch2md release build could run:

```bash
npm run build
repolens release \
  --work-root .repolens/sketch2md \
  --artifact .open-next/worker.js \
  --target cloudflare-worker \
  --notice-md THIRD_PARTY_NOTICES.generated.md \
  --notice-json public/legal/third-party-notices.json \
  --policy-json .repolens/release.policy.json
```

Then Sketch2md could incorporate the generated output in two places:

- The repository keeps a generated or checked `THIRD_PARTY_NOTICES.generated.md` for release
  review.
- The app exposes `public/legal/third-party-notices.json` or a rendered notice page linked
  from `/about`.

The current `THIRD_PARTY_NOTICES.md` can remain as the human-maintained overview, but the
release-specific dependency disclosures should come from RepoLens so they match the actual
artifact.

## PR Prep And CI Gate

RepoLens should support two adoption modes.

Manual PR prep:

1. Developer runs the normal product build.
2. Developer runs the RepoLens release command against the built artifact.
3. RepoLens updates the generated notices and policy result.
4. PR prep includes the generated diff and a short release-license summary.
5. CI fails if generated notices are stale or if delivered blocking licenses are present.

Automatic PR prep:

1. CI builds the release artifact.
2. RepoLens scans it and writes generated release files.
3. A bot can update the PR with notice-file changes when the only required action is
   attribution or disclosure.
4. CI still blocks on delivered GPL, LGPL, AGPL, non-commercial, source-available,
   unknown, or other organization-defined unfriendly licenses.
5. Future-risk items stay in the PR summary, but they do not fail the release unless policy
   requires artifact-scan coverage or a fresh review.

This gives projects a practical split:

- `CC-BY-4.0` delivered in Sketch2md: generate attribution, include it in `/about` or legal
  notices, and keep the release moving.
- LGPL lockfile-only Sharp/libvips package: document as monitored future risk and reopen if
  artifact evidence changes.
- LGPL/GPL delivered in the Worker: block the release.

## Suggested Implementation Slices

1. Add npm lockfile relation enrichment for optional, devOptional, peer, platform, and path
   metadata.
2. Add or accept a build-artifact scan that can mark packages as delivered for the chosen
   target.
3. Split shortlist rendering by delivered, installed-only, and future-risk presence state.
4. Split finalized reports so `report.main.*` emphasizes delivered obligations and appendices
   carry monitored non-delivered risks.
5. Add release disclosure artifacts for generated notice files and CI-readable policy
   results.
6. Add a regression fixture for a Next/OpenNext/Sharp-style app where platform-specific
   LGPL packages are present in the lockfile but absent from the delivered Worker artifact.

## Acceptance Criteria

- A lockfile-only optional LGPL package is not rendered as delivered runtime code.
- A delivered LGPL/GPL/AGPL package appears in the top action-required section.
- If artifact scanning was skipped, RepoLens says `artifact not scanned` instead of claiming
  `not delivered`.
- A package that moves from future-risk to delivered reopens review and moves to the
  delivered section.
- Final reports separate shipped obligations from monitored future risks.
- Mixed groups split by presence state instead of hiding delivered rows among optional rows.
- Delivered `CC-BY-4.0` packages generate attribution/disclosure output without being treated
  like copyleft blockers.
- Delivered GPL/LGPL/AGPL and other configured unfriendly licenses fail the release policy
  gate.
- Sketch2md can consume a generated notice artifact from RepoLens and expose it from `/about`
  or a linked legal notices page.

## Open Questions

- Which artifacts should RepoLens scan by default for common targets such as Cloudflare
  Workers, Docker images, npm packages, Electron apps, and static sites?
- Should `installed build/dev` appear in `report.main.*`, or only in an appendix unless policy
  marks it as blocking?
- How should RepoLens model packages that are dynamically downloaded at runtime?
- Should policy allow an organization to block release when artifact scanning is missing?
- Should generated notice files be committed, attached as CI artifacts, or both?
- Should RepoLens generate app-ready formats such as JSON for `/about` pages, Markdown for
  repos, and text for bundled distributions in one command?
