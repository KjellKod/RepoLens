# The Last Mile of License Compliance — Where Every Tool Quietly Gives Up

*Most open-source license tools get you 90% of the way and then hand you a spreadsheet of "UNKNOWN." This is about that last 10% — who actually closes it, what it costs, and where RepoLens is going.*

---

## The 90% problem

Run any modern scanner over your dependencies — ScanCode, Syft, Trivy, ORT — and you'll get an impressive-looking inventory in minutes. Hundreds of components, each with a neat SPDX identifier next to it. It feels done.

It isn't. Look closer and a stubborn residue is staring back at you:

- `NOASSERTION` and `UNKNOWN` rows where the scanner found *something* but couldn't map it to a real license.
- Dual- and multi-licensed packages (`MIT OR Apache-2.0`) where *somebody* still has to decide which obligation you're accepting.
- Packages whose repo isn't version-pinned, so the "license" the scanner saw might not be the license you actually shipped.
- And the part nobody enjoys: assembling the actual **attribution** — the LICENSE and NOTICE text you're legally required to redistribute for permissive licenses like MIT, Apache-2.0, and BSD.

Independent testing puts ScanCode — the gold-standard open-source engine — at roughly 95% correct license detection on real codebases. That 95% is genuinely excellent. But "95% detected" is not "100% disclosed," and the gap between those two numbers is the **last mile**: the detective work of resolving the ambiguous rows, proving each answer, and producing a disclosure you'd actually sign your name to.

That last mile is where the money, the time, and the lock-in all live.

---

## What each tier actually costs

There are three honest tiers in this market.

**Free / open-source engines** — ScanCode Toolkit, FOSSology, ORT, Syft, Trivy.
List price: **$0.** Real price: your engineers' time. These are excellent detectors and SBOM generators (ScanCode's curated license DB alone holds 2,000+ licenses), and they're the engines *inside* most of the commercial tools and aggregators like ClearlyDefined. But they stop at *findings*. ORT, for example, expects you to supply file-location **curations** to suppress false positives, and anything it can't map cleanly becomes `NOASSERTION` — your problem now.

**Commercial SCA / compliance platforms** — FOSSA, Black Duck, Snyk, Mend, Sonatype.
These are the tools that *do* close the last mile — attribution reports, policy gates, SBOM portals — and they price accordingly:

| Tool | Public pricing? | Real-world cost |
|---|---|---|
| **Snyk** | Yes | Free for open source; Team ~**$25/dev/mo** (~$275/yr/dev) on annual; bundles climb to **$52–98/dev/mo**. Watch the test-count limits. |
| **FOSSA** | Quote-only | Small teams **$20k–50k/yr**; enterprise **$150k+/yr**. Scales with projects/repos. |
| **Black Duck** | Quote-only | ~**$800–1,500 per seat/yr**; orgs commonly land **$75k–150k/yr**, up to **$250k+**. |
| **Mend** | Quote-only | Per *contributing* developer, annual; accessible for enterprises, steep for startups. |

**Data aggregators** — ClearlyDefined, deps.dev. Free license metadata, but they're inputs, not answers.

The pattern is stark: **the last mile is free if you do it by hand, or five-to-six figures a year if you buy it.** There has been very little in between.

---

## So who *actually* closes the last mile? (Candidly)

Let me be honest about each option, including my own.

**The commercial platforms genuinely do it.** FOSSA and Black Duck will generate an attribution/NOTICE bundle, enforce a license policy in CI, comment on your PRs, and hand you an SBOM portal. Black Duck even does binary and snippet analysis to catch components the metadata-only tools miss. If you have the budget and need audit-grade defensibility for M&A or IP indemnity, this is a solved problem — you're paying to make it someone else's job. The cost is the cheque and the vendor lock-in.

**The free tools mostly don't — and they're upfront about it.** This is the part the comparison blogs gloss over. With ScanCode + ORT + Syft, closing the last mile looks like:

1. Export findings to JSON.
2. Write glue scripts to triage `NOASSERTION`/`UNKNOWN` rows.
3. Manually go read the actual repo, the package metadata, the LICENSE file — *detective work* — to decide what each ambiguous component really is.
4. Maintain a growing pile of curation files so the same false positives don't reappear next scan.
5. Hand-assemble the NOTICE/attribution text from a dozen different file layouts.
6. Do it all again next release, because nothing remembered *why* you concluded what you concluded.

It works. Plenty of serious teams run exactly this. But it's bespoke scripting plus institutional memory, and the evidence trail lives in someone's head or a stale wiki page. When an auditor (or an acquirer's lawyer) asks "how do you *know* this is MIT?", "the scanner said so" is not a great answer.

**That is the gap RepoLens was built for.**

---

## Where RepoLens fits

RepoLens is a **license-disclosure orchestrator**. Point it at an owner/org, it sweeps *every* repository in *any* language, and turns the ambiguity the scanners leave behind into one clean, **evidence-backed** disclosure. Three things make it different from both tiers above:

1. **Verify-don't-trust.** RepoLens doesn't record a license because a tool *claimed* it. For each resolution it re-fetches the cited source — the GitHub License API, deps.dev, the CocoaPods spec — and confirms the *exact* SPDX anchor is really there, behind SSRF guards and host allowlists, fail-closed. A claim that can't be proven doesn't get trusted; it gets routed to a human with the receipt attached.

2. **The UNKNOWNs are the product, not the leftovers.** Where other tools dump the hard rows on you, resolving them *is* RepoLens's main job — with a clickable evidence link for every answer and a labeled review queue for everything it won't vouch for.

3. **Org-wide and free.** Not one repo at a time, not $50k/yr. The whole owner, in one pass, as open source.

There's a fourth thing that matters more in 2026 than it would have a few years ago: RepoLens's core verification is **model-free**. In an era where everything is plausibly AI-generated — including license claims — RepoLens's evidence is checked against authoritative sources, not guessed by a language model. (The research community has started auditing exactly this kind of "permissive-washing" in the AI supply chain; deterministic, fail-closed verification is the antidote.)

**The candid caveat:** RepoLens is early and individually maintained. The architecture is strong and the verification discipline is real, but it's not a funded vendor with a 2,750-license legal database, a support SLA, and a sales team. It is a sharp, trustworthy *disclosure layer* — not a one-tool-does-everything SCA suite. Use it for the job it's great at; don't expect it to also be your CVE scanner.

---

## Feature by feature: RepoLens vs the free stack

The fair comparison for an open-source tool isn't the five-figure platforms — it's the other free tools. And here's the twist: **inside the free tier, cost is a wash. Everything is $0.** So the question stops being "what does it cost" and becomes "what does each tool actually *do*, and how much hand-work does it leave on your desk?" That's the last-mile lens, pointed straight at the free stack.

Legend: ✅ strong · ◑ partial/shallow · ⬜ no · 🛣️ RepoLens roadmap (not today)

| Capability | RepoLens | ScanCode | ORT | FOSSology | Syft | Trivy |
|---|:--:|:--:|:--:|:--:|:--:|:--:|
| Deep license/copyright detection from source text | ⬜ | ✅ | ✅ | ✅ | ◑ | ◑ |
| Dependency resolution across build systems | ◑ | ◑ | ✅ | ⬜ | ✅ | ✅ |
| Multi-language / many ecosystems | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| **Org-/owner-wide sweep (all repos, one pass)** | ✅ | ⬜ | ⬜ | ⬜ | ⬜ | ⬜ |
| **Evidence-verified resolution** (re-fetch source, confirm exact SPDX anchor) | ✅ | ⬜ | ⬜ | ⬜ | ⬜ | ⬜ |
| Source↔package provenance binding | ✅ | ⬜ | ◑ | ⬜ | ⬜ | ⬜ |
| **UNKNOWN / NOASSERTION handling** | ✅ verified queue w/ receipts | ⬜ reports it | ◑ you curate | ◑ human clears | ⬜ | ⬜ |
| Human review workflow | ◑ markdown queue | ⬜ | ◑ | ✅ web UI + DB | ⬜ | ⬜ |
| Policy / allowlist enforcement | ◑ → 🛣️ | ⬜ | ✅ rules engine | ◑ | ⬜ | ◑ |
| CI gate / PR comments | 🛣️ | ◑ | ✅ | ◑ | ◑ | ✅ |
| Attribution / NOTICE generation | 🛣️ | ⬜ | ✅ | ✅ | ⬜ | ⬜ |
| SBOM export (SPDX/CycloneDX) | 🛣️ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Vulnerability scanning | ⬜ | ⬜ | ◑ | ⬜ | ⬜ | ✅ |
| Setup effort | low | low | **high** | **high** | low | low |
| Maturity / ecosystem / support | ⬜ early, solo | ✅ | ✅ | ✅ | ✅ | ✅ |

**RepoLens is mostly a column of blanks — and that's the entire point.** Strip away everything it deliberately *doesn't* do — detection engine, SBOM generator, vuln scanner — and you're left with three rows where it's the only ✅: org-wide sweep, evidence-verified resolution, and a receipts-backed UNKNOWN queue. It's a thin layer doing the one slice the others skip.

Per tool, candidly:

- **ScanCode** is the best detector here, full stop — but it answers "what licenses appear in these files," not "what do we ship across the org, and how do we *prove* it." Everything after detection is yours to script.
- **ORT** is the most *complete* free pipeline (analyze → scan → policy → NOTICE) if you can stomach the setup and the ongoing curation files. Its weak spot is exactly RepoLens's strong spot: it trusts what the scanner concluded rather than independently re-verifying each license against its source, and the `NOASSERTION` residue is still your detective work.
- **FOSSology** is the gold standard for *human* clearing at scale — real review UI, database, audit trail — but it's a heavyweight self-hosted server and the clearing is manual by design.
- **Syft / Trivy** are fast, CI-native, and beloved — and shallow on license (package metadata, not source text). Perfect for "give me an SBOM," useless for "give me a disclosure I can defend."

And where RepoLens plainly **loses**: detection depth (the text-scanners win on novel or mangled in-file licenses), attribution *today* (ORT and FOSSology generate NOTICE bundles now; for RepoLens that's roadmap), and maturity (the others have years, sponsors, and communities).

### The real conclusion: a layer, not a competitor

Put the table down and the honest takeaway isn't "RepoLens beats the free tools." It's that **RepoLens isn't their peer — it's the layer that belongs on top of them.** ScanCode and Syft are *evidence sources*. ORT is a *pipeline*. FOSSology is a *review desk*. None of them independently prove a license against its source, sweep a whole org, or turn the leftover UNKNOWNs into a disclosure with clickable receipts.

```
            ┌─────────────────────────────────────────────┐
            │   RepoLens — verify · resolve · disclose      │
            │   org-wide sweep · evidence receipts ·        │
            │   UNKNOWN queue · (soon) policy + NOTICE      │
            └───────────────▲───────────────▲──────────────┘
                            │ findings as evidence
        ┌───────────────────┼───────────────┼───────────────────┐
     ScanCode             Syft / Trivy       ORT            FOSSology
   (deep license        (fast SBOM,       (dep pipeline)  (human review)
    detection)        metadata licenses)
```

That's why the roadmap item "consume ScanCode/Syft output as evidence" matters more than any feature RepoLens could clone. The sharpest one-liner falls right out of it:

> **Bring your own scanner. RepoLens verifies it and turns it into a disclosure you can defend.**

---

## The road ahead

The disclosure-with-receipts core is the foundation. Here's where it can go — and the honest version of each.

### 1. Early-warning policy gate
A license allowlist/denylist that **warns or fails** when a disallowed family (say, AGPL or GPL in a permissively-licensed product) shows up. RepoLens already carries a policy notion internally, so this is a natural extension.
*Candid note:* this is **table stakes** — Snyk, FOSSA, Aikido, and RunSafe all gate builds on bad licenses today. RepoLens's differentiator can't be "we have a gate." It has to be "we have a gate backed by *verified evidence*, across your *whole org*, for *free*" — a policy decision you can defend, not just a red X in CI.

### 2. CI-native, incremental, cached
Run on every PR, but be cheap about it: **cache the SBOM**, and on each diff **only re-verify the dependencies that changed**. Post a PR comment with the new/changed components and their evidence. This turns RepoLens from a quarterly fire-drill into a quiet, always-on guardrail — and incremental re-verification is exactly the kind of thing the expensive platforms charge per-developer for.

### 3. The actual deliverable: attribution generation
Auto-assemble the **NOTICE / attribution bundle** — the legally-required LICENSE and copyright text — from the same verified evidence. This is the single most tedious last-mile chore, and producing it *from proven sources* (rather than scraped guesses) is a uniquely strong position.

### 4. Standards out, evidence in
- **Out:** SPDX and CycloneDX SBOM export, so RepoLens plays nicely with everything downstream (and rides the EU Cyber Resilience Act / SBOM-mandate tailwind).
- **In:** consume ScanCode and Syft output *as evidence sources*. Don't reinvent the scanner — orchestrate the best ones and add the verification + disclosure layer on top. That keeps RepoLens complementary to the free engines instead of competing with them.

### 5. Drift and history
Track license posture over time: when did this dependency change license? When did an UNKNOWN get resolved, by whom, and on what evidence? A durable, queryable **evidence archive** is something neither a one-shot scan nor a human's memory provides — and it's what auditors actually want.

---

## Should this be commercialized? (An honest counsel to myself)

It's tempting, and there's a real case for it. Compliance has budget, the pain is recurring, regulation (CRA, federal SBOM mandates) is creating tailwinds, and "last mile + evidence archive + org dashboard + support" is a sellable bundle. The likely model is **open-core**: keep the verification engine and CLI fully open source, and charge for the *operational* burden — a hosted org dashboard, a retained evidence/attestation vault, attribution-as-a-service, CI at scale.

But here's the part I'd want said out loud:

- **Don't try to win as a dashboard.** FOSSA, Black Duck, Snyk, and Mend are well-funded and have years of polish. Competing on feature-count is a losing game for a small team.
- **The moat is trust, not features.** RepoLens's credibility comes from being transparent, deterministic, and open. The moment it becomes a paid "compliance authority," it inherits legal liability and starts eroding the very thing that makes it believable. Monetize *convenience and scale*, never the core verification or the honesty.
- **Open-core has a tension.** Paywalling the wrong thing alienates the community whose trust *is* the product.
- **There's a respectable non-commercial path.** ScanCode-adjacent work has been funded by NLnet and similar; grants, sponsorship, and consulting can sustain a high-impact OSS tool without a sales motion at all.

My honest read: if the goal is **impact**, stay OSS, pursue sponsorship, and become the trustworthy free layer the ecosystem is missing. If the goal is a **business**, go open-core — but sell the hosting, retention, and attestations, keep the engine free and auditable, and accept that you're entering a knife fight with incumbents on everything except the one thing they don't have: *proof.*

---

## A few other angles worth keeping in view

- **AI-era trust.** "Verified against the source, not generated by a model" is going to be a louder and louder selling point as AI-authored code and AI-guessed metadata flood the supply chain.
- **Human-in-the-loop as a feature, not a failure.** RepoLens doesn't pretend to auto-approve everything; it's honest about what it can't prove. In compliance, that humility is exactly what a reviewer and an auditor want.
- **Complement, don't compete.** The smartest positioning is "bring your own scanner, we'll verify and disclose." That makes RepoLens additive to the free tools people already run, and a cheaper finisher than the platforms.
- **Regulation is a rising tide.** SBOMs are moving from nice-to-have to mandated. The tool that produces a *defensible, evidence-backed* one — not just a list — is well-placed.

---

## The verdict

If you need a vendor's legal database and indemnity for high-stakes compliance, pay for **Black Duck** or **FOSSA** and make it their job. If you just need a fast SBOM, use **Syft**. If you want the most accurate free *engine*, it's **ScanCode**.

But if your real problem is *"produce a trustworthy license disclosure across all our repos, and stop hand-resolving UNKNOWNs with throwaway scripts"* — that last mile has been a false choice between a five-figure cheque and a weekend of detective work. RepoLens exists to make it a third thing: **free, org-wide, and backed by receipts.**

---

### Sources
- [Open-Source License Compliance for Developers (2026) — AppSec Santa](https://appsecsanta.com/sca-tools/open-source-license-compliance)
- [Best SBOM Tools 2026: Syft Leads OSS, FOSSA Leads Commercial — AppSec Santa](https://appsecsanta.com/sca-tools/sbom-tools-comparison)
- [Top Open Source License Scanners — Aikido](https://www.aikido.dev/blog/top-open-source-license-scanners)
- [Snyk plans & pricing](https://snyk.io/plans/) · [FOSSA pricing](https://fossa.com/pricing/) · [Snyk pricing breakdown 2026 — Vendr](https://www.vendr.com/marketplace/snyk) · [FOSSA pricing — Vendr](https://www.vendr.com/marketplace/fossa) · [Black Duck pricing — Vendr](https://www.vendr.com/marketplace/black-duck-software)
- [ScanCode Toolkit — GitHub](https://github.com/aboutcode-org/scancode-toolkit) · [ScanCode LicenseDB: 2,000+ curated licenses — AboutCode](https://aboutcode.org/2023/curated-licenses-public-database-scancode-licensedb/)
- [FOSSology](https://www.fossology.org/) · [ScanCode scanner — OSS Review Toolkit docs](http://oss-review-toolkit.org/ort/docs/plugins/scanners/ScanCode)
- [Snyk license compliance & SDLC policies — Snyk Docs](https://docs.snyk.io/scan-with-snyk/snyk-open-source/scan-open-source-libraries-and-licenses/snyk-license-compliance-management)
- [Permissive-Washing in the Open AI Supply Chain: A Large-Scale Audit of License Integrity — arXiv](https://arxiv.org/pdf/2602.08816)
