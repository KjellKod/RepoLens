# LinkedIn post — RepoLens / last-mile license compliance

**Your license scanner says you're 95% compliant. That last 5% is where the lawyers live.**

Run ScanCode, Syft, or Trivy over your dependencies and you get a tidy inventory in minutes. Hundreds of components, each with a neat SPDX tag. It *feels* done.

It isn't.

Look closer and the same residue is always there:

• `NOASSERTION` / `UNKNOWN` — the scanner saw something but couldn't pin the license
• dual-licensed packages (`MIT OR Apache-2.0`) where *someone* still has to choose the obligation you're accepting
• repos that aren't version-pinned, so the license it saw may not be the one you shipped
• and the chore nobody wants: assembling the actual attribution — the LICENSE and copyright text you're legally required to redistribute

"95% detected" is not "100% disclosed." The gap between them is the **last mile**: resolving the ambiguous rows, *proving* each answer, and producing a disclosure you'd put your name on.

Today that last mile is a brutal either/or:

→ **Pay for it.** FOSSA, Black Duck, and friends will finish it for you — attribution bundles, policy gates, SBOM portals — for roughly $20k–$250k a year, plus the lock-in.

→ **Script it.** With the free tools you export findings, write glue scripts to triage the UNKNOWNs, go read the actual repos and LICENSE files (yes, detective work), maintain curation files so the same false positives don't reappear, and hand-assemble the NOTICE text. Then do it all again next release — because nothing remembered *why* you concluded what you concluded.

Here's the part the comparison blogs skip: the free scanners are brilliant at *detection* and then hand you the hard part. The commercial platforms finish it, but you're renting the answer.

That's the gap I built **RepoLens** to close.

RepoLens is a license-disclosure orchestrator. Point it at an org, it sweeps every repo in any language, and turns the ambiguity the scanners leave behind into one clean, **evidence-backed** disclosure. The core idea is *verify-don't-trust*: it doesn't record a license because a tool claimed it — it re-fetches the cited source (the GitHub License API, deps.dev, the package registry), confirms the *exact* license is really there, and routes anything it can't prove to a human review queue with a clickable receipt attached.

In 2026 that last detail matters more than it used to. When an auditor — or an acquirer's lawyer — asks "how do you *know* this is MIT?", "the scanner said so" is a weak answer. "Here's the verified source we checked it against" is not. In an era where licenses, code, and metadata are all plausibly AI-generated, **verified beats generated.**

And the honest part: RepoLens isn't trying to replace ScanCode or Syft. It's the *layer on top* of them. Bring your own scanner — RepoLens verifies it and turns it into a disclosure you can defend. It's open source, it runs org-wide, and it's free.

If your problem is "produce a trustworthy license disclosure across all our repos, and stop hand-resolving UNKNOWNs with throwaway scripts" — that's exactly the itch.

I'd genuinely value the scrutiny: if you do open-source compliance, where does *your* last mile hurt most — the UNKNOWNs, the attribution bundle, or proving any of it to legal?

🔗 [link to repo / longer write-up]

#opensource #softwarecomposition #compliance #SBOM #devtools #licensing
