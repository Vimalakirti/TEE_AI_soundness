Title: Potential soundness issues in Tinfoil’s stack
To: security@tinfoil.sh
CC: ddkang@g.illinois.edu, erl015@ucsd.edu, stephanie.q.ding@gmail.com, hpmv118@gmail.com

Hi Tinfoil security team,
We are a research team at UIUC and MATS studying soundness issues in TEE-based AI attestation systems. As part of this work, we reviewed two parts of the Tinfoil stack: the modelwrap build-time tool and the tinfoil-go client-side verifier SDK.
During our review, we identified several potential soundness gaps that we would like to disclose and discuss with you. The issues we believe are most important involve the handling of pre-existing modelwrap output artifacts during model packaging, and the way tinfoil-go resolves release metadata through github-proxy.tinfoil.sh. In our current understanding, these issues may affect the integrity or freshness assumptions behind the attestation flow.
Reviewed versions:
github.com/tinfoilsh/modelwrap, branch main, commit 6d514838 dated 2026-05-04.
github.com/tinfoilsh/tinfoil-go, branch main, commit ff185e53 dated 2026-05-08.
The main issues we would like to report are:
Pre-existing modelwrap outputs appear to bypass fresh packaging. In pack.py:58-71, 77-102, the tool appears to skip mkfs.erofs and veritysetup when the expected output files already exist. Our understanding is that a malicious or compromised builder may be able to pre-place a chosen <commit>.mpk and <commit>.info pair before running modelwrap, causing the downstream CVM image builder to consume an attacker-chosen dm-verity root hash.
The .info output does not appear to bind enough model identity metadata. The current .info format appears to contain the root hash, offset, and verity UUID, but not the model name, Hugging Face revision, tool version, or publisher signature. This may make it difficult for downstream consumers to link a root hash back to a specific named model and revision without relying on an external mapping.
Optional @revision may allow the selected model revision to float. In pack.py:25-31, the model revision appears to be optional. Depending on how the tool is invoked, this may allow different environment states or upstream repository states to produce different root hashes while the verifier sees only the resulting root hash.
Output artifacts appear to be unsigned. The generated .mpk and .info artifacts do not appear to carry a publisher signature. This may leave room for substitution between the build container and the CVM image-building step unless the surrounding deployment pipeline provides additional provenance guarantees.
tinfoil-go appears to rely on github-proxy.tinfoil.sh for release currency. In verifier/github/github.go:11, the SDK hard-codes githubProxy = "https://github-proxy.tinfoil.sh", and the release tag, digest, and attestation bundle resolution flow appears to go through this proxy. Although the Sigstore bundle is still verified downstream, our understanding is that the SDK’s view of the “latest” release depends on the proxy response. This may allow rollback or stale-release behavior if the proxy is compromised, misconfigured, or serving stale data.
The hardware measurement resolution path appears to share the same proxy dependency. LatestHardwareMeasurements appears to be resolved through the same proxy path, so the same trust-root centralization may apply to the GPU-related measurement chain.
Some possible mitigations we are considering include:
When outputs already exist for the requested (model, revision), either rebuilding to a temporary directory and comparing the result byte-for-byte, or refusing to proceed until the operator clears the output directory.
Extending .info to a structured format, such as JSON or TOML, that records the model name, Hugging Face revision, tool versions, and a publisher signature.
Having the CVM image builder reject unsigned or provenance-free modelwrap outputs.
Driving modelwrap from CI with in-toto / SLSA-style provenance and requiring that provenance downstream.
Resolving (tag, digest) from at least one trust root independent of github-proxy.tinfoil.sh, such as GitHub’s Release API, and requiring agreement before accepting the resolution.
Adding a freshness floor or minimum accepted tag/digest policy for the SDK.
Tightening the Sigstore identity policy to a specific workflow path and release-tag pattern where appropriate.
Our current plan is to release a blog post and arXiv preprint around August 6, 2026, which is 60 days from this email. We would like to coordinate responsibly, incorporate your feedback, and acknowledge your response in the writeup.
We would also appreciate any corrections if we have misunderstood Tinfoil’s intended threat model, deployment assumptions, build pipeline, or verifier workflow.
Please confirm receipt and let us know which channel you would prefer for further correspondence.
Best,
Bing-Jyue
UIUC



Hey Bing-Jyue,

Thank you so much for reaching out with these findings!

None of the findings break attestation soundness, but they are helpful from a build hygiene and supply chain hardening perspective. Rollback mitigation is also something we're aware of, freshness at the repo release level is hard to enforce since Sigstore doesn’t have a notion of freshness. But we do support client side version pinning and minimum firmware version, and will be adding minimum CVM image version shortly. Jules (my cofounder) has also been thinking a lot about freshness recently, he's back tomorrow and will have additional thoughts on the last mitigation you listed ("Tightening the Sigstore identity policy to a specific workflow path and release-tag pattern where appropriate.") as he's been working towards similar goals with short-lived, periodically refreshed Sigstore proofs.

re: 1-4 (modelwrap), the reason they don't break integrity is because the root hash is pinned to the tinfoil-config.yml file (Example model tinfoil-config.yml). Weights that don't match the root hash fail at boot because the served bytes are dm-verity-bound to the root hash. Weights that do match require getting the hash into the signed config which involves a CI/repo compromise and even so, the modelwrap build is bit-by-bit reproducible which makes the substitution independently detectable.

Taking a step back and thinking about the trust assumptions at a high level, for modelwrap this is not an "attested build" argument where the builders are trusted and attested, it's a "reproducible build" argument where anyone can rebuild the mpk from the model referenced in the config and confirm the root hash matches. This is why all of modelwrap is computed by us on the host in an untrusted way, there are no trust assumptions there.

With that said, I'll go through each point one-by-one.

1. "Pre-existing modelwrap outputs appear to bypass fresh packaging…"

This is an intentional build cache and the outputs are keyed on the model's commit and packing is deterministic, so a cache hit returns exactly the bytes a clean rebuild would produce. Even if an attacker with write access to the build host swapped the .mpk, it wouldn't affect integrity for two reasons: (1) an inconsistent swap fails dm-verity/attestation at boot, and a self-consistent one only matters if its hash is committed into the signed tinfoil-config.yml, which requires a CI/repo compromise. (2) Even then it's detectable, since the build is reproducible (rebuild from model@commit and compare). The mitigation you listed involving recomputation on every run is already covered with the dm-verity + reproducibility guarantees and would get rid of the performance benefits of the cache.

2. "The .info output does not appear to bind enough model identity metadata.."

.info is not part of the attestation at all, it's just a helpful descriptor. It is the deployment repo's tinfoil-config.yml that actually records the served name, the full Hugging face repo@revision and the mpk root hash together, example. The mpk root hash already incorporates the specific model revision. A publisher signature on the artifact is redundant because trust is anchored in the measured config + live client attestation.

However, to improve auditor convenience, it is valuable to pin the tool version, since the root hash depends on the modelwrap version (pack.py flags + pinned erofs-utils/cryptsetup). We've never changed the pinned versions here so missed the part about recording which version produced a given hash, but we'll close that by recording the specific modelwrap commit alongside hash.

3. "Optional @revision may allow the selected model revision to float.."

modelwrap's @revision is optional only as a build-time convenience (it resolves HEAD if omitted) but whatever it resolves to, the output is a concrete root hash, and that's what gets deployed. In the deployment config however, we pin the full commit, and the revision cannot float (example). So a verifier always checks a fixed revision and hash, not a floating revision. The actual hardening here is to require the version to be pinned in tinfoil-config.yml.

To be fully precise about 2 and 3: a tinfoil-config.yml could in principle mislabel the model by claiming a name and revision that doesn't match the bytes behind mpk and that would still attest because the client is verifying the measurement but not the label's truthfulness. But that is not forgeable by an outsider and is detectable by reproduction.

4. "Output artifacts appear to be unsigned…"

Yes, there are additional provenance guarantees. For a bad hash of .mpk to ever reach a client, it has to make it into the signed tinfoil-config.yml, which means the attacker has to have compromised (with write access) our CI/deployment pipeline. A signature on modelwrap's output wouldn't prevent that. This is necessary because the deployed .mpk is dm-verity-bound to whatever hash is in that signed config. Also note that the hash <-> model link is reproducibly checkable by anyone.

5 and 6. Yes, these are both very fair concerns, we have relatively weak freshness guarantees for repo release versions. This is due to the fact that Sigstore as is has no notion of freshness. The easiest thing to mitigate this was to add a trust assumption for freshness on Tinfoil and GitHub. We already support full client side version pinning, but we do plan to support a monotonic minimum version floor for CVM version across all SDKs, plus a configurable repo floor. Additionally, we already have firmware/TCB rollback floor compiled into the client so a rollback is bounded to the release/code-measurement layer, not the platform, see AMD floor and TDX floor. It’s quite difficult to add separate floors for each deployment repo, so the next best thing is to add floors for firmware and CVM image which already seriously limits the blast radius of a rollback.

In terms of next steps, here is what we plan to action (in order of priority):

1. Rollback prevention: Add minimum accepted version of CVM version to all our SDKs.
2. Ease of auditability: Record modelwrap version and model commit version used to produce root hash in tinfoil-config.yml.

On process, August 6 timeline is good and we'll prioritize getting these fixes shipped before then, security@tinfoil.sh is the best channel and we'd be happy to review a draft before you publish.

Please let me know if you have any other concerns!

Best,
Tanya


Hi Bing-Jyue and sorry for the delay in response,

I wanted to make more progress on architecture/implementation before writing to you about it.

First, we've released a substantial set of changes to modelwrap since the version you reviewed (6d514838), and several of them directly address the findings and remediations we discussed. Please find a summary below. Everything is on github.com/tinfoilsh/modelwrap main.

Formal spec. modelwrap now has a written specification (SPEC.md) covering the artifact format, trust assumptions, and verification parameters. It explicitly documents that the packer is untrusted and that verifiability rests on reproducibility: the trust model from our earlier email is now a normative document you can cite.

Re: issue 1 (cached outputs). We added an optional --verify flag that re-runs full dm-verity verification over cached or pre-existing artifacts, so operators can validate cache hits at pack time rather than discovering a mismatch later at boot (trade packing time for more certainty). As discussed, an artifact that doesn't match the root hash in the signed config still fails closed regardless.

Re: issues 2 and 3 (identity metadata and revision pinning). As discussed, the trust argument here was unchanged: the label in tinfoil-config.yml was descriptive, and the bytes-to-label link was (and is) established by reproducibility. That said, we took the auditability point to heart! First, the dm-verity salt is now derived from name@revision, which the enclave re-derives from the repo field in the measured config at boot. A root hash therefore commits to a single model identity, so a mislabeled name or revision fails closed at boot instead of attesting silently. This also implements your suggested hardening for issue 3: repo with a pinned revision is now a required config field, so revisions cannot float by construction. Second, on recording the tool version behind each hash: packing now always runs via a digest-pinned toolchain image, with the digest embedded in release binaries, giving auditors a deterministic mapping from any root hash to the toolchain that produced it.

To answer your first question: the model root hash (independently reproducible) is recorded in the tinfoil-config.yml, which is hashed and 1) added to the kernel command line (part of both SEV-SNP and TDX measurements) 2) checked during boot to match the loaded config. The client SDK verifies that expected measurements (which are cryptographically tied to the model root hash and fetched from Sigstore) match the live enclave measurements on each connection.

On what's pinned: the client pins the enclave host and the github repo that contains the tinfoil-config.yml (the accepted Sigstore signing identity is derived from that repo: a tag-triggered workflow of the pinned repo). For now, the release tag/digest is resolved dynamically: that's the gap the freshness design below tries to close. There is no duplicate model-name pin: the model identity and root hash come from the measured tinfoil-config.yml.

For the second question: we've since converged on a freshness architecture that we expect will supersede the version-floor design we previously described.

The plan is to publish "freshness witnesses" alongside our regular Sigstore releases. A single Tinfoil-owned repo (tinfoilsh/freshness-witness) will publish one small Sigstore-signed statement per tracked config repo, endorsing that repo's latest release (tag and digest) with an issuance timestamp. SDKs then require any accepted artifact to be covered by a witness less than 7 days old, with the window hardcoded in the verifier rather than declared in the witness, so the signing pipeline cannot extend its own validity.

This is essentially the TUF timestamp-role pattern applied to Sigstore, which lacks a native freshness notion. It gives us:

- Bounded validity: any release goes stale after 7 days unless actively re-endorsed.
- Auditability: the currently endorsed set is published on a transparency log, so a freeze or rollback attempt is either bounded to the window or leaves a public trace.
- Concurrent valid versions: witnesses are looked up by artifact digest rather than "latest," so multiple supported releases can be fresh simultaneously (e.g. during a fleet rollout).

The "operational" cost is that we now need to periodically re-triggers the witness signing for every repo in production. We also intentionally pick the trade-off of not maintaining revocation lists for specific vulnerable versions: instead, ceasing to re-endorse a version effectively revokes it within the freshness window, which is more operationally robust for us.

To your question on defaults: the freshness check will land in the verifier alongside the existing version pinning and firmware/TCB floors, and we intend to make it the default and may tighten the window overtime. To be precise about the trust model: this doesn't fully remove Tinfoil from the freshness loop. We operate the witness service and can always deny service or republish a freshness-witness for an old version, but it makes these actions publicly logged in concordance with the rest of our threat model.

Let me know if you have any other questions regarding this and we will keep you posted as the freshness feature rolls out in prod.

Cheers,
Jules
