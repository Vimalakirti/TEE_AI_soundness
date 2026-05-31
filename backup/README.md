# `backup/` — defensive snapshot of submodule upstreams

This directory contains **bare git mirrors** of the ten upstream
repositories referenced as submodules under `tee_attest/`. It exists
because the submodules track commits in third-party repositories
audited as part of this work; after responsible disclosure, those
upstreams may force-push to rewrite history, delete branches, or
take the repository private — any of which would render the pinned
submodule SHAs unreachable from upstream.

The mirrors here preserve **every ref and every object** present in
the upstreams at the time of capture, so the exact commits the
findings reference remain reproducible regardless of what happens
upstream.

**The submodule layout under `tee_attest/` is unchanged.** These
mirrors are purely additive — a fallback you can pivot to if needed.

## Contents

| Mirror | Upstream | Pinned commit (referenced by findings) |
|---|---|---|
| `EphemeralML.git`                  | https://github.com/cyntrisec/EphemeralML            | `44cb844e69cd782e54e65fbe47540bde936cd7cc` |
| `Power.git`                        | https://github.com/A3S-Lab/Power                    | `7bbaebee1dfe47c3b8b642b3e346bae7492e461e` |
| `laminator.git`                    | https://github.com/ssg-research/laminator           | `ce2d10bbe562f08bb1d03bc72f4530d64fc71c0e` |
| `nearai-cloud-verifier.git`        | https://github.com/nearai/nearai-cloud-verifier     | `8b7830e96aa4c0b2b797a2249616da7de6d0087f` |
| `confidential-model-router.git`    | https://github.com/tinfoilsh/confidential-model-router | `e77912035c5979ce6eb3a06cf01c9e5f4ee94fbc` |
| `verifiable-reviewer.git`          | https://github.com/tinfoilsh/verifiable-reviewer    | `98ed88aa69064fb8e57c1c6a390336e3bfad5f46` |
| `tinfoil-python.git`               | https://github.com/tinfoilsh/tinfoil-python         | `6f8f20b817735a89df138e1c8f214d7891bd8911` |
| `tinfoil-go.git`                   | https://github.com/tinfoilsh/tinfoil-go             | `ff185e53ce49743322f3357ba311a7c66701b39e` |
| `modelwrap.git`                    | https://github.com/tinfoilsh/modelwrap              | `6d514838cb3889aed13def0d453752afab19340d` |
| `cvmimage.git`                     | https://github.com/tinfoilsh/cvmimage               | `dd81cae2ba952979b7e86c4984c87d703b56876d` |

Total: ~356 MB. Each `*.git/` is a bare git repository (no working
tree); it stores the full object graph and all refs as captured.

## Using a mirror

To **extract the pinned snapshot** as a working tree:

```bash
git clone backup/laminator.git -b main /tmp/laminator-pin
cd /tmp/laminator-pin
git checkout ce2d10bbe562f08bb1d03bc72f4530d64fc71c0e
```

To **inspect a specific commit** without checking it out:

```bash
git --git-dir=backup/laminator.git show ce2d10bbe5
git --git-dir=backup/laminator.git log --oneline -20
git --git-dir=backup/laminator.git ls-tree -r HEAD | head
```

To **pivot a submodule to its backup** (e.g., upstream disappeared):

```bash
# Point the submodule's origin at the in-repo backup.
git -C tee_attest/laminator remote set-url origin "$(git rev-parse --show-toplevel)/backup/laminator.git"
git submodule update --init tee_attest/laminator
```

(You can also edit `.gitmodules` to make the swap permanent for new
cloners, but that change disconnects them from upstream's live tree.
Leaving `.gitmodules` on the upstream URL and relying on these
backups as a manual fallback is usually the right policy.)

## Refreshing

The mirrors are point-in-time snapshots. To pull any new upstream
refs into a mirror without losing what's already captured:

```bash
cd backup/<name>.git
git fetch --prune --tags origin
```

This is safe — `git fetch` into a bare mirror only adds refs/objects;
it never deletes them locally even if upstream did.

## What's preserved

For each mirror, **all branches, all tags, all reachable
historical commits** at capture time are stored. The pinned commits
listed above are each anchored as a reachable object — even if
upstream later force-pushes or deletes the branch that contained
them.

## Capture method (for the record)

```bash
git clone --mirror <upstream-url> <name>.git
# (Two large mirrors were repacked with --max-pack-size=80m
#  so no single object file exceeds GitHub's per-file ceiling.)
```
