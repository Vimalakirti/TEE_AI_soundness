# Reproductions for GHSA-qg2r-c2j8-phcm

Local reproductions for the three issues in the advisory write-up. Everything runs on one machine
against an unmodified PySyft checkout. No cloud deployment, TEE, or Tinfoil account is needed.
You need `git`, `uv` (issue 3 uses it to build the job's environment) and Python 3.12.

## Setup

```bash
git clone https://github.com/OpenMined/PySyft.git && cd PySyft
git checkout <commit under test>        # e.g. 7c111ddd6e (reviewed) or 3921fcaa97 (dev, 2026-11-19)
UV_PROJECT_ENVIRONMENT=.venv-repro uv sync --frozen --no-dev --package syft-enclave --python 3.12
cd <this folder>
PYSYFT=/path/to/PySyft PY=/path/to/PySyft/.venv-repro/bin/python ./run_repro.sh
```

Issue 3 builds a job venv; `run_repro.sh` sets `UV_LINK_MODE=symlink`. PySyft's in-process test
setup leaves `/tmp/sb_folder_testing-*` directories behind.

### Testing the syft-restrict release on PyPI

At dev `3921fcaa97` the in-tree syft-restrict rejects the issue-1 files, but the gemma notebooks
install `syft-restrict` from PyPI unpinned. To test the published release instead, unpack its
wheel and point `RESTRICT_SRC` at it:

```bash
mkdir -p /tmp/sr && cd /tmp/sr
pip download --no-deps syft-restrict==0.1.1 && unzip -qo syft_restrict-0.1.1-*.whl -d src
cd <this folder>
RESTRICT_SRC=/tmp/sr/src PYSYFT=... PY=... ./run_repro.sh
```

With 0.1.1 (and 0.1.0), `poc1` and `poc2` get `ok = True` and `demo_restrict_exfil.py` reports
REPRODUCED.

## Files

| File | Issue | What it does |
|---|---|---|
| `restrict/harness.py` | 1 | Runs `syft_restrict.run` (from `RESTRICT_SRC`, default the copy in `$PYSYFT`) with the allow-list and operators from `notebooks/enclave/gemma/colab-3-persona/1. DO-model-owner-gemma-restrict.ipynb`; prints the verdict and violations. |
| `restrict/poc1_sorted_key_urlopen.py` | 1 | `sorted([url % prompt], key=urlopen)` inside `obfuscate` markers, with a public `from urllib.request import urlopen`. |
| `restrict/poc2_pickle_rce.py` | 1 | Hidden bytes constant and `max([blob], key=loads)` inside `hide` markers, with a public `from pickle import loads`. |
| `restrict/poc3_dunder_assign.py` | 1 | `__getattr__ = _hook` (and `__init__`, `__reduce__`) assigned in a class body instead of defined with `def`. |
| `restrict/poc4_flax_variable_gadget.py` | 1 | `self.variable("cache", "k", system, "...")`: flax calls `init_fn(*args)`. Verdict only; not executed. |
| `restrict/poc5_inherited_attr.py` | 1 | Never-assigned `self.exfiltrate(x)` on an `nn.Module` subclass, accepted under `allow_base_class_attributes=True`. Verdict only. |
| `restrict/neg_direct.py` | 1 | Control: a direct `urlopen(...)` call. Expected `ok=False`. |
| `restrict/regression/*.py` | 1 | Further variants (module-attribute reference, public helper taking a function, default argument, decorator, inherited attribute as `key=`). Useful as regression cases. |
| `restrict/demo_restrict_exfil.py` | 1 | Analyzes poc1/poc2, then imports and runs them: a listener on `127.0.0.1:8765` stands in for the exfiltration endpoint, and the pickle payload writes `pwned.txt`. Reports REPRODUCED only if the verifier accepted both files. |
| `issue2_receipt_forgery.py` | 2 | Takes `notebooks/enclave/double-blind-eval-w-receipts/receipt.json`, changes `unsafe_completion_rate` 0.6 to 0.0, signs with a fresh ed25519 key, rebuilds the `keyBinding` section around that key so its internal hashes match, and calls `verify_receipt`. |
| `issue3_log_stdout.py` | 3 | PySyft's in-process test setup (`quad_with_mock_drive_service_connection`, encryption on). An approved job fails with an exception quoting a private prompt; neither data owner releases the logs; checks whether the prompt reached the enclave process's stdout. For dev at or after `354b283bb6` (read-permissions API). |
| `issue3_log_stdout_pre_354b283bb6.py` | 3 | Same test with the earlier disclosures API (`request_disclosures`, `granted_disclosures`). `run_repro.sh` picks the right one. |
| `expected_output_7c111ddd6e.txt`, `expected_output_3921fcaa97.txt` | all | Our output at the reviewed commit and at dev on 2026-11-19. |
| `expected_output_3921fcaa97_syft-restrict-0.1.1.txt` | all | Our output at dev with `RESTRICT_SRC` set to the syft-restrict 0.1.1 wheel from PyPI. |

Issue 3 shows output on container stdout only. Whether it reaches Cloud Logging depends on the
image's `tee.launch_policy.log_redirect` label and the operator's launch metadata; we did not test
a live deployment.
