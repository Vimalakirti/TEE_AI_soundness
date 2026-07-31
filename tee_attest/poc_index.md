# Paper-Aligned Index of P1--P18

This is the authoritative index for the eighteen executable witnesses in the
paper. It supersedes the earlier nineteen-attack numbering in the historical
working documents. In particular, the former NEAR AI model-identity attack is
withdrawn: the platform binds model identity through `mr_config_id` and its
compose measurement.

An *executable witness* may demonstrate a concrete dishonest-provider attack,
an implementation under-enforcement case, or a narrower evidence-format or API
boundary. The final column prevents those results from being interpreted as
equivalent end-to-end compromises.

| ID | System | Class | Property examined | Executed boundary and status |
|---|---|---|---|---|
| P1 | Laminator | F5, F2 | The attested model identifier refers to the weights that produced the result. | Exercises the vulnerable loader and keeps its hash fixed while returned weights change; SGX quote generation is stubbed. Fixed upstream. |
| P2 | Laminator | F5 | Reported accuracy is computed for the identified model. | Drives payload construction and changes the metric during deserialization; quote generation is stubbed. Fixed upstream. |
| P3 | A3S/Power | F2 | The attestation-time model hash describes the model subsequently loaded. | Invokes real hashing and checking helpers while reproducing the HTTP handler; no confidential VM or quote. Maintainer committed remediation. |
| P4 | Tinfoil `modelwrap` | F2 | A standalone invocation produced output for the requested revision. | Runs the unmodified skip-if-output-exists path. Tinfoil's first-party measured configuration and reproducible rebuild add checks; build hardening shipped. |
| P5 | Laminator | F1 | Signed run metadata independently establishes the run configuration. | Reproduces the constructor that copies unmeasured `argv`; demonstrates signed operator assertions, not unchanged evidence. Fixed upstream. |
| P6 | A3S/Power | F5 | Request evidence identifies the template and rendered prompt given to the model. | Invokes the real Jinja renderer. The receipt lacks a separate rendered-prompt field, while a full GGUF hash may bind the template indirectly. Maintainer committed schema clarification/hardening. |
| P7 | EphemeralML / AIR | F7 | AIR can represent and let policy pin the sampling regime. | Builds valid AIR receipts and calls the unmodified verifier; no model inference or Nitro hardware. Format extension planned. |
| P8 | NEAR AI Cloud | F7 | The signed-text format can represent and pin the sampling regime. | Reproduces the published signed-text path; no service call or platform signature. Intended assurance boundary clarified. |
| P9 | NEAR AI Cloud | F6 | The published client binds the live TLS peer to the attested key on its default path. | Imports the real report-data check with a synthetic quote and two local TLS keys. Tests an optional check in an illustrative client, not the platform binding. |
| P10 | EphemeralML / AIR | F6 | Calling the low-level receipt verifier establishes hardware provenance of its signing key. | Calls the unmodified low-level verifier with a software-generated key. The complete flow must also verify the Nitro document; a one-call chained verifier shipped. |
| P11 | A3S/Power | F8 | Separate CPU and GPU evidence identifies one composed inference. | Invokes the real 64-byte report-data constructor; the NRAS verdict is mocked, so this is a layout/composition witness rather than a TDX/H100 run. Maintainer committed explicit binding. |
| P12 | NEAR AI Cloud | F8 | The published client rejects a GPU nonce that differs from the request. | Exercises illustrative-client under-enforcement. The platform itself uses a shared nonce and combined measurement. |
| P13 | NEAR AI Cloud | F4 | The client independently authenticates the NRAS JWT before reading its verdict. | Invokes the real payload decoder on an unsigned token. The production path fetches NRAS over certificate-validated TLS, so this is defense in depth. |
| P14 | Tinfoil SDK | F4 | `tinfoil-go` resolves a current rather than merely historically signed release. | Ports release resolution against a mock proxy with placeholder bundle bodies. Requires control of the release-distribution proxy; freshness-witness remediation is planned. |
| P15 | EphemeralML / AIR | F9 | AIR distinguishes user input from retrieved or operator-provided context. | Uses the real AIR builder and verifier with two opaque request hashes; establishes a receipt-format limitation without executing a RAG service or Nitro enclave. |
| P16 | NEAR AI Cloud | F9 | Signed text distinguishes user messages from gateway-supplied history. | Reproduces the published signed-text check. A client comparing the exact body it sent detects modification; the format itself does not identify component provenance. |
| P17 | EphemeralML / AIR | F3 | `AirVerifyPolicy::default()` pins expected model identity before returning `verified`. | Calls the real verifier on receipts with different model identifiers. Both pass under `default()` and diverge under a pinned policy. Strict policy support shipped. |
| P18 | A3S/Power | F3 | The documented `verify_report` path necessarily authenticates the hardware signature. | Calls the real verifier with a fabricated report and `hardware_verifier=None`; it returns success with `hardware_verified=false`. A caller can detect the partial result by inspecting that field. Maintainer committed fail-closed production behavior. |

## Evidence conventions

- **Concrete attack:** the dishonest provider changes a relied-on execution
  property while the evaluated verification path accepts.
- **Under-enforcement:** the relevant implementation computes or exposes a
  check but its caller or default path does not enforce failure.
- **Format/API boundary:** the witness demonstrates what a schema or low-level
  API can and cannot establish; it does not imply that a deployed platform
  violated an explicit guarantee.

These terms describe experimental scope, not a severity ordering.

