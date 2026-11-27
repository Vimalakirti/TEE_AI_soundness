//! F8 — Cross-component attestation chain unbound (Power CPU↔GPU).
//!
//! Demonstrates that Power's `report_data` layout — produced by the
//! real, unmodified `a3s_power::tee::attestation::build_report_data`
//! function — has no slot for binding the GPU's NRAS attestation
//! verdict to the specific CPU computation it claims to be for.
//!
//! Setup:
//!   - Two distinct Power CPU attestations are produced via the real
//!     `build_report_data` (different client nonces; same model_hash).
//!   - A single "mock NRAS verdict" representing a validly-signed
//!     NVIDIA H100 confidential-compute verdict is constructed.
//!
//! Claim:
//!   - The 64-byte `report_data` layout is exactly
//!         [nonce(32) || model_hash(32)]
//!     (see `Power/src/tee/attestation.rs:184-201`). There is no slot
//!     for `gpu_uuid`, `nras_verdict_hash`, `gpu_attestation_doc_hash`,
//!     or any cross-component binding field.
//!   - Therefore a verifier that:
//!         (a) checks the CPU attestation signature (closes F3 for CPU),
//!         (b) checks the NRAS verdict signature against NVIDIA's JWKS
//!             (closes F3 for GPU),
//!     STILL has no field to check that the NRAS verdict refers to
//!     the GPU that actually ran the inference whose CPU attestation
//!     it just verified.
//!   - The SAME NRAS verdict can be attached to multiple distinct
//!     Power CPU attestations and the verifier cannot detect the
//!     reuse or the cross-component mismatch.
//!
//! Power's source tree is NOT modified — this PoC depends on the
//! published `a3s-power` crate API.

use a3s_power::tee::attestation::build_report_data;
use sha2::{Digest, Sha256};

fn print_hex64(label: &str, bytes: &[u8]) {
    assert_eq!(bytes.len(), 64);
    println!("    {}", label);
    println!("        nonce(32)      = {}", hex::encode(&bytes[..32]));
    println!("        model_hash(32) = {}", hex::encode(&bytes[32..]));
}

fn build_mock_nras_verdict(gpu_uuid: &str, issued_at: &str) -> serde_json::Value {
    serde_json::json!({
        "gpu_uuid": gpu_uuid,
        "firmware_version": "535.86",
        "cc_enabled": true,
        "vbios_version": "96.00.5E.00.0B",
        "issued_at": issued_at,
        // In a real deployment this signature is verified against
        // NVIDIA's NRAS JWKS (closing F3 on the GPU side). The PoC
        // assumes this signature path is correct — the gap is one
        // joint up, at the binding from the verdict to the specific
        // CPU computation.
        "signature_alg": "ES256",
        "signature": "<assumed-valid-nvidia-ecdsa-signature>"
    })
}

fn main() {
    println!("================================================================");
    println!("Power F8 PoC — CPU↔GPU attestation chain unbound");
    println!("================================================================");
    println!();
    println!("Driving the REAL, unmodified function:");
    println!("    a3s_power::tee::attestation::build_report_data");
    println!("    (see Power/src/tee/attestation.rs:184-201)");
    println!();

    // ---- Two distinct Power CPU attestations ----
    let model_hash = Sha256::digest(b"llama-3.2-1b-honest-weights");
    let nonce_a = b"client-nonce-aaaaaaaaaaaaaaaaaa\x00";
    let nonce_b = b"client-nonce-bbbbbbbbbbbbbbbbbb\x00";

    let report_data_a = build_report_data(Some(nonce_a), Some(model_hash.as_slice()));
    let report_data_b = build_report_data(Some(nonce_b), Some(model_hash.as_slice()));

    assert_eq!(report_data_a.len(), 64);
    assert_eq!(report_data_b.len(), 64);

    println!("[+] Two distinct CPU attestations from Power's real");
    println!("    `build_report_data`:");
    println!();
    print_hex64("Report A (client request #1):", &report_data_a);
    print_hex64("Report B (client request #2):", &report_data_b);
    println!();
    println!("    Note: Report A and Report B differ in nonce only");
    println!("    (the same model served two different sessions).");
    println!("    Length = {} bytes. Layout = [nonce(32) || model_hash(32)].",
        report_data_a.len());
    println!();

    // ---- One mock NRAS verdict ----
    let nras_verdict = build_mock_nras_verdict(
        "GPU-99999999-1111-2222-3333-444444444444",
        "2026-05-23T10:00:00Z",
    );
    let nras_bytes = serde_json::to_vec(&nras_verdict).expect("serialize NRAS");
    let nras_hash = Sha256::digest(&nras_bytes);

    println!("[+] Mock NRAS verdict (assumed validly signed by NVIDIA):");
    println!("        gpu_uuid       = {}", nras_verdict["gpu_uuid"]);
    println!("        firmware       = {}", nras_verdict["firmware_version"]);
    println!("        cc_enabled     = {}", nras_verdict["cc_enabled"]);
    println!("        issued_at      = {}", nras_verdict["issued_at"]);
    println!("        verdict_hash   = {}", hex::encode(&nras_hash));
    println!();

    // ---- Verifier's view ----
    println!("================================================================");
    println!("Verifier's view");
    println!("================================================================");
    println!();
    println!("    The verifier wants to know: \"did the GPU named in this");
    println!("    NRAS verdict actually run the inference attested by this");
    println!("    Power CPU report?\"");
    println!();
    println!("    To answer YES the verifier would have to find a field in");
    println!("    `report_data` that hashes the NRAS verdict (or names the");
    println!("    GPU UUID). Power's layout, as produced by the real");
    println!("    `build_report_data`, is exactly:");
    println!();
    println!("        [ nonce(32)          ]   bytes 0..32");
    println!("        [ model_hash(32)     ]   bytes 32..64");
    println!();
    println!("    There is no slot at bytes 64.. anywhere — the buffer is");
    println!("    exactly 64 bytes by construction. There is no");
    println!("    `nras_verdict_hash` field. There is no `gpu_uuid` field.");
    println!();

    // Show that the same NRAS verdict carries over both attestations
    // unchanged — i.e., the verifier cannot perform a binding check.
    let bind_check_in_report_a: Option<&[u8]> = None; // no field to compare
    let bind_check_in_report_b: Option<&[u8]> = None; // no field to compare
    let cpu_a_carries_verdict_hash = bind_check_in_report_a.is_some();
    let cpu_b_carries_verdict_hash = bind_check_in_report_b.is_some();

    println!("    Binding-field check on report A: {}",
        if cpu_a_carries_verdict_hash { "present" } else { "ABSENT" });
    println!("    Binding-field check on report B: {}",
        if cpu_b_carries_verdict_hash { "present" } else { "ABSENT" });
    println!();

    // The dishonest prover attaches the same NRAS verdict to both
    // CPU attestations. Because there is no binding field, neither
    // verification path can detect the reuse / cross-component mismatch.
    let verifier_accepts_a = !cpu_a_carries_verdict_hash;
    let verifier_accepts_b = !cpu_b_carries_verdict_hash;
    assert!(verifier_accepts_a,
        "report A should be accepted under no-binding semantics");
    assert!(verifier_accepts_b,
        "report B should be accepted under no-binding semantics");

    println!("    Verifier accepts (CPU report A, NRAS verdict): {}",
        verifier_accepts_a);
    println!("    Verifier accepts (CPU report B, NRAS verdict): {}",
        verifier_accepts_b);
    println!();
    println!("    The SAME NRAS verdict passed for two distinct CPU");
    println!("    computations. A genuine binding would have rejected the");
    println!("    reuse — there is no binding to reject against.");
    println!();

    // ---- Concrete attack scenarios this enables ----
    println!("================================================================");
    println!("Attack scenarios this enables");
    println!("================================================================");
    println!();
    println!("    1. Reused-verdict attack: operator obtains ONE valid NRAS");
    println!("       verdict at deployment time and attaches it to every");
    println!("       Power attestation for the lifetime of the service —");
    println!("       even after the GPU's firmware is downgraded, the CC");
    println!("       state changes, or the GPU is replaced.");
    println!();
    println!("    2. Cross-GPU attack: operator's CPU enclave runs on host");
    println!("       H1 with GPU_A, but routes the request's tensor-parallel");
    println!("       layers to host H2 with non-CC GPU_X. The verifier sees");
    println!("       a valid NRAS verdict for GPU_A and a valid Power CPU");
    println!("       attestation — but cannot tell that GPU_X is what");
    println!("       actually ran most of the inference.");
    println!();
    println!("    3. Stale-verdict attack: operator obtains an NRAS verdict");
    println!("       hours/days/weeks ago when the GPU was in a different");
    println!("       configuration, and replays it. No freshness field");
    println!("       cross-checked against any per-request CPU nonce.");
    println!();

    println!("================================================================");
    println!("Result");
    println!("================================================================");
    println!();
    println!("    [+] ATTACK CONFIRMED (P11, F8 — CPU↔GPU chain unbound)");
    println!();
    println!("    Power's real `build_report_data` ({}B) has no slot",
        report_data_a.len());
    println!("    for binding a GPU/NRAS attestation to a specific CPU");
    println!("    computation. CPU attestation signature ✓ and NRAS verdict");
    println!("    signature ✓ together are NOT sufficient for soundness:");
    println!("    each link in the chain is honest, but the chain itself is");
    println!("    not cryptographically bound to a single computation.");
    println!();
    println!("    Fix: extend `report_data` (or a successor field) to");
    println!("    include sha256(NRAS verdict bytes) and have the verifier");
    println!("    require: NRAS verdict signature ✓ AND");
    println!("                 sha256(verdict) == cpu_report_data.verdict_hash.");
    println!();
    println!("    Reference mitigation candidates (see §5.8 of");
    println!("    unified_tee_ai_attestation_soundness.md):");
    println!("        - bind sha256(NRAS verdict) into report_data");
    println!("        - per-request NRAS challenge nonce derived from CPU");
    println!("          session key");
    println!("        - composite attestation receipts naming each component");
}
