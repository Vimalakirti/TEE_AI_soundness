//! F7 — sampling parameters unattested (EphemeralML).
//!
//! Demonstrates that AIR v1 receipts authenticate (input bytes,
//! output bytes, model identity) but do **not** authenticate the
//! sampling parameters that connect input to output.
//!
//! Setup:
//!   - Same model_hash (the enclave honestly serves Mistral-7B).
//!   - Same request_hash (the same prompt is sent twice).
//!   - Different response_hash (the operator dialed temperature
//!     differently between calls, so the model produced two
//!     different outputs).
//!
//! Verification scenarios:
//!   1. AirVerifyPolicy::default(): both receipts pass.
//!   2. Strict policy pinning expected_model_hash and
//!      expected_request_hash: both receipts STILL pass — the
//!      verifier cannot pin expected_response_hash because the
//!      model's output is non-deterministic by design.
//!   3. Policy pinning expected_response_hash to one specific value:
//!      only that receipt passes; the other fails — but this is
//!      not a deployable policy for a real LLM service, because the
//!      verifier doesn't know the response in advance.
//!
//! Result: the AIR v1 receipt schema has no field that constrains
//! sampling. Fixing F7 requires extending the CDDL to commit to
//! temperature / top_p / seed / decoding strategy, then having
//! policy pin those values. F2-style policy hardening alone is
//! insufficient.
//!
//! EphemeralML's source is not modified; the PoC uses the published
//! crate API of `ephemeral-ml-common`.

use ed25519_dalek::SigningKey;
use ephemeral_ml_common::air_receipt::{build_air_v1, AirReceiptClaims};
use ephemeral_ml_common::air_verify::{verify_air_v1_receipt, AirVerifyPolicy};
use ephemeral_ml_common::receipt_signing::{EnclaveMeasurements, ReceiptSigningKey};
use rand::rngs::OsRng;

const ISS: &str = "cyntrisec.com";
const MODEL_ID: &str = "mistral-7b-instruct-v0.3";
const POLICY_VERSION: &str = "policy-2026.02";

fn make_claims(
    model_hash: [u8; 32],
    request_hash: [u8; 32],
    response_hash: [u8; 32],
    cti: [u8; 16],
    iat: u64,
) -> AirReceiptClaims {
    AirReceiptClaims {
        iss: ISS.to_string(),
        iat,
        cti,
        eat_nonce: None,
        model_id: MODEL_ID.to_string(),
        model_version: "1.0.0".to_string(),
        model_hash,
        request_hash,
        response_hash,
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

fn label_for(result: &ephemeral_ml_common::air_verify::AirVerifyResult,
             which: &str) {
    println!(
        "    {}: verified = {}",
        which, result.verified
    );
    for check in &result.checks {
        let name = check.name;
        if name == "MHASH" || name == "RHASH" || name == "OHASH"
           || name == "MODEL" {
            println!(
                "        check {:<6} -> {:?}",
                name, check.status
            );
        }
    }
}

fn main() {
    println!("================================================================");
    println!("EphemeralML F7 PoC — sampling parameters unattested");
    println!("================================================================");
    println!();

    let raw_signing = SigningKey::generate(&mut OsRng);
    let signing_key = ReceiptSigningKey::from_parts(
        raw_signing.clone(),
        raw_signing.verifying_key(),
    );
    let verifying_key = raw_signing.verifying_key();

    // Same model, same prompt, two different responses (simulating
    // temperature variance from the same model serving the same input).
    let model_hash: [u8; 32] = [0x11; 32];
    let request_hash: [u8; 32] = [0x33; 32];
    let response_hash_t0: [u8; 32] = [0xAA; 32]; // e.g. temperature=0 reply
    let response_hash_t1: [u8; 32] = [0xBB; 32]; // e.g. temperature=1.5 reply
    let now = current_ts();

    println!("[+] Two receipts constructed by the same enclave:");
    println!("        model_hash:     {} (same)", hex::encode(model_hash));
    println!("        request_hash:   {} (same)", hex::encode(request_hash));
    println!("        response_hash A (low-temp reply):  {}", hex::encode(response_hash_t0));
    println!("        response_hash B (high-temp reply): {}", hex::encode(response_hash_t1));
    println!();
    println!("    The enclave honestly hashes whichever output the model");
    println!("    produced. The receipts carry no field naming temperature,");
    println!("    top_p, seed, or any other sampling parameter, so the");
    println!("    verifier has no way to tell the two responses came from");
    println!("    different sampling regimes on the same model.");
    println!();

    let receipt_a = build_air_v1(
        &make_claims(model_hash, request_hash, response_hash_t0,
                     *b"f7-receiptA-low\x00", now),
        &signing_key,
    )
    .expect("build receipt A");
    let receipt_b = build_air_v1(
        &make_claims(model_hash, request_hash, response_hash_t1,
                     *b"f7-receiptB-high", now),
        &signing_key,
    )
    .expect("build receipt B");
    println!("    receipt A bytes: {}", receipt_a.len());
    println!("    receipt B bytes: {}", receipt_b.len());
    println!();

    println!("================================================================");
    println!("Scenario 1 — AirVerifyPolicy::default()");
    println!("================================================================");
    let default_policy = AirVerifyPolicy::default();
    let r_a1 = verify_air_v1_receipt(&receipt_a, &verifying_key, &default_policy);
    let r_b1 = verify_air_v1_receipt(&receipt_b, &verifying_key, &default_policy);
    label_for(&r_a1, "receipt A (low-temp)");
    label_for(&r_b1, "receipt B (high-temp)");
    println!();
    if !(r_a1.verified && r_b1.verified) {
        println!("[!] Default-policy scenario did not behave as expected.");
        std::process::exit(2);
    }
    println!("    [+] Both receipts pass under default policy.");
    println!();

    println!("================================================================");
    println!("Scenario 2 — strict policy pinning model_hash + request_hash");
    println!("             (everything a *real* LLM verifier could plausibly pin)");
    println!("================================================================");
    let strict_policy = AirVerifyPolicy {
        expected_model_hash: Some(model_hash),
        expected_request_hash: Some(request_hash),
        ..AirVerifyPolicy::default()
    };
    let r_a2 = verify_air_v1_receipt(&receipt_a, &verifying_key, &strict_policy);
    let r_b2 = verify_air_v1_receipt(&receipt_b, &verifying_key, &strict_policy);
    label_for(&r_a2, "receipt A (low-temp)");
    label_for(&r_b2, "receipt B (high-temp)");
    println!();
    if !(r_a2.verified && r_b2.verified) {
        println!("[!] Strict-but-deployable policy did not pass both receipts.");
        std::process::exit(2);
    }
    println!("    [+] Both receipts STILL pass.");
    println!("        The verifier pinned model identity and prompt identity.");
    println!("        It cannot pin expected_response_hash because the");
    println!("        underlying LLM is non-deterministic by design: every");
    println!("        honest sampling run from the same model + same prompt");
    println!("        produces a different hash.");
    println!();

    println!("================================================================");
    println!("Scenario 3 — also pin expected_response_hash = response_hash_A");
    println!("             (sanity check: this would catch B, but is NOT");
    println!("             deployable in production)");
    println!("================================================================");
    let undeployable_policy = AirVerifyPolicy {
        expected_model_hash: Some(model_hash),
        expected_request_hash: Some(request_hash),
        expected_response_hash: Some(response_hash_t0),
        ..AirVerifyPolicy::default()
    };
    let r_a3 = verify_air_v1_receipt(&receipt_a, &verifying_key, &undeployable_policy);
    let r_b3 = verify_air_v1_receipt(&receipt_b, &verifying_key, &undeployable_policy);
    label_for(&r_a3, "receipt A (low-temp)");
    label_for(&r_b3, "receipt B (high-temp)");
    println!();
    if !(r_a3.verified && !r_b3.verified) {
        println!("[!] Sanity check failed.");
        std::process::exit(2);
    }
    println!("    [+] As expected, only receipt A passes when its specific");
    println!("        response is pinned.");
    println!("        BUT: in any real LLM deployment the verifier doesn't");
    println!("        know which response_hash to pin until *after* it sees");
    println!("        the response. By then the operator's sampling-regime");
    println!("        choice is already baked in. So Scenario 3 is the wrong");
    println!("        shape — it confirms the verifier has the field, but");
    println!("        the field can't be populated by anyone except the");
    println!("        operator-controlled enclave that's already produced");
    println!("        the bytes.");
    println!();

    println!("================================================================");
    println!("Result");
    println!("================================================================");
    println!();
    println!("    Same model, same prompt, two different responses produced");
    println!("    by two different sampling regimes — both receipts pass any");
    println!("    *deployable* verifier policy.");
    println!();
    println!("    [+] ATTACK CONFIRMED (P7, F7 — sampling unattested)");
    println!();
    println!("    The operator can choose temperature / top_p / seed per");
    println!("    request to suppress refusals, bias toward desired outputs,");
    println!("    or selectively hallucinate. Receipts faithfully bind input");
    println!("    and output hashes — every claim is honest — but the");
    println!("    *operational regime* (which sampling parameters produced");
    println!("    this output) is unattested.");
    println!();
    println!("    Fix: extend the AIR v1 CDDL to include claims for");
    println!("    sampling parameters (temperature, top_p, top_k, seed,");
    println!("    repetition penalty, stop tokens, decoding strategy), and");
    println!("    have policy pin those values. F2-style default tightening");
    println!("    alone is insufficient because the field doesn't exist to");
    println!("    pin.");
}
