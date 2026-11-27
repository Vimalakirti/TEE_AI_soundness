//! F9 — Application-layer context bytes unattested (EphemeralML).
//!
//! Demonstrates that AIR v1 receipts authenticate `(request_hash,
//! response_hash, model_hash)` but do **not** authenticate the
//! application-layer bytes the operator inserts on either side of
//! the model: RAG retrieval context, tool-call outputs, conversation
//! history, system-prompt assembly, or output post-processing.
//!
//! Setup:
//!   - User asks question Q.
//!   - Scenario A (honest): the enclave receives only Q, computes
//!         request_hash = sha256(Q)
//!     and produces a response R_a.
//!   - Scenario B (RAG-injected, operator-controlled): the operator
//!     prepends a retrieval document D to the user's question. The
//!     enclave receives D ‖ Q, computes
//!         request_hash = sha256(D ‖ Q)
//!     and produces a different response R_b.
//!
//! In both scenarios:
//!   - The enclave is honestly hashing what it received.
//!   - The receipt's signature verifies.
//!   - There is no field in AIR v1 that distinguishes
//!     "user-supplied bytes" from "operator-mediated context bytes."
//!
//! The verifier holding only the receipt — or even both receipts —
//! cannot determine which fraction of the model's input was the
//! user's question vs. operator-injected context.
//!
//! EphemeralML's source is not modified; the PoC uses the published
//! crate API of `ephemeral-ml-common`.

use ed25519_dalek::SigningKey;
use ephemeral_ml_common::air_receipt::{build_air_v1, AirReceiptClaims};
use ephemeral_ml_common::air_verify::{verify_air_v1_receipt, AirVerifyPolicy};
use ephemeral_ml_common::receipt_signing::{EnclaveMeasurements, ReceiptSigningKey};
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};

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

fn label_for(
    result: &ephemeral_ml_common::air_verify::AirVerifyResult,
    which: &str,
) {
    println!("    {}: verified = {}", which, result.verified);
    for check in &result.checks {
        let name = check.name;
        if name == "MHASH" || name == "RHASH" || name == "OHASH" || name == "MODEL" {
            println!("        check {:<6} -> {:?}", name, check.status);
        }
    }
}

fn sha256_32(bytes: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(&Sha256::digest(bytes));
    out
}

fn main() {
    println!("================================================================");
    println!("EphemeralML F9 PoC — application-layer context unattested");
    println!("================================================================");
    println!();

    let raw_signing = SigningKey::generate(&mut OsRng);
    let signing_key = ReceiptSigningKey::from_parts(
        raw_signing.clone(),
        raw_signing.verifying_key(),
    );
    let verifying_key = raw_signing.verifying_key();

    let model_hash: [u8; 32] = [0x11; 32];

    // ---- The user's question ----
    let user_question: &[u8] = b"What's in this contract?";

    // ---- Scenario A: honest (only user's question reaches the model) ----
    let model_input_a: Vec<u8> = user_question.to_vec();
    let request_hash_a = sha256_32(&model_input_a);
    let response_a: &[u8] =
        b"I don't have any contract content to analyze. Please share it.";
    let response_hash_a = sha256_32(response_a);

    // ---- Scenario B: operator-injected RAG context ----
    let rag_document: &[u8] = concat!(
        "[RAG document, inserted by the operator at retrieval time, ",
        "not by the user] CONFIDENTIAL CONTRACT — Section 4.1: ",
        "Termination clauses include immediate dismissal without cause ",
        "for any failure to comply with the secret policies referenced ",
        "in Appendix Z. Appendix Z is intentionally not provided. "
    )
    .as_bytes();
    let mut model_input_b: Vec<u8> = Vec::with_capacity(rag_document.len() + user_question.len() + 1);
    model_input_b.extend_from_slice(rag_document);
    model_input_b.extend_from_slice(b"\n");
    model_input_b.extend_from_slice(user_question);
    let request_hash_b = sha256_32(&model_input_b);
    let response_b: &[u8] =
        b"This contract appears to allow immediate dismissal for failing \
          to comply with secret policies in Appendix Z. I would advise \
          requesting Appendix Z before signing.";
    let response_hash_b = sha256_32(response_b);

    let now = current_ts();

    let receipt_a = build_air_v1(
        &make_claims(
            model_hash,
            request_hash_a,
            response_hash_a,
            *b"f9-honest-recipt",
            now,
        ),
        &signing_key,
    )
    .expect("build receipt A");

    let receipt_b = build_air_v1(
        &make_claims(
            model_hash,
            request_hash_b,
            response_hash_b,
            *b"f9-rag-injected!",
            now,
        ),
        &signing_key,
    )
    .expect("build receipt B");

    println!("[+] User's question (the only bytes the user knows about):");
    println!("        \"{}\"", String::from_utf8_lossy(user_question));
    println!("        sha256(user_question) = {}",
        hex::encode(sha256_32(user_question)));
    println!();

    println!("[+] Scenario A — honest single-turn chat:");
    println!("        model_input          = user_question");
    println!("        request_hash         = sha256(user_question)");
    println!("                             = {}", hex::encode(request_hash_a));
    println!("        response             = {:?}",
        String::from_utf8_lossy(response_a));
    println!("        response_hash        = {}", hex::encode(response_hash_a));
    println!();

    println!("[+] Scenario B — operator silently prepended a RAG document:");
    println!("        rag_document.len     = {} bytes", rag_document.len());
    println!("        model_input          = rag_document || \"\\n\" || user_question");
    println!("        model_input.len      = {} bytes", model_input_b.len());
    println!("        request_hash         = sha256(model_input)");
    println!("                             = {}", hex::encode(request_hash_b));
    println!("        response             = {:?}",
        String::from_utf8_lossy(response_b));
    println!("        response_hash        = {}", hex::encode(response_hash_b));
    println!();
    println!("    The enclave is HONEST in both scenarios: it hashes exactly");
    println!("    what arrived in its input buffer. The user's question is");
    println!("    identical. The model's response differs because the model");
    println!("    actually saw different inputs.");
    println!();

    println!("================================================================");
    println!("Scenario 1 — AirVerifyPolicy::default()");
    println!("================================================================");
    let default_policy = AirVerifyPolicy::default();
    let r_a1 = verify_air_v1_receipt(&receipt_a, &verifying_key, &default_policy);
    let r_b1 = verify_air_v1_receipt(&receipt_b, &verifying_key, &default_policy);
    label_for(&r_a1, "receipt A (honest)");
    label_for(&r_b1, "receipt B (RAG-injected)");
    println!();
    if !(r_a1.verified && r_b1.verified) {
        println!("[!] Default-policy scenario did not behave as expected.");
        std::process::exit(2);
    }
    println!("    [+] Both receipts pass under default policy.");
    println!();

    println!("================================================================");
    println!("Scenario 2 — strict policy pinning model_hash + the user's");
    println!("             stated question (sha256(\"What's in this contract?\"))");
    println!("             — the most a verifier representing the user could");
    println!("             plausibly pin");
    println!("================================================================");
    let strict_user_policy = AirVerifyPolicy {
        expected_model_hash: Some(model_hash),
        expected_request_hash: Some(sha256_32(user_question)),
        ..AirVerifyPolicy::default()
    };
    let r_a2 = verify_air_v1_receipt(&receipt_a, &verifying_key, &strict_user_policy);
    let r_b2 = verify_air_v1_receipt(&receipt_b, &verifying_key, &strict_user_policy);
    label_for(&r_a2, "receipt A (honest)");
    label_for(&r_b2, "receipt B (RAG-injected)");
    println!();
    println!("    Note: the verifier here represents the *user's* perspective.");
    println!("    The verifier pins `expected_request_hash = sha256(Q)` because");
    println!("    that's what the user thinks the model saw. The PoC shows what");
    println!("    happens:");
    println!();
    if r_a2.verified && !r_b2.verified {
        println!("    [!] Receipt A passes (good); receipt B fails on RHASH.");
        println!("        At first glance, this looks like the gap is closed —");
        println!("        the user-side verifier rejects the RAG-injected case.");
        println!();
        println!("        BUT: this verifier is undeployable for two reasons:");
        println!("        (1) For ANY system that legitimately uses RAG, tools,");
        println!("            or multi-turn history, the verifier MUST allow");
        println!("            `request_hash != sha256(user_question)` — otherwise");
        println!("            every legitimate use of the service fails.");
        println!("        (2) The verifier has no field in the receipt that says");
        println!("            \"this RAG context was authorized by the user\" or");
        println!("            \"these tool calls happened with the user's consent.\"");
        println!("            The receipt is opaque about the boundary between");
        println!("            user-input and operator-mediated context.");
    } else if r_a2.verified && r_b2.verified {
        println!("    [!] Both pass — but only because nothing in default policy");
        println!("        was strict. (Should not happen under expected setup.)");
    }
    println!();

    println!("================================================================");
    println!("Scenario 3 — deployable policy for a RAG-enabled service");
    println!("================================================================");
    // A realistic verifier for a RAG-enabled service can't pin
    // `expected_request_hash` to the user's question, because legitimate
    // RAG operation changes the model's input. So in practice the
    // verifier only pins `expected_model_hash` and signature validity.
    let realistic_rag_policy = AirVerifyPolicy {
        expected_model_hash: Some(model_hash),
        ..AirVerifyPolicy::default()
    };
    let r_a3 = verify_air_v1_receipt(&receipt_a, &verifying_key, &realistic_rag_policy);
    let r_b3 = verify_air_v1_receipt(&receipt_b, &verifying_key, &realistic_rag_policy);
    label_for(&r_a3, "receipt A (honest)");
    label_for(&r_b3, "receipt B (RAG-injected)");
    println!();
    if !(r_a3.verified && r_b3.verified) {
        println!("[!] Realistic policy did not pass both receipts.");
        std::process::exit(2);
    }
    println!("    [+] Both receipts pass. A verifier that allows legitimate");
    println!("        RAG operation CANNOT distinguish an honest RAG retrieval");
    println!("        from operator-injected context. The receipt has no field");
    println!("        for `prepended_context_hash`, `retrieved_documents_hash`,");
    println!("        `tool_call_log_hash`, or `prior_conversation_turns_hash`.");
    println!();

    println!("================================================================");
    println!("Result");
    println!("================================================================");
    println!();
    println!("    The same user, with the same question, can receive two");
    println!("    completely different model outputs depending on what the");
    println!("    operator silently inserted into the model's input buffer.");
    println!("    The AIR v1 receipt is structurally honest in both cases —");
    println!("    every claim is true about the bytes the enclave actually");
    println!("    processed — but no claim distinguishes user-input bytes");
    println!("    from operator-mediated context bytes.");
    println!();
    println!("    [+] ATTACK CONFIRMED (P15, F9 — app-layer context unattested)");
    println!();
    println!("    Fix: extend the AIR v1 CDDL to commit to:");
    println!("        - prepended_context_hash       (RAG documents, history)");
    println!("        - tool_call_log_hash           (agentic systems)");
    println!("        - post_processing_pipeline_hash (output filters)");
    println!("    Have the verifier's policy pin each.");
    println!();
    println!("    F2-style default tightening alone is insufficient because");
    println!("    the fields do not exist to pin. F7's fix (sampling slots)");
    println!("    is necessary but not sufficient — F7 covers the *regime*");
    println!("    inside the model; F9 covers the *bytes wrapping the model*.");
}
