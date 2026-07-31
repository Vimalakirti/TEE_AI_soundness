Title: Potential soundness issues in Laminator (CODASPY ’25)
To: vasisht.duddu@uwaterloo.ca
CC: n.asokan@uwaterloo.ca, ddkang@g.illinois.edu, erl015@ucsd.edu, stephanie.q.ding@gmail.com, hpmv118@gmail.com

Dear Prof. Asokan and Vasisht,
We are a research team at UIUC and MATS studying soundness issues in TEE-based AI attestation systems. As part of this work, we reviewed Laminator (CODASPY 2025), including the implementation at github.com/ssg-research/laminator and the paper at arxiv.org/abs/2406.17548.
During our review of the implementation against Laminator’s Property-of-Training (PoT), Input/Output Attestation (IOAtt), and Accuracy Attestation (AccAtt) protocols, we identified several potential soundness gaps that we would like to disclose and discuss with you. The issue we believe is most important involves the use of torch.load on host-supplied .pth files inside the SGX enclave, which appears to allow pickle deserialization behavior during model loading. In our current understanding, this may affect the integrity of Laminator’s attestation claims.
Reviewed version: github.com/ssg-research/laminator, branch main, commit ce2d10bb dated 2025-03-06.
The main issues we would like to report are:
torch.load deserialization during model loading. At generate_attestations/main.py:291, 384, the host-supplied .pth file appears to be deserialized inside the enclave before load_state_dict() runs. In our testing, this creates a path for attacker-controlled behavior during model loading and may affect AccAtt, IOAtt, and PoT attestations.
Command-line arguments flow into the PoT payload. Because loader.insecure__use_cmdline_argv = true is enabled in main.manifest.template:17, command-line arguments appear to flow into the PoT payload without being part of the measured enclave configuration. This may allow reported metadata to diverge from what is cryptographically bound.
The model hash does not appear to bind the model architecture. The current h(M) claim appears to cover the model state dictionary but not a separate architecture specification. Depending on the loading path, this may leave room for architecture-level ambiguity.
IOAtt inputs do not appear to be bound to a secure user-to-enclave channel. Our understanding is that a dishonest prover may be able to answer inputs different from those intended by the user unless the inputs are bound to a verifier-supplied nonce or channel key.
Dataset bytes appear to be host-controlled. The datasets data/adult.data, utkface.csv, and IMDB_Dataset.csv are listed as allowed_files in main.manifest.template:69-71. The enclave hashes the bytes present at read time, so AccAtt soundness appears to rely on an external certifier publishing canonical h(D_te) mappings. We did not find complete certifier wiring in the repository; for example, scripts/verifier.py:23 appears to use a placeholder test_certifications dictionary.
Some possible mitigations we are considering include:
Replacing torch.load with safetensors loaders, or using weights_only=True with PyTorch 2.0 or later.
Either folding relevant command-line arguments into the SGX measurement, or hashing them as first-class PoT claims that the verifier must pin.
Adding h(architecture_spec) as a separate first-class claim alongside h(M).
Binding IOAtt inputs to a verifier-supplied nonce or authenticated channel key.
Our current plan is to release a blog post and arXiv preprint around August 6, 2026, which is 60 days from this email. We would like to coordinate responsibly, incorporate your feedback, and acknowledge your response in the writeup.
We would also appreciate any corrections if we have misunderstood Laminator’s intended threat model, deployment assumptions, or verifier workflow.
Please confirm receipt and let us know which channel you would prefer for further correspondence.
Best,
Bing-Jyue
UIUC

Hi Vasisht, Lachlan, Adam, and Asokan,  

Thank you, this is a thorough and fast response, and the fixes match what we'd hoped to see. Our reactions per issue: 

(1) torch.load / (2) command-line arguments. Both fixes look right to us. weights_only=True closes the deserialization path, and pinning 
oader.argv while hashing result-affecting parameters into report_data removes the unmeasured-input channel (and, as you note, the python -c vector). One confirmation: since configuration now flows through pass-through environment variables, soundness rests on the runtime report_data hashing being exhaustive — could you confirm the full set of result-affecting parameters (dataset, model_size/architecture, epochs, attestation_type, and any device-affecting flags) is hashed, so no host-supplied value can shift a payload field without changing report_data?

(3) Architecture binding. We agree this is effectively pinned, and we'd locate the guarantee slightly differently: in the reviewed code the dataset identifier selects the model class family, while the depth (e.g. CENSUS LinearNet([128]) vs LinearNet([128,256,512,256])) comes from model_size/architecture. So what disambiguates the architecture is the default-strict load_state_dict (a mismatched state-dict fails to load) combined with your fix (2) binding model_size/architecture into report_data — which is why confirming that parameter is in the hashed set (above) also closes this one.

(4) IOAtt channel binding. Agreed. With model.eval() and deterministic evaluation, binding the input bytes into the attestation lets a verifier detect input substitution by comparing the attested input hash to their intended query, so channel binding isn't required for soundness here. We'd flag two residuals only as documentation points: the verifier must recompute and check h(I) themselves (no client-side helper), and the argument relies on determinism — for non-deterministic or generative inference (e.g. the PAL*M setting) a verifier-supplied nonce would be needed to prevent output cherry-picking. We're happy to treat this as resolved for the current prototype.

(5) Host-controlled datasets. Fully agreed — the attestation binds h(D), and the certifier only links that hash to a well-known name, which a verifier can check directly for public benchmarks. We'll present this as a scoped, by-design boundary rather than a soundness gap; the only residual is the name→hash registry for private/held-out test sets, which you've reasonably left to deployment.  
So yes, your responses match our understanding: (1) and (2) are fixed, and (3)–(5) are either resolved by those fixes or are intended design boundaries. The one open thread is the confirmation about the hashed-parameter set. We'd also be glad to look at PAL*M — thank you for the pointer, and for engaging so constructively.  
Best,  
Bing-Jyue


Hi Bing-Jyue,

Thank you very much for the email, and for the detailed analysis that your group has undertaken. I am cc’ing my co-author, Lachlan Gunn, who led in the implementation as well as the response below, and open a channel for communication if needed. We have looked over the code relating to these issues, and will respond to each in turn:

torch.load deserialization during model loading. At generate_attestations/main.py:291, 384, the host-supplied .pth file appears to be deserialized inside the enclave before load_state_dict() runs. In our testing, this creates a path for attacker-controlled behavior during model loading and may affect AccAtt, IOAtt, and PoT attestations.

We agree this is a problem. Fixed in commit 2fbdab6: all three torch.load() calls in generate_attestations/main.py (lines 291, 361, 384) now pass weights_only=True, so model and input files are deserialized as plain tensors and cannot execute embedded code during loading

Command-line arguments flow into the PoT payload. Because loader.insecure__use_cmdline_argv = true is enabled in main.manifest.template:17, command-line arguments appear to flow into the PoT payload without being part of the measured enclave configuration. This may allow reported metadata to diverge from what is cryptographically bound.

We agree and have fixed it. We removed loader.insecure__use_cmdline_argv and fixed the command line in the manifest with loader.argv, so the host can no longer pass anything to the in-enclave Python (the real risk: an attacker-supplied argv could run python -c "..." inside the enclave). Config parameters are now pass-through environment variables read by main.py, and every result-affecting parameter is hashed into the quote's report_data at runtime, so reported metadata cannot diverge from what was run. Fixed in commits e7282ee and ad39588.

The model hash does not appear to bind the model architecture. The current h(M) claim appears to cover the model state dictionary but not a separate architecture specification. Depending on the loading path, this may leave room for architecture-level ambiguity.

In our script inside the TEE, the architecture is chosen according to the dataset identifier supplied to the test script, and this dataset identifier is included in the attestation.  The attestation therefore leaves no ambiguity regarding the model weights or architecture, as we understand it.

IOAtt inputs do not appear to be bound to a secure user-to-enclave channel. Our understanding is that a dishonest prover may be able to answer inputs different from those intended by the user unless the inputs are bound to a verifier-supplied nonce or channel key.

The IOAtt attestation includes both the inputs and outputs of the inference operation.  Because the model is evaluated deterministically (and thus, the same input+model will always yield the same output), this eliminates the need to use channel binding to prevent replay attacks.

Dataset bytes appear to be host-controlled. The datasets data/adult.data, utkface.csv, and IMDB_Dataset.csv are listed as allowed_files in main.manifest.template:69-71. The enclave hashes the bytes present at read time, so AccAtt soundness appears to rely on an external certifier publishing canonical h(D_te) mappings. We did not find complete certifier wiring in the repository; for example, scripts/verifier.py:23 appears to use a placeholder test_certifications dictionary.

It is intentional that datasets be host-controlled, as the same enclave must be able to handle different datasets that might evolve over time.  The soundness of AccAtt does not depend on external certifications, since the attestation covers the dataset hash.  The purpose of external certifiers is to link this dataset hash to a well-known name, but if the hash of a dataset is known, then this can be checked against the attestation directly.  Since the goal of our experiments was to validate the performance when running attested ML operations within a TEE, our effort was focussed on the attester side, rather than on associated certification infrastructure.

Do these responses match up with your understanding of the issues that you found, or have we underestimated some of them?

In addition to Laminator, we have been working on a newer framework, PAL*M, for attesting properties in generative models (https://arxiv.org/abs/2601.16199). I am cc’ing my co-author Adam who led that project in case you want to discuss further.

Warm regards,
Vasisht, Lachlan, Adam, Asokan