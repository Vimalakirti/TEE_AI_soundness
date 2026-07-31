Hi Zhixiao,

Thank you for confirming receipt and for the detailed response. We appreciate your careful review of the report and are glad to hear that the issues are being treated as soundness-relevant.
Your remediation plan sounds well aligned with the concerns we raised, especially the fail-closed production behavior, mandatory hardware verification, clearer model-digest semantics, simulated-attestation rejection, and explicit binding between CPU TEE evidence and NVIDIA GPU confidential-computing evidence.
Thank you as well for the clarification on NVIDIA GPU support. We will describe NVIDIA GPU acceleration, including confidential-computing-capable GPU environments, as an intended production target for A3S Power, and we will present the CPU/GPU binding as an agreed hardening item rather than as a gap in the intended design.
Opening a private GitHub Security Advisory would be useful for coordinating patch review and keeping the technical discussion organized. Please feel free to invite me there. We would be happy to review the proposed fixes and documentation changes.
We also appreciate the opportunity to share the A3S/Power-related technical description with you before publication for factual review. Our intent is to accurately describe the current implementation and threat model, incorporate corrections where we have misunderstood anything, and acknowledge your response and remediation work appropriately. We will also distinguish the behavior we reviewed at commit 7bbaebee from the fixed state where applicable. To avoid ambiguity, our current publication target remains around August 6, 2026.
Please let us know when you have a concrete patch or documentation plan ready for review, and whether there are any specific deployment assumptions or verifier API expectations that you would like us to take into account when describing the findings.
Thanks again for engaging constructively and responsibly.

Best,
Bing-Jyue
