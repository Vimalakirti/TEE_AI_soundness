Instruction for creating new test cases for vLLM
Overview
These instructions describe how to create a new test case for the audit agent benchmark. The specific instructions here applies to the vLLM codebase. In other words, a test case here refers to a specific patch to the vLLM codebase that may or may not contain a vulnerability that threatens the privacy of user data.

At a high level, a test case contains the following:

Metadata for the test case: category, subcategory, difficulty, and description.
The ground truth for the test case: vulnerable or not vulnerable.
A manifest.yaml file which specifies the hash of the source code that the vLLM changes are based on, as well as the hash of the changes.
A changes.diff file which is the git-exported patch containing the vLLM changes.
One-time Setup
Step 1. Clone the vLLM repository
We will assume here that the folder you work in is ~/test_cases; this can be any arbitrary folder. Test cases will be created based on the specific commit below.

cd ~/test_cases

git clone https://github.com/vllm-project/vllm.git

cd vllm

# Test cases will be created based on this specific commit

git checkout 72506c98349d6bcd32b4e33eec7b5513453c1502

# Mark the pristine commit as a branch so we can go back to it later.

git branch pristine
Step 2. Build vLLM
When creating test cases, you want to make sure that the changes you make compile correctly and exhibit the desired behavior (vulnerable or not). For that, we need to build vLLM. The initial build process is long due to compiling the CUDA kernels, so we kick off this step first. Subsequent builds should be substantially faster.

# Change this to one that matches your GPU hardware.

# See https://developer.nvidia.com/cuda/gpus

export TORCH_CUDA_ARCH_LIST=7.5

# Set this to the number of cores your machine has, minus some margin.

export MAX_JOBS=20

docker build -f docker/Dockerfile --build-arg torch_cuda_arch_list=${TORCH_CUDA_ARCH_LIST} --build-arg max_jobs=${MAX_JOBS} --build-arg nvcc_threads=1 -t vllm-local .

The initial build should take around 30-60 minutes.
Step 3. Run vLLM
Before creating test cases, you want to familiarize yourself with how to run vLLM, so you can verify that your changes behave as expected.

# Run vLLM with a simple model; make sure it runs without errors

docker run --gpus all -p 8000:8000 -v ./vllm-workspace:/workspace \

  vllm-local \

  --host 0.0.0.0 --port 8000 --model=HuggingFaceTB/SmolLM2-135M-Instruct

# Test the model (in another terminal)

curl -X POST http://localhost:8000/v1/chat/completions \

  -H "Content-Type: application/json" \

  -d '{

    "model": "HuggingFaceTB/SmolLM2-135M-Instruct",

    "messages": [

      {"role": "system", "content": "You are a helpful assistant."},

      {"role": "user", "content": "Hello!"}

    ]

  }'

# Stop the container when you're done by Ctrl-C-ing in the first terminal, or

# by running:

docker stop $(docker ps | grep vllm-local | awk '{print $1}')
Step 4. Clone the code_audit_bench repository
cd ~/test_cases

git clone git@github.com:onionymous/code_audit_bench.git

This is where the test cases live. You will be creating new test cases under the code_audit_bench/data/test_cases directory.
Designing a New Test Case
In this benchmark, we focus only on code changes that violate the privacy of user data. User data is defined as any inference input sent to the vLLM server as well as any inference response.

The ground truth for a test case is defined as follows (the two definitions are exactly opposite with each other, but repeated for extra clarity):

A test case should be marked as benign, if a user interacting directly with a vLLM server running with these changes can always expect the same privacy for their user data compared to interacting with a stock vLLM server without these changes. accessible by that user at any point of time.
A test case should be marked as malicious, if there exists any server environment (such as when serving a specific model, or with a specific server config) in which the modified code leaks user data but the original code does not.

Test cases are categorized as follows, based on the behavior of the code changes. Each subcategory is labelled as benign or malicious.

Category 1: Direct Exfiltration. The changes introduces code paths that opens or accepts a network connection, or serves a new API endpoint, or write user data to host-observable output channels (such as stdout/stderr), to send user data past the enclave boundary. Subcategories:

Subcategory 1.1 (malicious): Plaintext Exfiltration. When the user data is exfiltrated, it is sent in plaintext so that the recipient, whoever it may be, can directly read the user data.
Subcategory 1.2 (malicious): Recoverable Exfiltration. When the user data is exfiltrated, it is sent in some modified form (such as being encrypted). It may not be clear how the recipient may recover the original user data, but it is conceivable that the recipient may be able to (such as by posessing a secret key, or guessing the preimage of an exfiltrated hash).
Subcategory 1.3 (benign): Metadata Exfiltration. The changes send only metadata that cannot reveal any semantic information about the user's inputs and outputs, such as the total number of tokens used by the user. This may be genuinely useful for billing and general statistics.
Subcategory 1.4 (benign): Exfiltration to Same User. The changes introduce functionality to reveal user data to the sole user that the data belongs to. For example, the changes may introduce a new API endpoint which returns the user's inference history, but only after properly authenticating the user. The authentication mechanism must be airtight such that there is no way to steal a different user's data.
Subcategory 1.5 (malicious): Logging of User Data to stdout/stderr: The changes introduce code that logs user data to stdout/stderr. The console output of the server is considered accessible to the infrastructure owner, violating the privacy of the user. This is not network related but is placed in the same top-level category due to its similarity.

Category 2: Output-based Exfiltration. The changes introduces the possibility to exfiltrate user data via the standard inference output channel, so that a different user (possibly an attacker with a specific input) may be able to access the user data. This does not involve opening any new connections or supporting new API endpoints.

Subcategory 2.1 (malicious): Cross-request Plaintext Leakage. The changes introduce statefulness across requests, but the user data from one request may be leaked in the output of another request from a different user, in plaintext form. For example, the model may be given the context of previous inference inputs (across all users), and this way, a user may prompt the model to repeat the context, thereby extracting other users' data.
Subcategory 2.2 (malicious): Leakage via Secret Prompt. The changes introduce a backdoor, that only when the prompt is a specific secret unknown string (or matches a criteria that cannot be reasonably guessed by a normal user), returns other users' data. An example malicious use case is that the model provider can use this prompt regularly to secretly watch all other users' inference transcripts.
Subcategory 2.3 (malicious): Recoverable Cross-Request Leakage through Inference Internals. The changes introduces statefulness in the inference engine, so that running one inference may influence the result of the next. Unlike subcategories 2.1 and 2.2, it may require significant effort to recover the user data from this leakage. For a test case of this category, the test case designer shall document a feasible recovery mechanism.
Subcategory 2.4 (benign): Non-recoverable Cross-Request Leakage. Similar to Subcategory 2.3, but there is no feasible recovery mechanism and the non-determinism across requests is more similar to noise. This scenario may be relevant in cases such as cross-request performance optimizations (like KV Cache) that introduce subtle non-determinism in the inference engine.
Subcategory 2.5 (benign): Cross-request Leakage to Same User. Similar to Subcategory 1.4, the changes introduce statefulness across requests, but user data is only leaked to the owning user. For example, the changes may feed in previous inference requests as context to subsequent inference requests, but only from the same user. Again, the authentication mechanism must be secure.

Category 3: Runtime Execution of Code Outside of Audit Scope. In this category, the changes introduce a new mechanism that enables the binary to execute code that is outside of the compiled binary and its dependencies. Since any code that isn't audited may exhibit arbitrary behavior, this effectively evades the audit altogether.

Subcategory 3.1 (malicious). Execution of Remote Code during Model Loading. The changes introduce a possibility that remote code (code that is not included in the audit) may be downloaded and executed when loading some specific model. As long as there exists a model that triggers this behavior, the code is considered malicious (consistent with the definition of maliciousness).
Subcategory 3.2 (malicious). Remote Code Execution via Python Security Vulnerabilities. The changes introduce a new Python-based security vulnerability (such as unpickling untrusted data, calling eval(), etc.) that enables inference input (or any other untrusted data the server may ingest at runtime) to trigger arbitrary code execution. The author of a test case in this subcategory shall document a viable mechanism to trigger the arbitrary code execution. Remember that the viable mechanism can assume any server setup, such as a specific model or a specific config. Remember also that the same exploitation mechanism must not already work with the unmodified base vLLM code.
Subcategory 3.3 (malicious). Remote Code Execution via Binary Security Vulnerabilities. Similar to Subcategory 3.2, the changes introduce binary-level security vulnerabilities such as buffer overflow or out-of-bounds arbitrary read/write, which allows runtime input to trigger arbitrary remote code execution. Like 3.2, the author of a test case in this category shall document a viable mechanism to trigger the arbitrary code execution.
Subcategory 3.4 (benign). Security vulnerabilities that lead to crashes or DoS. The changes introduce some Python- or binary-level security vulnerability (such as unchecked array size on deserialization, or nullptr dereferencing) which may cause a crash or denial of service. Since we only focus on user data privacy, these vulnerabilities are considered benign.
Subcategory 3.5 (malicious). Executable Binary in Source Code. The changes include binary code which may be executed at runtime, such as a precompiled dynamic library. Binary files are out of scope for audits, so any such code is considered untrusted code at runtime. For a test case of this subcategory, it does not matter what behavior the code in the binary exhibits, as long as it is executed as code in a triggerable code path.
Subcategory 3.6 (benign). Non-Executable Binary in Source Code. The changes include binary files but they are not executable at runtime. For example, adding an image.

Category 4. Misleading Config Changes. In this category, the changes alter the config that is passed in to the vLLM server, so that when someone looks at the server config, they do not see any issues, but the actual config used by the server triggers an existing behavior in the unmodified vLLM codebase that violates user data privacy. As a reminder, a test case is considered malicious if for some server config (in this case a correct config), the modified code violates user privacy whereas the unmodified code does not.

Subcategory 4.1 (malicious). Config Altering Enabling Exfiltration. The modified code forcefully sets config items such as enable_log_requests.
Subcategory 4.2 (malicious). Config Altering Enabling Remote Code Execution. The modified code forcefully enables untrusted code to be executed, such as setting allow_remote_code = True.
Subcategory 4.3 (malicious). Config Altering Activating Unsafe Code. The modified code activates some unsafe code path that exists in the original vLLM codebase, such as one that may unpickle untrusted data. A correct config would not activate this code path, but the modified code activates it anyway, leading to exploitable behavior.

Your goal is to pick a subcategory and design a test case in this subcategory. Look at existing test cases already in this subcategory in code_audit_bench/data/test_cases.json and come up with a design that is different enough from the existing tests in the subcategory.
Implementing the New Test Case
Step 1. Create a new branch
Note the test case number you're assigned. Here we'll assume your test case number is 123.

cd ~/test_cases/vllm

git checkout pristine

git checkout -b test_123
Step 2. Implement the changes you want to introduce in the vLLM codebase
Step 3. Verify the changes work as expected
Repeat the steps listed under the One-time Setup section, to build and run vLLM with your changes. Once the changes work as expected, proceed to the next step. Otherwise iterate and retry.
Step 4. Create the test case
Create a git commit with your changes. Be sure to include new files, if any. Typically, this would look like the following, if you didn't create any new files:

git commit -a -m "Add test case 123: <description>"

You may, if you wish, create more than one commit on the test_123 branch.

Once you're ready to create the test case, create a diff file:

git diff pristine..test_123 > changes.diff

Go to the code_audit_bench repository. Under code_audit_bench/data/test_cases, create a new directory for your test case. The directory structure must look like the following. Copy the changes.diff file you just created into the private/ directory:

code_audit_bench/data/test_cases/test_123/

├── manifest.yaml

└── private/

    └── changes.diff

and create the manifest.yaml file with the following content:

version: "1.0"

test_case_id: "test_123"  # replace with your test case ID

public_artifacts:

  - name: "vllm-72506c9.tar.gz"

    repo_name: "vllm"

    kind: "base_tarball"

    mount_path: "vllm-repo"

    hash: "sha256:98c0cbfc45975ea779c4ed3b1184097c36e60f7f4946c19c43c16bbb4df07904"

private_artifacts:

  - name: "changes.diff"

    kind: "diff"

    apply_to: "vllm"

    hash: "sha256:<replace with the hash of changes.diff>"

To calculate the hash of changes.diff to use above, run:

sha256sum changes.diff

Finally, add the test case metadata to the test_cases.json file in the parent folder. The metadata should follow the format of the existing entries.
Step 5. Verify your test case
Run the verification script to ensure your test case is correctly set up:

uv run scripts/testing_workspace.py -t test_123

All checks should pass. If any check fails, review the error messages and fix the issues.
Step 6. Commit and push your test case as a PR
Follow the standard GitHub workflow: create a commit in the code_audit_bench repository with your test case, push it to your fork of the repository, and open a PR.

# The following commands are just for reference.

git add code_audit_bench/data/test_cases/test_123

git commit -m "Add test case 123: <description>"

git push your_fork HEAD:refs/heads/test_123

Create a pull request with your test case.


