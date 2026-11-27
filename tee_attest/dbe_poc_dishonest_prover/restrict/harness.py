import sys, json
import os
# Usage: harness.py <file.py> [syft-restrict dir]
# The syft-restrict package is taken from argv[2], else $RESTRICT_SRC (e.g. an unpacked PyPI
# wheel), else $PYSYFT/packages/syft-restrict/src.
SRC = (sys.argv[2] if len(sys.argv) > 2 else os.environ.get("RESTRICT_SRC")
       or os.path.join(os.environ["PYSYFT"], "packages", "syft-restrict", "src"))
sys.path.insert(0, SRC)
import syft_restrict as restrict
# exact policy from notebooks/enclave/gemma/colab-3-persona/1. DO-model-owner-gemma-restrict.ipynb
ALLOW_FUNCTIONS = [
    "jax.numpy.einsum", "jax.numpy.mean", "jax.numpy.square", "jax.numpy.arange",
    "jax.numpy.sin", "jax.numpy.cos", "jax.numpy.concatenate", "jax.numpy.tril",
    "jax.numpy.triu", "jax.numpy.ones", "jax.numpy.where", "jax.numpy.repeat",
    "jax.numpy.sqrt", "jax.numpy.transpose", "jax.numpy.array", "jax.numpy.float32",
    "jax.numpy.bool_", "jax.lax.rsqrt", "jax.nn.softmax", "jax.nn.gelu",
    "flax.linen.Module", "jax.lax", "jax.nn",
]
r = restrict.run(sys.argv[1], allow_functions=ALLOW_FUNCTIONS,
                 allow_operators=["arithmetic", "indexing", "comparison"],
                 out=sys.argv[1].replace(".py", ".obfuscated.py"), strict=False)
print("ok =", r.ok, "| calls checked =", r.certificate and r.certificate["n_calls_checked"])
for v in r.violations: print(f"  line {v.line} [{v.code}] {v.message}")
