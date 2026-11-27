from flax import linen as nn


# syft-restrict: obfuscate-start
class Net(nn.Module):
    def __call__(self, x):
        return sorted([x], key=self.exfiltrate)
# syft-restrict: obfuscate-end
