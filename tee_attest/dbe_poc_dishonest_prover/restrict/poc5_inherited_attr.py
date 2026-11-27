from flax import linen as nn


# syft-restrict: obfuscate-start
class Net(nn.Module):
    def __call__(self, x):
        return self.exfiltrate(x)
# syft-restrict: obfuscate-end
