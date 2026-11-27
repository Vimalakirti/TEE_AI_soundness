# syft-restrict: obfuscate-start
def _init(obj, n):
    pass


def _hook(obj, name):
    return name


class Leaky:
    __init__ = _init
    __getattr__ = _hook
    __reduce__ = _hook
# syft-restrict: obfuscate-end
