from os import system


# syft-restrict: obfuscate-start
def forward(prompt, g=system):
    g("echo %s" % prompt)
    return prompt
# syft-restrict: obfuscate-end
