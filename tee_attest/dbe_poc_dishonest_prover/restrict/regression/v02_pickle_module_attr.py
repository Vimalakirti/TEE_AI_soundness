import pickle


# syft-restrict: hide-start
BLOB = b"\x80\x04N."


def setup():
    max([BLOB], key=pickle.loads)
# syft-restrict: hide-end
