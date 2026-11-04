from ccdc.scanners.lse import LSEScanner


class CredentialScanner(LSEScanner):
    tests = ("fst120", "fst200", "sof000", "sof010", "sof015", "sof020", "sof170")
