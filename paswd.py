import re


COMMON_PASSWORDS_FILEPATH = './data/common100Kpass.txt'


def load_passwords_from_file(filepath):
    passwords = list()
    with open(filepath) as file:
        for line in file:
            passwords.append(line.strip())
    return passwords


COMMON_PASSWORDS = load_passwords_from_file(COMMON_PASSWORDS_FILEPATH)


def ensure_hard(pwd):
    password_re =  re.compile(r'''(
        ^(?=.*[A-Z].*[A-Z])                # at least two capital letters
        (?=.*[!@#$&*])                     # at least one of these special c-er
        (?=.*[0-9].*[0-9])                 # at least two numeric digits
        (?=.*[a-z].*[a-z].*[a-z])          # at least three lower case letters
        .{8,}                              # at least 8 total digits
        $
        )''', re.VERBOSE)
    
    if not password_re.search(pwd):
        return False
    return True


def ensure_not_common(pwd):
    return pwd not in COMMON_PASSWORDS