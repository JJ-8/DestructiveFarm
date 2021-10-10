#!/usr/bin/env python3

import random
import string
import sys
import base64
import re

flag_regex = "[a-zA-Z0-9]{31}="

if len(sys.argv) < 2:
    print("Team ip argument is missing!")

# this is the host/team ip you are going to attack
host = sys.argv[1]

def http_target(path = "", port = 80):
    return f"http://{host}:{port}{path}"

def extract_flags_from_string(string):
    return re.findall(flag_regex, string)

def print_flags_in_string(string):
    flags = extract_flags_from_string(string)
    for flag in flags:
        print(flag, flush=True)

def xor(a: bytes, b: bytes):
    return a ^ b

def xorstr(a: str, b: str):
    xored = [chr(ord(c1) ^ ord(c2)) for c1, c2 in zip(a,b)]
    return "".join(xored)

def unhex(a: str):
    # Create a bytes object from hex string then decode into utf-8 string
    return bytes.fromhex(a).decode()
    #return int(a, 16)

def enhex(a: str):
    # Convert to bytes and then use hex()
    return a.encode().hex()

def b64e(a):
    a_bytes = a.encode('utf-8')
    return base64.b64encode(a_bytes) 

def b64d(a: str):
    return base64.b64decode(a).decode()

def randomstring(amount: int):
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=amount))


    
"""
Use this for printing the flag to stdout
print(flag, flush=True)
"""

"""
HTTP requests:

sess = requests.Session()

sess.post(http_target(), data={"key": value}, timeout=10)
result = sess.get(http_target(), timeout=10)

# Get text of page:
result.text

"""

###########################
#Your exploit starts here:#
###########################

