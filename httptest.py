import sys
import json
import requests
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5 as PKCS1_signature
from Crypto.Hash import SHA1

def get_key(key_file):
    with open(key_file) as f:
        data = f.read()
        key = RSA.importKey(data)
    return key

def get_params(argv):
    params = {}
    for arg in argv:
        params[arg.split("=")[0]] = arg.split("=")[1]
    params["sign"] = ""

    data = json.dumps(params)
    hashdata = SHA1.new()
    hashdata.update(data.encode("utf8"))

    private_key = get_key('files/private.pem')
    signer = PKCS1_signature.new(private_key)
    params["sign"] = signer.sign(hashdata)
    print(params)


if __name__ == '__main__':
    url = sys.argv[2]
    resp = requests.Response
<<<<<<< HEAD
    if sys.argv[1] == "get":
        resp = requests.get(url)
        print(resp)
        print(resp.text)
    if sys.argv[2] == "post":
=======
    if sys.argv[1] == "GET":
        resp = requests.get(url)
        print(resp)
        print(resp.text)
    if sys.argv[1] == "POST":
>>>>>>> 0ae600c58a4bef1d1a5c84aa4d2f446a9ddf5999
        resp = requests.post(url, get_params(sys.argv[3:]))
        print(resp)
        print(resp.text)
