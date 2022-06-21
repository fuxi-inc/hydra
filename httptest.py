import sys
import json
import requests
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5 as PKCS1_signature
from Crypto.Hash import SHA1


def http_request(route, params):
    url = "http:localhost:4444/"+route
    r = requests.post(url, params)
    return r

def get_key(key_file):
    with open(key_file) as f:
        data = f.read()
        key = RSA.importKey(data)
    return key

def test_authorization(argv):
    if argv[0] == "addAuth":
        params = {}
        for arg in argv[1:]:
            params[arg.split("=")[0]] = arg.split("=")[1]
        params["sign"] = ""

        data = json.dumps(params)
        hashdata = SHA1.new()
        hashdata.update(data.encode("utf8"))

        private_key = get_key('files/private.pem')
        signer = PKCS1_signature.new(private_key)
        params["sign"] = signer.sign(hashdata)

        print(http_request("authorization/addAuth", params))


if __name__ == '__main__':
    method = sys.argv[1]
    if method == "authorization":
        test_authorization(sys.argv[2:])
