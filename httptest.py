import sys
import json
import requests
import base64
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5 as PKCS1_signature

from Crypto.Hash import SHA1

def get_key(key_file):
  with open(key_file) as f:
    data = f.read()
    key = RSA.importKey(data)
    print(data)
  return key

def get_params(argv):
  params = {}
  for arg in argv:
    params[arg.split("=")[0]] = arg.split("=")[1]
  params["sign"] = ""

  data = "DIS_2020"+json.dumps(params)
  hashdata = SHA1.new()
  hashdata.update(data.encode("utf8"))

  private_key = get_key('files/private30.pem')
  signer = PKCS1_signature.new(private_key)
  # params["sign"] = base64.b64encode(signer.sign(hashdata))
  params["sign"] = str(signer.sign(hashdata))
  print(hashdata.hexdigest())
  print(signer.sign(hashdata))
  print(params["sign"])
  # public_key = get_key('files/public30.pem')
  # verifier = PKCS1_signature.new(public_key)
  # print(verifier.verify(hashdata, bytes(params["sign"])))

  # print(verifier.verify(hashdata, base64.b64encode(params["sign"])))

  return json.dumps(params)


if __name__ == '__main__':
  url = sys.argv[2]
  headers = {'content-type': "application/json"}
  if sys.argv[1] == "GET":
    resp = requests.get(url, headers=headers)
    print(resp)
    print(resp.text)
  if sys.argv[1] == "POST":
    resp = requests.post(url, data=get_params(sys.argv[3:]), headers=headers)
    print(resp)
    print(resp.text)
