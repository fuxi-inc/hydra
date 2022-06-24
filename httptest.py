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
  print(json.dumps(params).encode("utf8").hex())

  data = "DIS_2020"
  for key in params.keys():
    data += params[key]
  print(data)
  print(data.encode("utf-8").hex())
  hashdata = SHA1.new()
  hashdata.update(data.encode("utf-8"))
  print(hashdata.hexdigest())


  testdata = str(json.dumps(params))
  hashtestdata = SHA1.new()
  hashtestdata.update(testdata.encode("utf8"))
  print(hashtestdata.hexdigest())

  private_key = get_key('files/private30.pem')
  signer = PKCS1_signature.new(private_key)
  params["sign"] = signer.sign(hashdata).hex()
  print(params["sign"])
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
