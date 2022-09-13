#!/bin/env python3
import argparse
import base64
import json
from cryptography import x509
from cryptography.hazmat.primitives import serialization
import requests

ct_log_list_url = 'https://www.gstatic.com/ct/log_list/v3/log_list.json'
ct_log_list = requests.get(ct_log_list_url).json()

def split_chain(chain_path):
    ca_certs = set()
    cert = ""
    for line in open(chain_path, 'r'):
        cert += line
        if '-----END CERTIFICATE-----' in line:
            ca_certs.add(cert)
            cert = ""
    return ca_certs

def find_log_by_id(ct_log_list,log_id):
  base64ctid = base64.b64encode(ct.log_id).decode('ascii')
  for operator in ct_log_list['operators']:
    for log in operator['logs']:
      if log['log_id'] == base64ctid:
        return log

def submit_to_log(log, log_request):
    resp = requests.post(f"{log['url']}ct/v1/add-chain", data=json.dumps(log_request))
    print(resp.text)
if __name__ == "__main__":
  parser = argparse.ArgumentParser(description='Script to upload cert to CT Logs')
  parser.add_argument('--cert',type=str, help='Path to PEM cert', default='cert.pem')
  parser.add_argument('--chain',type=str, help='Path to PEM chain', default='chain.pem')
  args = parser.parse_args()

  ct_log_request = { 'chain': []}

  cert_bytes = open(args.cert, 'rb').read()
  cert = x509.load_pem_x509_certificate(cert_bytes)
  ct_log_request['chain'].append(base64.b64encode(cert.public_bytes(serialization.Encoding.DER)).decode())
  chain_pem = split_chain(args.chain)

  for ca_pem in chain_pem:
      ca = x509.load_pem_x509_certificate(str.encode(ca_pem))
      ct_log_request['chain'].append(base64.b64encode(ca.public_bytes(serialization.Encoding.DER)).decode())


  cts = cert.extensions.get_extension_for_class(x509.PrecertificateSignedCertificateTimestamps)
  for ct in cts.value:
    log = find_log_by_id(ct_log_list,ct.log_id)
    submit_to_log(log, ct_log_request)
