#!/usr/bin/env python

__copyright__ = "copyright 2019 NXP"
__license__ = "BSD-2-Clause"

'''
The output key is not the final device key.
This is used to securely provision the device with its key.
On first boot the encrypted key will be decrypted then transformed
to a black key then a black blob. The resulting black blob is 
the final device key.   
'''

from Crypto.PublicKey import ECC
from Crypto.Hash import SHA256
from Crypto.Cipher import AES
import sys
import base64

MP_PUBKEY_PATH = "./mp.pem"
DEVICE_ID = ""

DEVICE_CERT_PATH = "./client.crt"
DEVICE_KEY_PATH = "./client.key"

try:
    if len(sys.argv) < 3:
        sys.exit("Usage: "+sys.argv[0] + " </path/to/cert> </path/to/key>")
                 
    # Write Cert    
    fcert = open(DEVICE_CERT_PATH, "wb")
    fcert.write(open(sys.argv[1]).read())
    fcert.close()
    
    # Read Plain key
    fk_plain = open(sys.argv[2], "rb")
    k_plain = fk_plain.read()
    fk_plain.close()
    
    # Wrap key
    # Derive a Data Encryption Key from MP public key
    fmp_key = open(MP_PUBKEY_PATH,'rt')
    mp_key =  ECC.import_key(fmp_key.read())
    bmp_key = mp_key.pointQ.x.to_bytes() + mp_key.pointQ.y.to_bytes()
    dek = SHA256.SHA256Hash(bmp_key + DEVICE_ID).hexdigest()
    fmp_key.close()

    # Encrypt a plain key using AES-CCM
    # Key is derived from MP pubkey    
    key = dek.decode("hex")
    k_out = ""
    cipher = AES.new(key, AES.MODE_CCM)
    hdr = b'-----BEGIN RSA PRIVATE KEY-----'
    cipher.update(hdr)
    k_enc = cipher.encrypt(k_plain)
    k_out += base64.b64encode(cipher.nonce) + "\n"
    k_out += base64.b64encode(hdr) + "\n"
    k_out += base64.b64encode(k_enc) + "\n"
    k_out += base64.b64encode(cipher.digest()) + "\n"    
    
    fkey = open(DEVICE_KEY_PATH, "wb")
    fkey.write(k_out)
    fkey.close()    
    
except Exception, e:
    sys.exit(str(e))