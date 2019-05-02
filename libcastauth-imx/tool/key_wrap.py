#!/usr/bin/env python

__copyright__ = "copyright 2019 NXP"
__license__ = "BSD-2-Clause"


from Crypto.PublicKey import ECC
from Crypto.Hash import SHA256
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import sys
import base64

MP_PUBKEY_PATH = "./mp.pem"
DEVICE_ID = ""
try:
    if len(sys.argv) < 3:
        sys.exit("Usage: "+sys.argv[0] + " </path/to/plain/key> </path/to/enc/key>")

    # Read Plain key
    fk_plain = open(sys.argv[1], "rb")
    k_plain = fk_plain.read()
    fk_plain.close()

    # Derive a Data Encryption Key from MP public key
    fmp_key = open(MP_PUBKEY_PATH,'rt')
    mp_key =  ECC.import_key(fmp_key.read())
    bmp_key = mp_key.pointQ.x.to_bytes() + mp_key.pointQ.y.to_bytes()
    print "MP key: "+bmp_key.encode("hex")
    dek = SHA256.SHA256Hash(bmp_key + DEVICE_ID).hexdigest()
    print "DEK: "+dek
    fmp_key.close()
        
    # Encrypt a plain key using AES-CCM
    # Key is derived from MP pubkey    
    key = dek.decode("hex")
    k_out = ""
    nonce = get_random_bytes(11)    
    cipher = AES.new(key, AES.MODE_CCM, nonce)
    hdr = b'-----BEGIN RSA PRIVATE KEY-----'
    cipher.update(hdr)
    k_enc = cipher.encrypt(k_plain)
    k_out += base64.b64encode(nonce) + "\n"
    k_out += base64.b64encode(hdr) + "\n"
    k_out += base64.b64encode(k_enc) + "\n"
    k_out += base64.b64encode(cipher.digest()) + "\n"
                  
    # Write encrypted key    
    fk_enc = open(sys.argv[2], "wb")
    fk_enc.write(k_out)
    fk_enc.close()
    
except Exception, e:
    sys.exit(str(e))