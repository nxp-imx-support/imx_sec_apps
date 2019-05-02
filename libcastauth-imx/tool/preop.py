#!/usr/bin/env python

__copyright__ = "copyright 2019 NXP"
__license__ = "BSD-2-Clause"

# Unwrap the model private key and copy it to path defined by argv[1]

from Crypto.PublicKey import ECC
from Crypto.Hash import SHA256
from Crypto.Cipher import AES
import sys
import base64

MP_PUBKEY_PATH = "./mp.pem"
MODEL_KEY_PATH = "./model.key.bin"
DEVICE_ID = ""
  
if __name__ == '__main__':
    if len(sys.argv) < 2:
        sys.exit("Usage: "+sys.argv[0] + " </path/to/unwrapped/key>")
    try:
        # Derive a Data Encryption Key from MP public key
        fmp_key = open(MP_PUBKEY_PATH,'rt')
        mp_key =  ECC.import_key(fmp_key.read())
        bmp_key = mp_key.pointQ.x.to_bytes() + mp_key.pointQ.y.to_bytes()
        dek = SHA256.SHA256Hash(bmp_key + DEVICE_ID).hexdigest()
        fmp_key.close()

        # Read model key
        fmodel_key = open(MODEL_KEY_PATH,'rt')
        model_key = map(base64.b64decode, fmodel_key.read().split("\n"))
        fmodel_key.close()

        nonce = model_key[0]
        hdr = model_key[1]
        ciphertext = model_key[2]
        mac = model_key[3]

        cipher = AES.new(dek.decode("hex"), AES.MODE_CCM, nonce)
        cipher.update(hdr)
        k_out = cipher.decrypt(ciphertext)
        try:
            cipher.verify(mac)
            #print "The message is authentic: hdr=%s" % (hdr)
        except ValueError:
            sys.exit("Key incorrect or message corrupted")
          
                  
        # Write plain key    
        fk_plain = open(sys.argv[1], "wb")
        fk_plain.write(k_out)
        fk_plain.close() 
    except Exception, e:
        sys.exit(str(e))   