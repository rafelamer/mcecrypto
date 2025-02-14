#!/usr/bin/python

import hashlib


key = 'My secret key'
hexstr = 'e65814e438275923984729b v298c29832bn93742bn983742n89 f85550029e723dc7e7'
pbkdf2_hmac_key = hashlib.pbkdf2_hmac('sha512', hexstr.encode(), key.encode(), 128000, dklen=128)
print(pbkdf2_hmac_key.hex())
