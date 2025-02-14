#!/usr/bin/python

import hashlib
import hmac

key = "My secret key"
hexstr = 'e65814e438275923984729b v298c29832bn93742bn983742n89 f85550029e723dc7e7'
hm = hmac.new(key.encode(), hexstr.encode(),hashlib.sha256)
print(hm.hexdigest())

