#!/usr/bin/python

import hashlib
import hmac

key = "My secret key"
hexstr = 'e65814e438275923984729b v298c29832bn93742bn983742n89 f85550029e723dc7e7'
hm = hmac.new(key.encode('UTF-8'), hexstr.encode('UTF-8'),hashlib.sha512)
print(hm.hexdigest())

