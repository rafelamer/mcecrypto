#!/usr/bin/python

import hashlib

hexstr = 'e65814e438275923984729b v298c29832bn93742bn983742n89 f85550029e723dc7e7'
sha = hashlib.sha256(hexstr.encode('UTF-8'))
print(sha.hexdigest())
