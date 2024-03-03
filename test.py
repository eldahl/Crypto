import hashlib, hmac, binascii


msg = b'I got my boots on'
mac = hmac.new(b'key', msg, hashlib.sha256).digest()

print(msg)
print(binascii.hexlify(mac))
