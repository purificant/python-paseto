from paseto.protocol.version2 import Version2

message = b"foo"  # your data
key = b"0" * 32  # encryption key

token = Version2.encrypt(message, key)
plain_text = Version2.decrypt(token, key)

assert plain_text == message
print("token={}".format(token))
print("plain_text={}".format(plain_text))
print("message={}".format(message))
