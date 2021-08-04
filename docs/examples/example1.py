from paseto.protocol.version2 import decrypt, encrypt

message = b"foo"  # your data
key = b"0" * 32  # encryption key

token = encrypt(message, key)
plain_text = decrypt(token, key)

assert plain_text == message
print(f"token={token}")
print(f"plain_text={plain_text}")
print(f"message={message}")
