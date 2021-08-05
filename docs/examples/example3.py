from paseto.protocol.version4 import create_symmetric_key, decrypt, encrypt

message = b"this is a secret message"  # your data
key = create_symmetric_key()  # encryption key

token = encrypt(message, key)
plain_text = decrypt(token, key)

assert plain_text == message
print(f"token={token}")
print(f"plain_text={plain_text}")
print(f"message={message}")
