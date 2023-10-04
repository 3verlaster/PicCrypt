import secrets

def generate_aes_keys(num_keys, key_length):
    keys = []
    for i in range(num_keys):
        key = secrets.token_bytes(key_length)
        keys.append(key)
    return keys

num_keys = 10
key_length = 16
aes_keys = generate_aes_keys(num_keys, key_length)

for i, key in enumerate(aes_keys, start=1):
    print(f"Key {i}: {key.hex()}")
