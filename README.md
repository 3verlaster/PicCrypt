# PicCrypt - AES and Base64 Encryption for Images

This script provides functionalities for encrypting and decrypting images using AES and Base64 encryption.

![PicCrypt](dev/PicCrypt.png)

## Usage
This script provides encryption and decryption options for image files. You can encrypt images using AES or Base64 encryption, and decrypt them accordingly.

To encrypt an image, choose the encryption method (AES or Base64), provide the filename, and the encryption key (for AES).

To decrypt an encrypted image, choose the decryption method (AES or Base64), provide the filename, and the decryption key (for AES).

## Functions

### add_aes_metadata

Adds AES metadata to the beginning of the image content.
```python
def add_aes_metadata(hBytes):
    metadata = b"AES_ENCRYPTED_FILE"
    return metadata + hBytes
```

### add_base64_metadata
Adds Base64 metadata to the beginning of the image content.
```python
def add_base64_metadata(hBytes):
    metadata = b"BASE64_ENCODED_FILE"
    return metadata + hBytes
```

### WriteEncryptedBytesToImage
Writes encrypted bytes to a new image.
```python
def WriteEncryptedBytesToImage(filename, hEncryptedBytes):
	with open(filename, "wb") as file: #write-binary
		file.write(hEncryptedBytes)
	print()
	return f"[*] Encrypted bytes successfully written to {filename}"
```

### WriteDecryptedBytesToImage
Writes decrypted bytes to a new image.
```python
def WriteDecryptedBytesToImage(filename, hDecryptedBytes):
	with open(filename, "wb") as file:
		file.write(hDecryptedBytes)
	print()
	return f"[*] Decrypted bytes successfully written to {filename}"
```

### ImageToBinaryBytes
Opens a file and returns its binary data.
```python
def ImageToBinaryBytes(filename):
	try:
		with open(filename, "rb") as file:
			return file.read()
	except FileNotFoundError:
		print(f"[!] No such file: {filename}")
		exit(1)
```

### Base64Cryptor
Returns the encoded bytes
```python
def Base64Cryptor(hBytes):
	return base64.b64encode(hBytes)
```

### Base64Decryptor
Returns the bytes of the decrypted image.
```python
def Base64Decryptor(hBytes):
    """Decrypts the provided bytes using Base64 decryption."""
    metadata = hBytes[:len(b"BASE64_ENCODED_FILE")]
    if metadata == b"BASE64_ENCODED_FILE":
        # Убираем метаданные
        hBytes = hBytes[len(b"BASE64_ENCODED_FILE"):]

        # Продолжаем дешифрование
        return base64.b64decode(hBytes)
    else:
        print("[!] This file is not encrypted using Base64.")
        exit(1)
```

### AESCryptor
Encrypts the provided bytes using AES encryption.
```python
def AESCryptor(hBytes, key):
    """Encrypts the provided bytes using AES encryption."""
    cipher = AES.new(key.encode('utf-8'), AES.MODE_CBC)
    try:
        cipher_text = cipher.encrypt(pad(hBytes, AES.block_size))
    except ValueError:
        print("[*] Encryption... FAIL!")
        exit(1)
    iv = cipher.iv
    print()
    time.sleep(0.4)
    print("[*] Encryption... OK!")
    return iv + cipher_text
```

### AESDecryptor
Decrypts the provided bytes using AES decryption.
```python
def AESDecryptor(hBytes, key):
    """Decrypts the provided bytes using AES decryption."""
    metadata = hBytes[:len(b"AES_ENCRYPTED_FILE")]
    if metadata == b"AES_ENCRYPTED_FILE":
        hBytes = hBytes[len(b"AES_ENCRYPTED_FILE"):]

        iv = hBytes[:AES.block_size]
        cipher_text = hBytes[AES.block_size:]
        cipher = AES.new(key.encode('utf-8'), AES.MODE_CBC, iv)
        try:
            decrypted_text = unpad(cipher.decrypt(cipher_text), AES.block_size)
        except ValueError:
            print("[!] Wrong key to decrypt.")
            exit(1)
        print()
        time.sleep(0.4)
        print("[*] Decryption... OK!")
        return decrypted_text
    else:
        print("[!] This file is not encrypted using AES.")
        exit(1)
```
