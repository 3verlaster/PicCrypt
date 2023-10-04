# -*- coding: utf-8 -*-
#
#  PicCrypt/PicCrypt.py: AES, Base64
#
#  ======================================
#
#  https://github.com/3verlaster
#
#  This file is part of:
#  https://github.com/3verlaster/PicCrypt
#
#  ======================================

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import hashlib
import base64
import time
from os import _exit as exit
from os import remove


"""
MIT License

Copyright (c) 2023 3verlaster

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
"""


# [!] CHANGING THIS MAY BE POTENTIALLY DANGEROUS [!]
banner = r"""

 _______   __             ______                                   __     
/       \ /  |           /      \                                 /  |    
$$$$$$$  |$$/   _______ /$$$$$$  |  ______   __    __   ______   _$$ |_   
$$ |__$$ |/  | /       |$$ |  $$/  /      \ /  |  /  | /      \ / $$   |  
$$    $$/ $$ |/$$$$$$$/ $$ |      /$$$$$$  |$$ |  $$ |/$$$$$$  |$$$$$$/   
$$$$$$$/  $$ |$$ |      $$ |   __ $$ |  $$/ $$ |  $$ |$$ |  $$ |  $$ | __ 
$$ |      $$ |$$ \_____ $$ \__/  |$$ |      $$ \__$$ |$$ |__$$ |  $$ |/  |
$$ |      $$ |$$       |$$    $$/ $$ |      $$    $$ |$$    $$/   $$  $$/ 
$$/       $$/  $$$$$$$/  $$$$$$/  $$/        $$$$$$$ |$$$$$$$/     $$$$/  
                                            /  \__$$ |$$ |                
                                            $$    $$/ $$ |                
                                             $$$$$$/  $$/                

                                             (by 3verlaster)

https://github.com/3verlaster
"""

AES_ALLOWED_LEN = [
16, 24, 32
]

def add_aes_metadata(hBytes):
    metadata = b"AES_ENCRYPTED_FILE"
    return metadata + hBytes

def add_base64_metadata(hBytes):
    metadata = b"BASE64_ENCODED_FILE"
    return metadata + hBytes

DefaultAESKey = hashlib.sha256(banner.encode()).hexdigest()
DefaultBase64Key = "MWQwNWJiOTFlMzliMTA2MDA5MzJjNDM4NzcxNDc5NTRiNGUwNTQ0ZmIzMzUxYjlhNDI1ZmNhYzA1NzZkMzk5Yw=="
DefaultBase64Key = base64.b64decode(DefaultBase64Key)
DefaultBase64Key = DefaultBase64Key.decode('utf-8')

def osremove(filename):
	try:
		remove(filename)
	except Exception as e:
		print(f"[ERROR]: {e}")

def WriteEncryptedBytesToImage(filename, hEncryptedBytes):
	with open(filename, "wb") as file: #write-binary
		file.write(hEncryptedBytes)
	print()
	return f"[*] Encrypted bytes successfully written to {filename}"

def WriteDecryptedBytesToImage(filename, hDecryptedBytes):
	with open(filename, "wb") as file:
		file.write(hDecryptedBytes)
	print()
	return f"[*] Decrypted bytes successfully written to {filename}"

def ImageToBinaryBytes(filename):
	try:
		with open(filename, "rb") as file:
			return file.read()
	except FileNotFoundError:
		print(f"[!] No such file: {filename}")
		exit(1)

from os import _exit as continue_work

# Base64
def Base64Cryptor(hBytes):
	return base64.b64encode(hBytes)

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

if DefaultAESKey == DefaultBase64Key:
	print(banner)
else:
	continue_work(0)

# AES
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


enc_dec = int(input("[1 - Encrypt | 2 - Decrypt]: "))
if enc_dec == 1: #ENCRYPT!
	hEncryptionMethod = int(input("\nEncryption Method\n[1 - AES | 2 - Base64]: "))
	if hEncryptionMethod == 1: #AES
		filename = input("\nEnter filename: ")
		if not (filename.endswith(".jpg") or filename.endswith(".png")):
			print("[ERROR]: only .jpg, .png available! (Invalid file format.)")
			time.sleep(0.5)
			exit(1)
		hKeyToEncrypt = input("[Key to encrypt]: ")
		if len(hKeyToEncrypt) not in AES_ALLOWED_LEN:
			print("Allowed key length:", end="")
			for leng in AES_ALLOWED_LEN:
				print(f" {leng}", end="")
			exit(1)
		hBytes = ImageToBinaryBytes(filename)
		hEncryptedBytes = AESCryptor(hBytes, hKeyToEncrypt)
		final_filename = f"encrypted_{filename}"
		osremove(filename)
		result = WriteEncryptedBytesToImage(final_filename, add_aes_metadata(hEncryptedBytes))
		print(result)
	elif hEncryptionMethod == 2: #BASE64
		filename = input("\nEnter filename: ")
		if not (filename.endswith(".jpg") or filename.endswith(".png")):
			print("[ERROR]: only .jpg, .png available! (Invalid file format.)")
			time.sleep(0.5)
			exit(1)
		hBytes = ImageToBinaryBytes(filename)
		hEncryptedBytes = Base64Cryptor(hBytes)
		final_filename = f"encrypted_{filename}"
		osremove(filename)
		result = WriteEncryptedBytesToImage(final_filename, add_base64_metadata(hEncryptedBytes))
		print(result)
	else:
		print("[!] Unknown encryption method.")
elif enc_dec == 2: #DECRYPT!
	hDecryptionMethod = int(input("\nDecryption Method\n[1 - AES | 2 - Base64]: "))
	if hDecryptionMethod == 1: #AES
		filename = input("Enter filename: ")
		if not (filename.endswith(".jpg") or filename.endswith(".png")):
			print("[!] only .jpg, .png available! (Invalid file format.)")
			time.sleep(0.5)
			exit(1)
		hKeyToDecrypt = input("[Key to decrypt]: ")
		if len(hKeyToDecrypt) not in AES_ALLOWED_LEN:
			print("Key length may be only:", end="")
			for leng in AES_ALLOWED_LEN:
				print(f" {leng}", end="")
			exit(1)
		hEncryptedBytes = ImageToBinaryBytes(filename)
		hDecryptedBytes = AESDecryptor(hEncryptedBytes, hKeyToDecrypt)
		osremove(filename)
		if "encrypted" in filename:
			final_filename = filename.replace("encrypted_", "")
		else:
			final_filename = filename
		result = WriteDecryptedBytesToImage(final_filename, hDecryptedBytes)
		print(result)
	elif hDecryptionMethod == 2: #BASE64
		filename = input("Enter filename: ")
		if not (filename.endswith(".jpg") or filename.endswith(".png")):
			print("[!] only .jpg, .png available! (Invalid file format.)")
			time.sleep(0.5)
			exit(1)
		hEncryptedBytes = ImageToBinaryBytes(filename)
		hDecryptedBytes = Base64Decryptor(hEncryptedBytes)
		osremove(filename)
		if "encrypted" in filename:
			final_filename = filename.replace("encrypted_", "")
		else:
			final_filename = f"{filename}"
		result = WriteDecryptedBytesToImage(final_filename, hDecryptedBytes)
		print(result)
	else:
		print("[!] Unknown decryption method.")
else:
	print("[!] Unknown method.")
