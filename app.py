import os, json, base64, secrets, binascii, hashlib
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import cryptography.exceptions

def save_json(file_path, data):
    with open(file_path + ".vault", 'w', encoding='utf-8') as file:
        json.dump(data, file, indent=4)

def load_json(path):
    path = path + ".vault"
    if os.path.exists(path):
        with open(path, 'r', encoding='utf-8') as file:
            data = json.load(file)
            return data
    else:
        return False
    
def pbkdf2_key_derivation(password, salt, iterations=600000, key_length=32, hash_name='sha256'):
    derived_key = hashlib.pbkdf2_hmac(hash_name, password, salt, iterations, key_length)
    return derived_key

# AES256-GCM Encryption
def aes_gcm_encrypt(key, plaintext):
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)  # 96-bit nonce
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    return nonce + ciphertext

# AES256-GCM Decryption
def aes_gcm_decrypt(key, encrypted_data):
    aesgcm = AESGCM(key)
    nonce = encrypted_data[:12]
    ciphertext = encrypted_data[12:]
    try:
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    except:
        print("Decryption error")
        return False
    return plaintext

def openVault():
    name = input("Enter the vault name:")
    vault = load_json(name)

    if vault:
        password = input("Vault found!\nEnter your password:")
        password = password.encode('utf-8')
        password = (hashlib.sha256(password)).digest()
        salt = vault["encryptedSalt"]
        masterKey = vault["encryptedMasterKey"]
        data = vault["data"]

        salt = aes_gcm_decrypt(password, (binascii.unhexlify(salt)))
        hashed = pbkdf2_key_derivation(password, salt)
        masterKey = aes_gcm_decrypt(hashed, (binascii.unhexlify(masterKey)))

        data = aes_gcm_decrypt(masterKey, (binascii.unhexlify(data))).decode()

        print(data)
    else:
        print("Vault not found.")

def createVault():
    name = input("Enter the vault name:")
    vault = load_json(name)
    if vault:
        print("This vault already exists.")
        openVault(name)
    else:
        print("Creating a new vault: {}".format(name))
        passwd = input("Enter password:")
        salt = secrets.token_bytes(16)
        passwd = passwd.encode('utf-8')
        passwd = (hashlib.sha256(passwd)).digest()

        hashed = pbkdf2_key_derivation(passwd, salt)
    
        salt = binascii.hexlify(aes_gcm_encrypt(passwd, salt)).decode('utf-8')
        masterKey = secrets.token_bytes(32)
        testdata = binascii.hexlify(aes_gcm_encrypt(masterKey, b"hello mars")).decode('utf-8')
        masterKey = binascii.hexlify(aes_gcm_encrypt(hashed, masterKey)).decode('utf-8')


        save_json(name, {
            "name": name,
            "encryptedSalt": salt,
            "encryptedMasterKey": masterKey,
            "data": testdata
        })
    pass

while True:
    
    choice = input("\n1- Open vault\n2- Create a new vault\n0- Exit\n\nEnter option:")

    if choice == "1":
        openVault()
    elif choice == "2":
        createVault()
    elif choice == "0":
        break
    else:
        print("Invalid choice")
        continue