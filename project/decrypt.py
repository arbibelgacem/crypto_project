import rsa

def decrypt_message():
    with open("keys/private.pem","rb") as f:
        private_key = rsa.PrivateKey.load_pkcs1(f.read())
    encrypted_messge = open("encrypted.message","rb").read()
    clear_message = rsa.decrypt(encrypted_messge,private_key)
    print(clear_message.decode())