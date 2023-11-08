import rsa

def encrypt_msg():
    message = input("Enter a message to encrypt:\n")
    with open("keys/public.pem","rb") as f:
        public_key = rsa.PublicKey.load_pkcs1(f.read())
    encrypted_message = rsa.encrypt(message.encode(),public_key)
    print(encrypted_message)
    with open("encrypted.message","wb") as f:
        f.write(encrypted_message)