import rsa

def generate_keys():
    public_key, private_key= rsa.newkeys(1024)
    with open("keys/public.pem","wb") as f:
        f.write(public_key.save_pkcs1("PEM"))
    with open("keys/private.pem","wb") as f:
        f.write(private_key.save_pkcs1("PEM"))

def encrypt_msg():
    message = input("Enter a message to encrypt:\n")
    with open("keys/public.pem","rb") as f:
        public_key = rsa.PublicKey.load_pkcs1(f.read())
    encrypted_message = rsa.encrypt(message.encode(),public_key)
    print(encrypted_message)
    with open("encrypted.message","wb") as f:
        f.write(encrypted_message)


def decrypt_message():
    with open("keys/private.pem","rb") as f:
        private_key = rsa.PrivateKey.load_pkcs1(f.read())
    encrypted_messge = open("encrypted.message","rb").read()
    clear_message = rsa.decrypt(encrypted_messge,private_key)
    print(clear_message.decode())


def sign_rsa():
    with open("keys/private.pem","rb") as f:
        private_key = rsa.PrivateKey.load_pkcs1(f.read())
    message =input("Enter a message to Sign with RSA:\n")
    signature =rsa.sign(message.encode(),private_key,"SHA-256")
    with open("signature",'wb') as f: 
        f.write(signature)

def verify_sign():
    message = input("enter the message to verify integrity :\n")
    with open("keys/public.pem","rb") as f:
        public_key = rsa.PublicKey.load_pkcs1(f.read())
    with open("signature",'rb') as f:
        signature=f.read()
    print(rsa.verify(message.encode(),signature ,public_key))