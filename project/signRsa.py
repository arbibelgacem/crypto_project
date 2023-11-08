import rsa

def sign_rsa():
    with open("keys/private.pem","rb") as f:
        private_key = rsa.PrivateKey.load_pkcs1(f.read())
    message =input("Enter a message to Sign with RSA:\n")
    signature =rsa.sign(message.encode(),private_key,"SHA-256")
    with open("signature",'wb') as f: 
        f.write(signature)