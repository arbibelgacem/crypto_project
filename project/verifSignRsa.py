import rsa

def verify_sign():
    message = input("enter the message to verify integrity :\n")
    with open("keys/public.pem","rb") as f:
        public_key = rsa.PublicKey.load_pkcs1(f.read())
    with open("signature",'rb') as f:
        signature=f.read()
    print(rsa.verify(message.encode(),signature ,public_key))