from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

def chiffrer_msg(): 
    with open('public_key.pem', 'rb') as public_key_file:
        public_key_pem = public_key_file.read()
        public_key = load_pem_public_key(public_key_pem, default_backend()) 
    message = input("Donner message a chiffrer: \n").encode() 
    ciphertext = public_key.encrypt(
        message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    with open("encrypter.message","wb") as f:
        f.write(ciphertext) 
