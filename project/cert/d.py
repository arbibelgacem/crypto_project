from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.primitives import padding
 
with open('private_key.pem', 'rb') as private_key_file:
    private_key_pem = private_key_file.read()
    private_key = load_pem_private_key(private_key_pem, password=None, backend=default_backend())
 
with open("encrypter.message","rb")as f:
    ciphertext=f.read()  
original_message = private_key.decrypt(
    ciphertext,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=padding.ALGORITHMS.SHA256),
        algorithm=padding.ALGORITHMS.SHA256,
        label=None
    )
)  
print("Message déchiffré : ", original_message.decode('utf-8'))