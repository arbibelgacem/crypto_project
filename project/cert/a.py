from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

# Générer une paire de clés RSA
def generate_keypair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,   
        key_size=1024,  
        backend=default_backend()
    )
    
    with open('private_key.pem', 'wb') as private_key_file:
        private_key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        private_key_file.write(private_key_pem) 
    public_key = private_key.public_key()
    
    with open('public_key.pem', 'wb') as public_key_file:
        public_key_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        public_key_file.write(public_key_pem)