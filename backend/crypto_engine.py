import os
import base64
from cryptography.hazmat.primitives.asymmetric import ec, rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

class CryptoEngine:
    def __init__(self):
        pass

    @staticmethod
    def generate_ecdh_keypair():
        """توليد مفاتيح ديفي-هلمان بالمنحنيات البيضاوية ECDH (SECP256R1)"""
        private_key = ec.generate_private_key(ec.SECP256R1())
        public_key = private_key.public_key()
        
        pub_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return private_key, pub_bytes.decode('utf-8')

    @staticmethod
    def derive_shared_secret(private_key, peer_public_pem_str):
        """توليد المفتاح السري المشترك من مفتاحك الخاص والمفتاح العام للطرف الآخر"""
        peer_pub_bytes = peer_public_pem_str.encode('utf-8')
        peer_public_key = serialization.load_pem_public_key(peer_pub_bytes)
        
        raw_shared_key = private_key.exchange(ec.ECDH(), peer_public_key)
        digest = hashes.Hash(hashes.SHA256())
        digest.update(raw_shared_key)
        return digest.finalize()

    @staticmethod
    def generate_rsa_keypair():
        """توليد زوج مفاتيح RSA للتوقيع الرقمي"""
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public_key = private_key.public_key()
        return private_key, public_key

    @staticmethod
    def sign_data(rsa_private_key, data_bytes):
        """توقيع البيانات رقمياً باستخدام RSA"""
        return rsa_private_key.sign(
            data_bytes,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )

    @staticmethod
    def verify_signature(rsa_public_key, signature, data_bytes):
        """التحقق من صحة التوقيع الرقمي"""
        try:
            rsa_public_key.verify(
                signature,
                data_bytes,
                padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                hashes.SHA256()
            )
            return True
        except Exception:
            return False

    @staticmethod
    def encrypt_msg(secret_key_bytes, plaintext_str):
        """تشفير الرسائل عبر AES-256-GCM"""
        aesgcm = AESGCM(secret_key_bytes)
        nonce = os.urandom(12)
        ciphertext = aesgcm.encrypt(nonce, plaintext_str.encode('utf-8'), None)
        return base64.b64encode(nonce + ciphertext).decode('utf-8')

    @staticmethod
    def decrypt_msg(secret_key_bytes, encrypted_b64):
        """فك تشفير الرسائل عبر AES-256-GCM"""
        try:
            data = base64.b64decode(encrypted_b64)
            nonce = data[:12]
            ciphertext = data[12:]
            aesgcm = AESGCM(secret_key_bytes)
            return aesgcm.decrypt(nonce, ciphertext, None).decode('utf-8')
        except Exception:
            return "[DECRYPTION FAILED / TAMPERED MESSAGE]"