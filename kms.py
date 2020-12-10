import os
import pickle
import secrets
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import keywrap


class KMS():

    # the name of KEK environment variable
    KEK_ENV_VAR_NAME = 'PASSWORD_STORAGE_KEK'
    # path to DEK key-value file storage 
    DEK_PATH = './data/dekkv'

    def __init__(self):
        self.KEK = os.environ.get(self.KEK_ENV_VAR_NAME)
        if self.KEK is None:
            raise Exception('KEK environment variable is not set.')

        self.KEK = bytes().fromhex(self.KEK)
        self.DEKs = self.load_DEKs()

    def load_DEKs(self):
        with open(self.DEK_PATH,'rb') as file:
            try:
                data = pickle.load(file)
            except EOFError:
                data = dict()
        return data

    def save_DEKs(self):
        with open(self.DEK_PATH,'wb') as file:
            pickle.dump(self.DEKs, file)

    def key_wrap(self, key):
        return keywrap.aes_key_wrap(self.KEK, key)

    def key_unwrap(self, wrapped_key):
        return keywrap.aes_key_unwrap(self.KEK, wrapped_key)

    def create_DEK(self, id_):
        new_DEK = self.generate_DEK()
        self.DEKs[id_] = self.key_wrap(new_DEK)
        self.save_DEKs()

    def is_exist_DEK(self, id_):
        return id_ in self.DEKs

    def encrypt(self, DEK_id, data, nonce):
        DEK = self.key_unwrap(self.DEKs[DEK_id])
        return AESGCM(DEK).encrypt(nonce, data, None)

    def decrypt(self, DEK_id, data, nonce):
        DEK = self.key_unwrap(self.DEKs[DEK_id])
        return AESGCM(DEK).decrypt(nonce, data, None)

    @classmethod
    def generate_DEK(cls):
        return AESGCM.generate_key(bit_length=128)

    @classmethod
    def generate_nonce(cls):
        return secrets.token_bytes(12)

