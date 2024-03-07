"""
Module for Common Functions
"""
import os
import yaml
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding

dirname = os.path.dirname(__file__)
conf_yml_path = os.path.join(dirname, 'main_config.yml')
try:
    with open(conf_yml_path, 'r', encoding="utf8") as yml:
        _config = yaml.safe_load(yml, Loader=yaml.FullLoader)
        yml.close()
except FileNotFoundError as error:
    print(f"Unable to find main_config.yml "
          f"\nDetails: {error}")


def credential_encrypter(client_secret):
    """
    This method is used to encrypt a value and can be used in other classes

    Args:
        client_secret: the value to be encrypted
    Returns:
        ciphertext: Byte String consisting the encrypted value of given message
    """
    key_path_pub = os.path.join(dirname, _config['key_paths']['public_key_path'])
    with open(key_path_pub, 'rb') as file_pem:
        public_key_pem = file_pem.read()
        public_key = serialization.load_pem_public_key(public_key_pem,
                                                       backend=default_backend())
        ciphertext = public_key.encrypt(client_secret.encode('utf-8'),
                                        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                                     algorithm=hashes.SHA256(), label=None))
    return ciphertext.hex()


def credential_decrypter(client_secret):
    """
    This method is used to decrypt a value and can be used in other classes

    Args:
        client_secret: the value to be decrypted
    Returns:
        decrypted_message: String consisting the decrypted value of given message
    """
    key_path_pri = os.path.join(dirname, _config['key_paths']['private_key_path'])
    with open(key_path_pri, 'rb') as file_pem:
        private_key_pem = file_pem.read()
        private_key = serialization.load_pem_private_key(private_key_pem,
                                                         password=None,
                                                         backend=default_backend())
        client_secret = bytes.fromhex(client_secret)
        decrypted_message = private_key.decrypt(client_secret,
                                                padding.OAEP(
                                                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                                    algorithm=hashes.SHA256(),
                                                    label=None))
    return decrypted_message.decode('utf-8')
