# Default Imports
import json
from typing import Literal

# Crypto Imports
from Crypto import Random
from Crypto.Cipher import AES, ChaCha20_Poly1305
from Crypto.Hash import SHA256
from Crypto.Protocol import KDF

from base64 import b64encode, b64decode

import click
from ..lib import session

# Master Secret
MasterSecret = None

# Exports

__all__ = [
	'JSONSec',
	'owt_random_bytes',
	'owt_set_master_secret',
]

# ==============
# Implementation
# ==============

# Some Constants
ALG_AES = 'AES'
ALG_CHACHA_POLY = 'ChaCha20_Poly1305'

# ==============
# Implementation
# ==============

def owt_random_bytes(length=32, encoding : Literal['hex', 'utf-8', None] = None) -> (bytes | str):
	"""Generates random bytes

	Args:
		length (int, optional): The length of the returned bytes. Defaults to 32.
		encoding (str, optional): Encoding for the returned data ('hex' | 'utf-8'| None).
  			Defaults to None.

	Returns:
		bytes: The generated random bytes
	"""
    
	# Sets a minimum length
	if not length or length < 16:
		length = 16
	
	# Returns the random bytes
	bytes_data = Random.get_random_bytes(length)
	if not encoding:
		return bytes_data
	
	# Returns the encoded bytes
	return bytes_data.decode(encoding)

def owt_set_master_secret(secret : bytes):
	"""Sets the Master Secret for the module

	Args:
		secret (bytes): The secret to be set
	"""
	global MasterSecret
	MasterSecret = bytes(secret, 'utf-8')

def owt_master_secret_is_set() -> bool:
	"""Checks if the Master Secret is set

	Returns:
		bool: True if the Master Secret is set, False otherwise
	"""
	return bool(MasterSecret)

class JSONSec():
    """JSONSec is a class that provides a simple way to encrypt and decrypt JSON data."""

    def __init__(self,
                data : dict = None, 
	            enc_data : dict = None, 
				secret : bytes = MasterSecret, 
				algorithm : str = 'AES', 
				nonce : bytes = None,
				iv : bytes = None,
                session = None):
        """Initializes the JSONSec Object

		Args:
			data (dict, optional): The data to be encrypted. Defaults to None.
			enc_data (dict, optional): The data to be decrypted. Defaults to None.
			secret (bytes, optional): The secret key to be used for encryption/decryption. Defaults to None.
			algorithm (str, optional): Defaults to 'AES' | 'ChaCha20_Poly1305' | 'XChaCha20_Poly1305'.
			mode (str, optional): _description_. Defaults to AES.MODE_SIV | AES.MODE_GCM | None.
			nonce (bytes, optional): _description_. Defaults to None.
			iv (bytes, optional): _description_. Defaults to None.

		Raises:
			ValueError: _description_
		"""
		# Only one between data and enc data can be passed
        if data and enc_data:
            raise ValueError("Only one between data and enc_data can be passed")

		# Sets the data and secret
        self.__data__ = data
        self.__secret__ = secret
        self.__algorithm__ = algorithm
        self.__nonce__ = nonce
        self.__iv__ = iv
        self.__mode__ = AES.MODE_GCM
        self.__session__ = session
    
        if not self.__secret__:
            self.__secret__ = MasterSecret
    
		# If no IV is passed, we generate a random one
        if not self.__iv__:
            # AES Encryption
            if self.__algorithm__ == ALG_AES:
                self.__iv__ = owt_random_bytes(16) 
            # ChaCha20 Poly1305 Encryption
            elif self.__algorithm__ == ALG_CHACHA_POLY:
                self.__iv__ = owt_random_bytes(12)
    
        if not self.__nonce__:
            # AES Encryption
            if self.__algorithm__ == ALG_AES:
                if self.__mode__ in [ AES.MODE_SIV, AES.MODE_GCM ]:
                    self.__nonce__ = owt_random_bytes(16)
            # ChaCha20 Poly1305 Encryption
            elif self.__algorithm__ == ALG_CHACHA_POLY:
                self.__nonce__ = owt_random_bytes(12)

        # Encrypts the data, if any was passed
        if self.__data__:
            self.__enc_data__ = self._encrypt()
            # Debug
            print(f"Encrypted Data: {self.__enc_data__}")

        # Decrypts the data, if any was passed
        elif self.__enc_data__:
            self.__data__ = self._decrypt()
    
    
    def _encrypt(self):

        if not self.__secret__ or not self.__data__:
                raise Exception("Secret or Data not set")

        key_seed = SHA256.new(self.__secret__).digest()
        enc_key = SHA256.new(KDF.bcrypt(key_seed, 12, b'open_web_trust_1')).digest()[:16]

        if self.__algorithm__ == ALG_AES:

            # Initialize the Cipher
            if self.__mode__ == AES.MODE_GCM:
                AESEncryption = AES.new(key=enc_key, 
                                        mode=self.__mode__,
                                        nonce=self.__nonce__,
                                        )
            elif self.__mode__ == AES.MODE_CBC:
                AESEncryption = AES.new(key=enc_key, 
                                        mode=self.__mode__,
                                        iv=self.__iv__,
                                        )
            else:
                raise Exception("Invalid Mode")

            # Encrypts the data
            self.__enc_data__ = AESEncryption.encrypt(str.encode(json.dumps(self.__data__)))

        elif self.__algorithm__ == ALG_CHACHA_POLY:
            # Let's get a nonce
            ChaCha20Poly1305Encryption = ChaCha20_Poly1305.new(key=self.__secret__, 
                                                                nonce=self.__nonce__)
            self.__enc_data__ = ChaCha20Poly1305Encryption.encrypt(json.dumps(self.__data__))
        else:
            raise Exception("Invalid Algorithm")
        
        return self.__enc_data__


    def _decrypt(self):
        # Checks if the secret is set
        if not self.__secret__ or not self.__enc_data__:
            raise Exception("Secret and/or Encrypted Data not set")

        key_seed = SHA256.new(self.__secret__).digest()
        enc_key = SHA256.new(KDF.bcrypt(key_seed, 12, b'open_web_trust_1')).digest()


        if self.__algorithm__ == ALG_AES:
            AESDecryption = AES.new(key=enc_key, 
                                    mode=self.__mode__, 
                                    iv=self.__iv__,
                                    nonce=self.__nonce__,
                                    use_aesni=True)
            self.__data__ = AESDecryption.decrypt(self.__enc_data__)

        elif self.__algorithm__ == ALG_CHACHA_POLY:
            ChaCha20Poly1305Decryption = ChaCha20_Poly1305.new(key=self.__secret__, nonce=self.__nonce__)
            self.__data__ = ChaCha20Poly1305Decryption.decrypt(self.__enc_data__)

        else:
            raise Exception("Invalid Algorithm")

        return json.loads(self.__data__)

    @property
    def enc_data(self):
        # Converts the data to a base64 string
        return b64encode(self.__enc_data__).decode('utf-8')

    @property
    def iv(self):
        # Converts the iv to a base64 string
        return b64encode(self.__iv__).decode('utf-8')

    @property
    def enc_json(self):
        
        # Converts the iv and data to a base64 string
        iv = b64encode(self.__iv__).decode('utf-8')
        data = b64encode(self.__enc_data__).decode('utf-8')

        # Builds the serializable JSON object
        ret_json = {
            'algorithm': self.__algorithm__,
            'encryption-mode': self.__mode__,
            'iv': iv,
            'data' : data,
        }

        # Returns the JSON object
        return ret_json

    @enc_data.setter
    def enc_data(self, value):
        
        if not self.__enc_data__:
            self.__algorithm__ = value.get('algorithm') or 'AES'
            self.__mode__ = value.get('encryption-mode') or AES.MODE_SIV
            self.__enc_data__ = value.get('data') or None
            self.__iv__ = value.get('iv') or None
            self.__nonce__ = value.get('nonce') or None
            self._encrypt(self)

        if not self.__enc_data__:
            raise Exception("Encrypted Data not set")

        self.__algorithm__ = value.get('algorithm') or 'AES'
        self.__mode__ = value.get('encryption-mode') or AES.MODE_SIV
        self.__enc_data__ = value.get('data') or None
        self.__iv__ = value.get('iv') or None
        self.__nonce__ = value.get('nonce') or None
        self._decrypt(self)

    @property
    def data(self):
        if self.__data__:
            return self.__data__
        elif self.__enc_data__:
            return self._decrypt()

    @data.setter
    def data(self, value):
        self.__data__ = value
        self._encrypt(self)


