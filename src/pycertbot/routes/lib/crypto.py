# Default Imports
import json
import click

from typing import Literal
from pprint import pprint

# Crypto Imports
from Crypto import Random
from Crypto.Cipher import AES, ChaCha20_Poly1305
from Crypto.Hash import SHA256, SHA512, SHA3_512, SHA3_256, SHAKE256
from Crypto.Protocol import KDF

# from base64 import b64encode, b64decode
# from pycertbot.routes.lib.utils import b64encode, b64decode
from base64 import urlsafe_b64encode as b64encode, urlsafe_b64decode as b64decode

# Master Secret
MasterSecret = None

# Exports

__all__ = [
	'JSONSec',
	'owt_random_bytes',
	'owt_set_master_secret',
    'owt_master_secret_is_set'
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

def owt_random_bytes(length=64, encoding : Literal['hex', 'utf-8', None] = None) -> (bytes | str):
	"""Generates random bytes

	Args:
		length (int, optional): The length of the returned bytes. Defaults to 32.
		encoding (str, optional): Encoding for the returned data ('hex' | 'utf-8'| None).
  			Defaults to None.

	Returns:
		bytes: The generated random bytes
	"""
    
	# Sets a minimum length
	if not length:
		length = 16
	
	# Returns the random bytes
	bytes_data = Random.get_random_bytes(length)
    
	if not encoding:
		return bytes_data
	
	# Returns the encoded bytes
	decoded_data = bytes_data.decode(encoding)
	return decoded_data

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

def owt_hkdf(secret, domain, len=32):
    
    # We support returning secrets up to 64 bytes
    if len > 64:
        print("Length must be less than 64 bytes")
        raise ValueError("Length must be less than 64 bytes")

    if domain is None:
        domain = b'OpenWebTrust2025'
    
    # Use bcrypt to derive the encryption key
    derived_key = KDF.bcrypt(secret, 12, domain)
      
    # # Generates a key from the secret
    # key_seed = SHA3_512.new(secret).digest()
    # # key_seed = SHA3_512.new(domain).update(secret).digest()
    
    # Use SHA3_512 to derive the encryption key
    enc_key = SHA3_512.new(derived_key + domain).digest()[:len]
    
    # Returns the derived key
    return enc_key

def owt_hash_ex(data, algorithm = 'SHA3_512', salt = None, pepper = None ):
    
    if not data:
        return None
    
    match algorithm:
        case 'SHA256':
            hash = SHA256.new()
        case 'SHA512':
            hash = SHA512.new()
        case 'SHA3' | 'SHA3_256':
            hash = SHA3_256.new()
        case 'SHA3_512':
            hash = SHA3_512.new()
        case 'SHAKE256':
            hash = SHAKE256.new()
        case _:
            return None

    # Generates the hash from the salt, data, and pepper
    if salt is not None:
        hash.update(salt)
        
    if pepper is not None:
        hash.update(data)
        
    hash.update(pepper)
    return hash.digest()

def owt_hash(data, salt = None, pepper = None):
    # Generates a key from the secret
    algorithm = 'SHA3_512'
    return owt_hash_ex(data, algorithm, salt, pepper)

class JSONSec():
    """JSONSec is a class that provides a simple way to encrypt and decrypt JSON data."""

    def __init__(self,
                 data : str = None, 
	             enc_data : dict = None, 
				 secret : bytes = MasterSecret, 
				 algorithm : str = 'AES',
                 encryption_mode : int = AES.MODE_GCM,
                 tag : bytes = None,
				 nonce : bytes = None,
				 iv : bytes = None,
                 enc_json : dict = None,
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
        if (data and enc_data) or ((data or enc_data) and enc_json):
            raise ValueError("Only one between data and enc_data can be passed")
        
		# Sets the data and secret
        self.__secret__ = secret
        self.__algorithm__ = algorithm
        self.__iv__ = iv
        self.__mode__ = encryption_mode 
        self.__nonce__ = nonce
        self.__session__ = session
        self.__tag__ = tag
        self.__enc_data__ = None

        if not self.__secret__:
            self.__secret__ = MasterSecret
       
        if enc_json is not None:
            try:

                # Parses the JSON data if the input is a string
                parsed_enc_json = enc_json
                if isinstance(enc_json, str):
                    parsed_enc_json = json.loads(enc_json)
        
                # Gets the values from the JSON data
                self.__algorithm__ = parsed_enc_json.get('algorithm', ALG_AES)
                self.__mode__ = parsed_enc_json.get('encryption-mode', AES.MODE_GCM)
                
                # Manage optional fields
                bin_value = parsed_enc_json.get('nonce')
                if bin_value:
                    self.__nonce__ = b64decode(bin_value)

                bin_value = parsed_enc_json.get('tag')
                if bin_value:
                    self.__tag__ = b64decode(bin_value)
                
                bin_value = parsed_enc_json.get('iv')
                if bin_value:
                    self.__tag__ = b64decode(bin_value)
                
                bin_value = parsed_enc_json.get('iv')
                if bin_value:
                    self.__iv__ = b64decode(bin_value)
                
                bin_value = parsed_enc_json.get('nonce')
                if bin_value:
                    self.__nonce__ = b64decode(bin_value)
                
                bin_value = parsed_enc_json.get('data')
                if bin_value:
                    self.__enc_data__ = b64decode(bin_value)

                if not self.__iv__ and not self.__nonce__:
                    raise ValueError("IV or Nonce not set")
                                
            except ValueError as e:
                print(f"Error: Cannot decode the encrypted JSON: {e}")
                raise ValueError(f"Invalid JSON: {e}")

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
                elif self.__mode__ == AES.MODE_CBC:
                    self.__iv__ = owt_random_bytes(16)
            # ChaCha20 Poly1305 Encryption
            elif self.__algorithm__ == ALG_CHACHA_POLY:
                self.__nonce__ = owt_random_bytes(12)

        # Encrypts the data, if any was passed
        if data is not None:
            self.__enc_data__ = self._encrypt(data)
            
    
    def _hkdf(self, secret, len=32):
        # Use the general HKDF function with set domain for derivation
        return owt_hkdf(secret, b'OpenWebTrust2025', len)

    
    def _encrypt(self, data):

        print(f"******** Encrypting Data: {data} ***********")
        
        if not self.__secret__ or not data:
            print(f"Secret ({self.__secret__} not Set or Data ({data}) not provided")
            raise Exception("Secret not Set or Data not provided")

        keylength = 32
        if self.__mode__ == AES.MODE_SIV:
            keylength = 64
        enc_key = self._hkdf(self.__secret__, keylength)
        
        if self.__algorithm__ == ALG_AES:

            # Initialize the Cipher
            if self.__mode__ == AES.MODE_GCM:
                AESEncryption = AES.new(enc_key, AES.MODE_GCM, self.__nonce__)
                self.__enc_data__, self.__tag__ = AESEncryption.encrypt_and_digest(str.encode(json.dumps(data)))
                
            elif self.__mode__ == AES.MODE_SIV:
                AESEncryption = AES.new(enc_key, AES.MODE_SIV, self.__nonce__)
                self.__enc_data__, self.__tag__ = AESEncryption.encrypt_and_digest(str.encode(json.dumps(data)))
                
            elif self.__mode__ == AES.MODE_CBC:
                AESEncryption = AES.new(enc_key, AES.MODE_CBC, self.__iv__)
                self.__enc_data__ = AESEncryption.encrypt(str.encode(json.dumps(data)))
            else:
                raise Exception(f"Invalid Mode: {self.__mode__}")

        elif self.__algorithm__ == ALG_CHACHA_POLY:
            # Let's get a nonce
            ChaCha20Poly1305Encryption = ChaCha20_Poly1305.new(key=self.__secret__, 
                                                               nonce=self.__nonce__)
            self.__enc_data__ = ChaCha20Poly1305Encryption.encrypt(json.dumps(data))
        else:
            raise Exception("Invalid Algorithm")
        
        print(f"******** Encrypted Data: {self.__enc_data__}, Tag: {self.__tag__}, Nonce: {self.__nonce__}, IV: {self.__iv__}")
        
        return self.__enc_data__


    def _decrypt(self):
        
        # Return Value
        data = None
        
        # Checks if the secret is set
        if not self.__secret__ or not self.__enc_data__:
            raise Exception("Secret not Set or No Encrypted Data set")

        keylength = 32
        if self.__mode__ == AES.MODE_SIV:
            keylength = 64
        enc_key = self._hkdf(self.__secret__, keylength)
        
        # Encryption Algorithm(s): AES, ChaCha20_Poly1305
        if self.__algorithm__ == ALG_AES:
            
            try:
                
                # Encryption Mode(s): GCM, SIV, CBC
                match self.__mode__:
                    case AES.MODE_GCM:
                        AESDecryption = AES.new(enc_key, AES.MODE_GCM, nonce=self.__nonce__, use_aesni=True)
                        data = AESDecryption.decrypt_and_verify(self.__enc_data__, self.__tag__)

                    case AES.MODE_SIV:
                        AESDecryption = AES.new(enc_key, AES.MODE_SIV, self.__nonce__, use_aesni=True)
                        data = AESDecryption.decrypt_and_verify(self.__enc_data__, self.__tag__)
                        
                    case AES.MODE_CBC:
                        AESDecryption = AES.new(enc_key, AES.MODE_CBC, iv=self.__iv__, use_aesni=True)
                        data = AESDecryption.decrypt(self.__enc_data__)
                    case _:
                        raise Exception(f"Invalid Mode: {self.__mode__}")
                
            except Exception as e:
                print(f"Error: Cannot decrypt the data: {e}")
                raise Exception(f"Invalid Data: {e}")
    
        elif self.__algorithm__ == ALG_CHACHA_POLY:
            ChaCha20Poly1305Decryption = ChaCha20_Poly1305.new(key=self.__secret__, nonce=self.__nonce__)
            data = ChaCha20Poly1305Decryption.decrypt(self.__enc_data__)

        else:
            raise Exception("Invalid Algorithm")

        try:
            return_value = json.loads(data)
        except Exception as e:
            print(f"Error: Cannot decode the decrypted data: {e}")
            raise Exception(f"Invalid Data: {e}")
       
        return return_value
    
    
    @property
    def enc_data(self):
        # Converts the data to a base64 string
        return b64encode(self.__enc_data__)

    @property
    def iv(self):
        # Converts the iv to a base64 string
        return b64encode(self.__iv__)

    @property
    def enc_json(self):

        # Converts the iv and data to a base64 string
        iv = b64encode(self.__iv__).decode('utf-8')
        data = b64encode(self.__enc_data__).decode('utf-8')

        # Builds the serializable JSON object
        ret_json = None
        if self.__mode__ in [ AES.MODE_SIV, AES.MODE_GCM ]:
            nonce = b64encode(self.__nonce__).decode('utf-8')
            tag = b64encode(self.__tag__).decode('utf-8')
            ret_json = {
                    'algorithm': self.__algorithm__,
                    'encryption-mode': self.__mode__,
                    'nonce': nonce,
                    'data' : data,
                    'tag': tag
            }
            
        elif self.__mode__ == AES.MODE_CBC:
            iv = b64encode(self.__iv__).decode('utf-8')
            ret_json = {
                'algorithm': self.__algorithm__,
                'encryption-mode': self.__mode__,
                'data' : data,
                'iv': iv,
            }
        else:
            raise ValueError(f"Invalid Mode: {self.__mode__}")

        # Returns the JSON object
        return ret_json

    @enc_data.setter
    def enc_data(self, value):
        click.echo(f"Setting Encrypted Data: {value}", err=True, color=True)
        if not self.__enc_data__:
            self.__algorithm__ = value.get('algorithm') or 'AES'
            self.__mode__ = value.get('encryption-mode') or AES.MODE_GCM
            self.__enc_data__ = value.get('data')
            if not self.__enc_data__:
                raise Exception("Encrypted Data not set")
            self.__iv__ = value.get('iv') or None
            if not self.__iv__:
                raise Exception("IV not set")
            self.__nonce__ = value.get('nonce') or None
            if self.__mode__ in [ AES.MODE_SIV, AES.MODE_GCM, AES.MODE_CBC ] and not self.__nonce__:
                raise Exception("Nonce not set for AES GCM/SIV/CCM")

        if not self.__enc_data__:
            raise Exception("Encrypted Data not set")

    @property
    def data(self):
        # Decrypts and returns the data
        if self.__enc_data__:
            return self._decrypt()
        
        # Error condition or no data
        click.echo("ERROR: No data to decrypt", err=True, color=True)
        return None

    @data.setter
    def data(self, value):
        self.__data__ = value
        self._encrypt(self)
        
        # Let's return the output of the internal getter enc_json
        return self.enc_json
        

