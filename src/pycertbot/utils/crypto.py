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

from base64 import urlsafe_b64encode as b64encode, urlsafe_b64decode as b64decode
from pycertbot.utils.logging import OWT_log_msg

# Master Secret
MasterSecret = None

# Exports

__all__ = [
	'JSONSec',
	'OWT_random_bytes',
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

def OWT_random_bytes(length=64, encoding : Literal['hex', 'utf-8', None] = None) -> (bytes | str):
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

def OWT_kdf_bcrypt_derive(secret, domain, len=32, cost : int = 12):
    """Derives a key from the secret using HKDF
    This function uses bcrypt to derive the key and SHA3_512 to generate the final key.
    The domain is used to derive the key and is set to 'OpenWebTrust2025' by default.
    The length of the key can be set to a maximum of 64 bytes.
    The default length is 32 bytes.
    
    The function raises a ValueError if the length is greater than 64 bytes.
    The function returns the derived key.
    
    Note: The cost factor for bcrypt is set to 12 by default, any increase in the cost
    factor will increase the time it takes to derive the key significantly even for small
    changes of the value. If the derivation time is too long, consider using a lower cost
    factor. The suggested minimum is 12 (default is 12).

    Args:
        secret (bytes): The secret to derive the key from.
        domain (bytes): The domain to use for key derivation.
        len (int, optional): The length of the derived key. Defaults to 32.
        cost (int, optional): The cost factor for bcrypt. Suggested min is 12 (def. 12).
        
    Raises:
        ValueError: If the length is greater than 64 bytes.

    Returns:
        bytes: The derived key.
    """
    
    # We support returning secrets up to 64 bytes
    if len > 64:
        print("Length must be less than 64 bytes")
        raise ValueError("Length must be less than 64 bytes")

    if domain is None:
        domain = b'OpenWebTrust2025'
    
    # Use bcrypt to derive the encryption key
    derived_key = KDF.bcrypt(secret, cost, domain)
    
    # Use SHA3_512 to derive the encryption key
    enc_key = SHA3_512.new(derived_key + domain).digest()[:len]
    
    # Returns the derived key
    return enc_key

def OWT_digest_ex(data, algorithm = 'SHA3_512', salt = None, pepper = None ):
    """Generates a hash from the data, salt, and pepper

    Args:
        data (str): The data to be hashed
        algorithm (str, optional): The hashing algorithm to use. Defaults to 'SHA3_512'.
        salt (bytes, optional): The salt to be used. Defaults to None.
        pepper (bytes, optional): The pepper to be used. Defaults to None.

    Returns:
        bytes: The generated hash
    """
    
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

def OWT_hash(data, salt = None, pepper = None):
    """Generates a hash from the data, salt, and pepper
    Args:
        data (str): The data to be hashed
        salt (str, optional): The salt to be used. Defaults to None.
        pepper (str, optional): The pepper to be used. Defaults to None.
    Returns:
        str: The generated hash
    """
    # Generates a key from the secret
    algorithm = 'SHA3_512'
    return OWT_digest_ex(data, algorithm, salt, pepper)

class JSONSec():
    """Class to handle JSON Encryption and Decryption
    
    This class uses AES and ChaCha20_Poly1305 for encryption and decryption.
    The built in KDF function for key derivation uses bcrypt and SHA3_512 for
    better diffusion and expansion.
    
    The class is meant to be used to encrypt and decrypt JSON data by using
    symmetric encryption algorithms. The default algorithm is AES, but ChaCha20_Poly1305
    is also supported.
    
    The AES algorithm supportess GCM, SIV, and CBC modes of operation.
    The ChaCha20_Poly1305 algorithm supports GCM mode of operation.
    """

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
                 session : object = None):
        """Initializes the JSONSec Object

		Args:
			data (dict, optional): The data to be encrypted. Defaults to None.
			enc_data (dict, optional): The encrypted data to be used by the instance. Defaults to None.
			secret (bytes, optional): The secret key to be used for encryption/decryption. Defaults to None.
			algorithm (str, optional): The encryption algorithm (one of 'AES' | 'ChaCha20_Poly1305' | 'XChaCha20_Poly1305').
			encryption_mode (int, optional): The mode of operation for the encryption algorithm. Defaults to AES.MODE_GCM.
			nonce (bytes, optional): The nonce for encryption used in AEAD modes. Defaults to None.
			iv (bytes, optional): The initialization vector for encryption for AES in CBC. Defaults to None.
			tag (bytes, optional): The tag for authentication used in AEAD modes (e.g., GCM, SIV, or Poly). Defaults to None.
			session (optional): The session information. Defaults to None.

		Raises:
			ValueError: If both data and enc_data are provided or if both data and enc_json are provided.
		"""
		# Only one between data and enc data can be passed
        if (data and enc_data) or ((data or enc_data) and enc_json):
            OWT_log_msg(f"ERROR: Only one between data and enc_data can be passed", is_error=True, raise_exception=True)
        
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
                self.__iv__ = OWT_random_bytes(16)
            # ChaCha20 Poly1305 Encryption
            elif self.__algorithm__ == ALG_CHACHA_POLY:
                self.__iv__ = OWT_random_bytes(12)

        if not self.__nonce__:
            # AES Encryption
            if self.__algorithm__ == ALG_AES:
                if self.__mode__ in [ AES.MODE_SIV, AES.MODE_GCM ]:
                    self.__nonce__ = OWT_random_bytes(16)
                elif self.__mode__ == AES.MODE_CBC:
                    self.__iv__ = OWT_random_bytes(16)
            # ChaCha20 Poly1305 Encryption
            elif self.__algorithm__ == ALG_CHACHA_POLY:
                self.__nonce__ = OWT_random_bytes(12)

        # Encrypts the data, if any was passed
        if data is not None:
            self.__enc_data__ = self._encrypt(data)
        
    
    def _hkdf(self, secret, len=32, cost=12):
        # Use the general HKDF function with set domain for derivation
        return OWT_kdf_bcrypt_derive(secret, b'OpenWebTrust2025', len, cost)

    
    def _encrypt(self, data):
        
        if not self.__secret__ or not data:
            OWT_log_msg(f"Secret ({self.__secret__} not Set or Data ({data}) not provided", is_error=True, raise_exception=True)

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
                OWT_log_msg(f"Invalid Mode: {self.__mode__}", is_error=True, raise_exception=True)

        elif self.__algorithm__ == ALG_CHACHA_POLY:
            # Let's get a nonce
            ChaCha20Poly1305Encryption = ChaCha20_Poly1305.new(key=enc_key, nonce=self.__nonce__)
            self.__enc_data__ = ChaCha20Poly1305Encryption.encrypt(json.dumps(data))
        else:
            OWT_log_msg(f"Invalid Algorithm: {self.__algorithm__}", is_error=True, raise_exception=True)
        
        # Returns the encrypted data
        return self.__enc_data__


    def _decrypt(self):
        
        # Return Value
        data = None
        
        # Checks if the secret is set
        if not self.__enc_data__:
            OWT_log_msg(f"ERROR: No data (None: {self.__enc_data__ is None}) to decrypt", is_error=True, raise_exception=True)
        
        if not self.__secret__:
            if owt_master_secret_is_set():
                self.__secret__ = MasterSecret
                OWT_log_msg(f"Using Master Secret for decryption.", is_error=True)
            else:
                OWT_log_msg(f"No Secret set for encryption, aborting.", is_error=True, raise_exception=True)
            
        # Sets up the encryption key
        keylength = 32
        if self.__mode__ == AES.MODE_SIV:
            keylength = 64
            
        # Derives the key from the secret. Note that bcrypt can take
        # a long time when the cost is set to values greater than 12)
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
                        OWT_log_msg(f"Invalid Mode: {self.__mode__}", is_error=True, raise_exception=True)
                
            except Exception as e:
                OWT_log_msg(f"Cannot decrypt the data: {e}", is_error=True, raise_exception=True)
    
        elif self.__algorithm__ == ALG_CHACHA_POLY:
            ChaCha20Poly1305Decryption = ChaCha20_Poly1305.new(key=self.__secret__, nonce=self.__nonce__)
            data = ChaCha20Poly1305Decryption.decrypt(self.__enc_data__)

        else:
            OWT_log_msg(f"Invalid Algorithm: {self.__algorithm__}", is_error=True, raise_exception=True)

        try:
            return_value = json.loads(data)
        except Exception as e:
            OWT_log_msg(f"Cannot decode the decrypted data: {e}", is_error=True, raise_exception=True)
       
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
        OWT_log_msg("No data to decrypt in JSONSec object", is_error=True)
        return None

    @data.setter
    def data(self, value):
        
        # Debugging Info
        OWT_log_msg("Setting JSONSec data property", is_error=False, is_debug=True)

        # encrypts the value and stores it encrypted in JSONSec object        
        self._encrypt(value)
        
        # Let's return the output of the internal getter enc_json
        return self.enc_json
        

