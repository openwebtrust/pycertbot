
import smtplib
from email.message import EmailMessage

import click
import locale

from InquirerPy import prompt

from Crypto import Random
from Crypto.Hash import SHA256
from base64 import urlsafe_b64encode as _b64encode, urlsafe_b64decode as _b64decode

import dns.resolver as dns

# Sets the locale
locale.setlocale(locale.LC_ALL, 'en_US')

# Exports

__all__ = [
    'banner',
    'b64encode',
    'b64decode',
    'has_token',
    'get_registration_token',
    'currencyUnits',
    'largeNumber',
    'formatNumber',
    'dns_resolve'
]

def banner(verbose=False):
	"""Prints the Banner for the CLI Tool.

	Args:
		verbose (bool, optional): Verbose Output. Defaults to False.
	"""
	# Some Banner Data
	if (verbose):
		click.echo()
		click.echo(message=f"Python Certbot - V0.0.1", color=True)
		click.echo(message=f"(c) 2024 Open Web Trust Community", color=True)
		click.echo(message="All Rights Reserved")
		click.echo()

def b64encode(data):
    if not data:
        return None
    return _b64encode(data).decode('utf-8')

def b64decode(data):
    if not data:
        return None
    return _b64decode(data).decode('utf-8')

def has_token(session):
	token = session.config_get("token")
	has_token = True if token is not None else False
	if not has_token:
		click.echo("Please login to access services.")
	return has_token

def get_registration_token(email=None, nonce=None):
    """Generates a Registration Token for the given email address.

    Args:
        email (str, optional): Email Address. Required.
        nonce (str, optional): Nonce. Defaults to Rand(32)

    Returns:
        str: Registration Token
    """
    
    # If no email is provided, we raise an exception
    if not email:
        raise Exception("Email Address is required.")
  
	# If no nonce is provided, let's generate one
    if not nonce:
        b64_nonce = b64encode(Random.get_random_bytes(32))
    else:
        b64_nonce = b64encode(bytes(nonce, 'utf-8'))

	# calculates the token value SHA256(email + nonce)
    hashObj = SHA256.new(data=bytes(b64_nonce, 'ascii'))
    b64_email = b64encode(bytes(email, 'utf-8'))
    hashObj.update(bytes(b64_email, 'utf-8'))
    
    # Finalizes the token and nonce
    b64_token = b64encode(hashObj.digest())
    
    # returns the B64 encoded data
    return b64_token, b64_nonce

def currencyUnits(priceUnits):
	price = float(priceUnits)
	return_value = "0.0"
	if (price < 0):
		return locale.currency(price, grouping=True)
	return_value = price / 100
	return locale.currency(return_value, grouping=True)

def largeNumber(value):
	temp_val = value
	selected_symbol = ""
	symbols = [ "", "K", "M", "G", "T", "P" ]
	for letter in symbols:
		if temp_val < 1000:
			selected_symbol = letter
			break
		temp_val = temp_val / 1000

	return f'{temp_val}{selected_symbol}'

def formatNumber(value):
	return "{:,.0f}".format(value)

def dns_resolve(domain : str = None, record_type : str = 'MX'):
    """Resolves a DNS Record for a given domain.

    Args:
        domain (str): Domain Name
        record_type (str): Record Type

    Returns:
        list: List of DNS Records
    """
    ret_list = []
    # Resolves the DNS Record
    for x in dns.resolve(domain, record_type):
        # Extracts the SMTP Host
        if x and x.to_text() != "":
            smtp_host = x.to_text().split(' ')[1][:-1]
            ret_list.append(smtp_host)
    # Returns the list of records
    return ret_list
