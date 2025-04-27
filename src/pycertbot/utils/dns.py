
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
    'resolve'
]

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
