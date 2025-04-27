
import time
import datetime
import email

# Exports
__all__ = [
    'created_timestamp',
    'created_datetime',
    'unix_timestamp',
    'current_date'
]

def created_timestamp(datestring):
	return datetime.datetime.strptime(datestring, "%Y-%m-%dT%H:%M:%S.%fZ").timestamp()

def created_datetime(datestring):
	return datetime.datetime.strptime(datestring, "%Y-%m-%dT%H:%M:%S.%fZ")

def generalized_timestamp(datestring):
    return datetime.datetime.strptime(datestring, "%Y%m%d%H%M%SZ")

def unix_timestamp():
	return int(time.time())

def current_date():
    return email.utils.formatdate()