
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

def created_timestamp(created):
	return datetime.datetime.strptime(created, "%Y-%m-%dT%H:%M:%S.%fZ").timestamp()

def created_datetime(created):
	return datetime.datetime.strptime(created, "%Y-%m-%dT%H:%M:%S.%fZ")

def unix_timestamp():
	return int(time.time())

def current_date():
    return email.utils.formatdate()