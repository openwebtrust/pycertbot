import json
import click
import locale
import smtplib
from email.message import EmailMessage
from InquirerPy import prompt

# PyCertBot Imports
from pycertbot.utils import timeutil
from pycertbot.utils import dns
from pycertbot.utils.format import b64encode, b64decode
from pycertbot.utils.crypto import OWT_random_bytes, OWT_digest_ex
# pass_session = click.make_pass_decorator(OWTSession)

def send_msg(session,
             from_addr : str = None,
             to_addr : str = None,
             msg : EmailMessage = None,
             pwd : str = None,
             verbose : bool = False,
             debug : bool = False,):
    
	# Retrieves the email password
    if not pwd or pwd == "":
        if (verbose):
            pwd = click.prompt(f"\nPlease enter the SMTP password ({from_addr})", type=str, hide_input=True)
        else:
            pwd = click.prompt(f"\nSMTP Password ({from_addr})", type=str, hide_input=True)
        click.echo()
    
    # Retrieves the configuration values
    host = session.config_get("smtp_host")
    if not host:
        # Look for the domain
        domain = session.config_get("smtp_domain")
        if not domain:
            # Look for the domain in the email address
            domain = from_addr.split('@')[1]
        # Get the hostname
        host = dns.resolve(domain)[0]
        
    port = session.config_get("smtp_port")
    user = session.config_get("smtp_user")
    
    # Sets the default locale language
    locale.setlocale(locale.LC_ALL, 'en_US')

    # Connect to the server
    if port == 465:
        # Use SSL
        smtp = smtplib.SMTP_SSL(host, port=port)
        # Let's be polite
        smtp.ehlo()  # send the extended hello to our server

    else:
        # Connects to the server and use STARTTLS
        smtp = smtplib.SMTP(host, port=port)
        # Let's say hello
        smtp.ehlo()  # send the extended hello to our server
        # Checks if the server supports STARTTLS
        if not smtp.has_extn('STARTTLS'):
            click.echo(f'\nError: STARTTLS not supported by the SMTP server.\n')
            exit(1)
        # Start SSL
        smtp.starttls()
        # Repeats the greeting
        smtp.ehlo()  # send the extended hello to our server

	# If we are in debug mode, we set the debug level
    if debug:
        smtp.set_debuglevel(1)  # show communication with the server
        smtp.ehlo()  # send the extended hello to our server

    # Set the extra email headers
    msg['X-Mailer'] = 'Python'
    msg['X-Priority'] = '1'
    msg['X-MSMail-Priority'] = 'High'
    msg['Date'] = timeutil.get_current_date() 
    
    try:
        # Login to the email server
        smtp.login(user, pwd)  # login to our email server
        
    except smtplib.SMTPException as exception:
        click.echo(f'\nError: authentication error ({exception}).\n')
        smtp.quit()
        exit(1)

    # send our email message 'msg' to our boss
    try:
        smtp.sendmail(from_addr,
                    to_addr,
                    msg.as_string())

    except smtplib.SMTPRecipientsRefused as exception:
        # Print a good error message
        for key in exception.recipients:
            # Let's get the recipient's error code and message
            code, message = exception.recipients[key]
            # let's convert the message to a string           
            str_message = message.decode('utf-8')
            err_message = str_message[str_message.find(':')+1:]
            # Prints the error message
            if verbose:
                click.echo(f'\n    Error: {err_message} ({code})')
                click.echo(f'            [ {key} ]\n')
            else:
                click.echo(f'\n    Error: Unable to send the email (recipient refused).\n')
        
        # close the connection
        smtp.quit()
        exit(1)
        
    except smtplib.SMTPException as exception:
        click.echo(f'\nError: Unable to send the email (Generic Error).\n')
        click.echo(exception)
        smtp.quit()
        exit(1)

    # all done, log out
    smtp.quit()
    
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
        b64_nonce = OWT_random_bytes(32, None)
    else:
        b64_nonce = b64encode(bytes(nonce, 'utf-8'))

	# calculates the token value SHA256(email + nonce)
    b64_email = b64encode(bytes(email, 'utf-8'))
    digest = OWT_digest_ex(data=bytes(b64_email, 'utf-8'), salt=bytes(b64_nonce, 'utf-8'),  pepper=b'OpenWebTrustDomainV1', algorithm='SHA256')
    
    # Finalizes the token and nonce
    b64_token = b64encode(digest)
    
    # returns the B64 encoded data
    return b64_token, b64_nonce