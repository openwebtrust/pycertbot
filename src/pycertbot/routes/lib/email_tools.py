import json
import click
import locale
import smtplib
from email.message import EmailMessage
from InquirerPy import prompt

# PyCertBot Imports
from pycertbot.routes.lib.session import OWTSession
from pycertbot.routes.lib import utils, timeutil

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
        host = utils.dns_resolve(domain)[0]
        
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