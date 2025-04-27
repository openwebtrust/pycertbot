import os
import sys
import click
import base64

from pprint import pprint
from urllib.parse import urlparse
from email.message import EmailMessage

from pycertbot.routes.lib import session, utils, email_tools
from pycertbot.routes.lib.message import ApiReplyMessage
from pycertbot.routes.lib.defaults import APP_ROUTES

pass_session = click.make_pass_decorator(session.OWTSession)

@click.command()
@click.option('-u', '--username',required=True, type=str, prompt=True)
@click.option('-p', '--password',required=True, type=str, prompt=True, hide_input=True)
@click.option('-v', '--verbose', 'opt_verbose', type=bool, help="Verbose output for humans (def. no)", is_flag=True, default=False, required=False)
@pass_session
def login(session, username, password, opt_verbose):
    """Login with username and password."""
    
    # global APP_ROUTES
    
    body = {"username": username, "password": password}
    
    if (opt_verbose > 0):
        click.echo(f'\nNew Session Info:')
        click.echo(f'- Config Path ..: {session.config_path}')
        click.echo(f'- Server Url ...: {session.config["url"]}')
    try:
        res = session.put_no_auth(route=f"{APP_ROUTES.account}/login", body=body)
        token = res["token"]
        session.config_set("token", token)
        click.echo(f'\nLogin Succeeded.\n')
        
    except:
        session.config_set("token", None)
        if (opt_verbose > 0):
            click.echo(f'\nLogin Failed. Please try again.\n')
        else:
            click.echo(f'\nLogin Failed. Please check the configuration ({session.config_path}).\n')


@click.command()
@click.option('-v', '--verbose', 'opt_verbose', type=bool, help="Verbose output for humans (def. no)", is_flag=True, default=False, required=False)
@pass_session
def logout(session, opt_verbose):
    """Terminates and removes the current session."""
    if (opt_verbose > 0):
        click.echo(f'\nSession Info:')
        click.echo(f'- Config Path ..: {session.config_path}')
        click.echo(f'- Server Url ...: {session.config["url"]}')
    try:
        res = session.post(route=f"{APP_ROUTES.account}/logout", body=None)
    except:
         if (opt_verbose > 0):
             click.echo(f'\nIssue in reaching the server. Local Session Removed.\n')

    session.config_set("token", None)
    click.echo(f'\nLogout Succeeded.\n')

@click.command()
@click.option('-u', '--url', required=False, type=str, prompt=False, default=None)
@click.option('-s', '--secret', required=False, type=str, prompt=False, hide_input=True)
@click.option('-e', '--email', required=False, type=str, prompt=False)
@click.option('-u', '--smtp-user', type=str, help="SMPT username (def. <email_addr>)", required=False, prompt=False)
@click.option('-p', '--smtp-password', 'smtp_pwd', type=str, help="SMPT password (def. env[SMTP_PASSWORD])", required=False, prompt=False)
@click.option('-s', '--send-email', type=bool, help = 'Send the confirmation email (def. False)', required=False, default=False, is_flag=True, prompt=False)
@click.option('-n', '--send-email-only', help = 'Only send the confirmation email (def. False)', required=False, type=bool, is_flag=True, prompt=False, default=False)
@click.option('-v', '--verbose', 'opt_verbose', type=bool, help="Verbose output for humans (def. no)", is_flag=True, default=False, required=False)
@pass_session
def register(session, url : str, email : str, smtp_user: str, smtp_pwd : str, send_email : bool, send_email_only : bool, secret : str, opt_verbose : bool):
    """Register a new account via email address."""
    
    # Assignment to avoid the 'referenced before assignment' error
    email_body = None
    recipient = None
    
    # Verbose Output
    utils.banner(opt_verbose)
    
    if url == "" or url == None:
        # Retrieves the URLs elements from the config
        scheme = session.config_get("scheme")
        host = session.config_get("host")
        port = session.config_get("port")
        release = session.config_get("release")
    else:
        # Parses the URL
        parsed_url = urlparse(url)
        scheme = parsed_url.scheme
        host = parsed_url.hostname
        port = parsed_url.port
        release = parsed_url.path.split("/")[2]
    
    if scheme == None:
        scheme = click.prompt("Scheme", type=str, default="https", show_default=True)
        session.config_set("scheme", scheme)
    
    if host == None:
        host = click.prompt("Host", type=str, default="127.0.0.1", show_default=True)
        session.config_set("host", host)
        
    if port == None:
        port = click.prompt("Port", type=int, default=8000, show_default=True)
        session.config_set("port", port)
    
    if release == None:
        release = click.prompt("Release (def. 1)", type=int, default=1)
        session.config_set("release", release)

    if email == None:
        email = session.config_get("email")
        if email == None:
            email = click.prompt("Email", type=str)
            session.config_set("email", email)
        if email == "" or email == None:
            click.echo(f'\nEmail required for registration.\n')
            return

    if smtp_user == None:
        smtp_user = session.config_get("email_user")
        if smtp_user == None:
            smtp_user = click.prompt("Email Username", type=str, default=email)
            session.config_set("email_user", smtp_user)

    if smtp_pwd == None:
        smtp_pwd = os.getenv("SMTP_PASSWORD")

    # Gets the API URL
    if url == None or url == "":
        url = session.get_service_url()
    
    # Retrieves the registration secret
    if secret == None:
        secret = session.config_get("secret")
        if secret == None or secret == "":
            secret = click.prompt("Registration Secret (Needed for future authentications)", type=str, hide_input=True)
            if secret == "" or secret == None:
                click.echo(f'\Secret is required for registration.\n')
                return

    # calculates the token value SHA256(email + nonce)
    token, nonce = utils.get_registration_token(email, secret)
    if not token or not nonce:
        click.echo(f'\nCannot generate the .\n')
        return

    if not send_email_only:
        if (opt_verbose > 0):
            click.echo(f'New Registration ({email}):')
            click.echo(f'- Server Url ...: {url}' + APP_ROUTES['account'] + '/registration')
            click.echo(f'- Token ........: {token[:10]} ... {token[-10:]}')
        
        try:
            # Posts the nonce
            res = session.post(route=f"{APP_ROUTES['account']}/registration",
                            body={ "token" : token, "secret" : secret },
                            include_auth=False)
            
            # Builds the API reply message
            apiReply = ApiReplyMessage(res)
            if not apiReply or apiReply.is_error:
                if opt_verbose > 0:
                    click.echo(f'\nError: {res}\n')
                else:
                    click.echo(f'\nError, Please Try Again.\n')
                return

            # Let's get the recipient's email
            recipient = apiReply.data.get("send_to")
            if recipient:
                session.config_set("recipient", recipient)
            email_body = apiReply.data.get("message")
        
        except Exception as exception:
            if opt_verbose > 0:
                click.echo(f'\nError: {exception}\n')
                click.echo(f'\nNetwork Error, Please check the configuration ({session.config_path}) and Try Again.\n')
            else:
                click.echo(f'\nError, Please Try Again.\n')
            sys.exit(1)
        
        # Lets have some extra output
        if opt_verbose > 0:
            click.echo(f"- Registration Information Sent (token: {token[:10]} ... {token[-10:]})")
        
    # Updates the registration nonce
    if not session.config_get("secret"):
        save_secret = click.prompt("Do you want to save the secret in ~/.pyconnect/config.json (def. No)", type=bool, default=False)
        if save_secret == True:
            session.config_set("secret", secret)

    # Let's create the email message
    email_msg = EmailMessage()
    
    # Let's check if we have a body already
    if email_body:
        email_msg.set_content(email_body)
    else:
        email_msg.set_content(f'token: {token}')
    
    # Now let's check for the recipient
    if not recipient:
        recipient = session.config_get("recipient")
        if not recipient:
            recipient = click.prompt("Recipient Email", type=str)
            if not recipient or recipient == "":
                click.echo(f'\nRecipient email is required for registration.\n')
                return
            session.config_set("recipient", recipient)
    
    # Sets the email headers
    email_msg['Subject'] = 'Registration'
    email_msg['From'] = email
    email_msg['To'] = recipient

    # If the email does not need to be sent, all done
    if not send_email:
        if opt_verbose:
            click.echo(f'\nRegistration successful.\n\nSend the following message to complete the process:')
            click.echo(f"\n  From: {email}\n  To: {recipient}\n  Subject: Registration\n")
            click.echo(f"  {email_msg.get_content()}\n\n")
        else:
            click.echo(f'{{ "to": "{recipient}", "token": "{token}" }}')
        return

    if opt_verbose:
        click.echo(f'- Sending Confirmation E-Mail ({recipient})')

    # Lets get the SMTP port
    smtp_port = session.config_get("smtp_port")
    if smtp_port == None:
        smtp_port = 465
        session.config_set("smtp_port", smtp_port)
    
    # Let's see if we have a SMTP host or domain
    smtp_host = session.config_get("smtp_host")
    if not smtp_host:
        smtp_domain = session.config_get("smtp_domain")
        if not smtp_domain:
            smtp_domain = email.split('@')[1]
            session.config_set("smtp_domain", smtp_domain)
        # Resolves the domain
        smtp_host = utils.dns_resolve(smtp_domain)[0]
        
    # Let's send the email
    email_tools.send_msg(session,
                         from_addr=email,
                         to_addr=recipient,
                         msg=email_msg,
                         pwd=smtp_pwd,
                         verbose=opt_verbose,
                         debug=False)
    
    if opt_verbose:
        click.echo(f'- All Done.\n')

@click.command()
@click.option('-e', '--email', 'opt_email', required=False, type=str, prompt=False)
@click.option('-n', '--nonce', 'opt_nonce', required=False, type=str, prompt=False)
@click.option('-v', '--verbose', 'opt_verbose', type=bool, help="Verbose output for humans (def. no)", is_flag=True, default=False, required=False)
@pass_session
def token(session, opt_email, opt_nonce, opt_verbose):
    """Returns the registration token for the given email and secret."""
    utils.banner(opt_verbose)
    
    # Checks if the email is provided
    if not opt_email or opt_email == "":
        opt_email = session.config_get("email")
        if opt_email == None:
            print(f'\nEmail addres is required for token generation.\n')

    # Checks if the nonce is provided
    if not opt_nonce or opt_nonce == "":
        opt_nonce = session.config_get("nonce")
        if opt_nonce == None:
            print(f'\nNonce is required for token generation.\n')
            return
    
    # calculates the token value SHA256(email + nonce)
    digest = utils.get_registration_token(opt_email, opt_nonce)
    
    # Let's return the calculated value
    if opt_verbose:
        click.echo(f'\nNew Token ({opt_email}):')
        click.echo(f'  > nonce .......: {opt_nonce}')
        click.echo(f'  > token .......: {digest}\n')
    else:
        click.echo(digest)
        
@click.command()
@click.option('-u', '--url', required=False, type=str, prompt=False, default=None)
@click.option('-s', '--secret', required=False, type=str, prompt=False, hide_input=True)
@click.option('-e', '--email', required=False, type=str, prompt=False)
@click.option('-u', '--smtp-user', type=str, help="SMPT username (def. <email_addr>)", required=False, prompt=False)
@click.option('-p', '--smtp-password', 'smtp_pwd', type=str, help="SMPT password (def. env[SMTP_PASSWORD])", required=False, prompt=False)
@click.option('-s', '--send-email', type=bool, help = 'Send the confirmation email (def. False)', required=False, default=False, is_flag=True, prompt=False)
@click.option('-n', '--send-email-only', help = 'Only send the confirmation email (def. False)', required=False, type=bool, is_flag=True, prompt=False, default=False)
@click.option('-v', '--verbose', 'opt_verbose', type=bool, help="Verbose output for humans (def. no)", is_flag=True, default=False, required=False)
@pass_session
def remove(session, url : str, email : str, smtp_user: str, smtp_pwd : str, send_email : bool, send_email_only : bool, secret : str, opt_verbose : bool):
    """Register a new account via email address."""