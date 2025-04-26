
import click

import json
import time

import dns.resolver as dns

from InquirerPy import prompt

from ..lib import session
from ..lib import tables
from ..lib import utils
from ..lib import timeutil

pass_session = click.make_pass_decorator(session.OWTSession)

@click.command("config")
@click.option('-s', '--set', type=bool, is_flag=True, help="Updates the configuration (def. off)", required=False, prompt=False)
@click.option('-p', '--pwd', type=str, help="Master Password (required)", required=False, prompt=True, hide_input=True)
@click.option('-h', '--host', type=str, help="Certbot service hostname (def. 127.0.0.1)", required=False, prompt=False)
@click.option('-t', '--port', type=int, help="Certbot service port number (def. 443)", required=False, prompt=False)
@click.option('-e', '--email', type=str, help="Email address for the cerificate (def. me@example.com)", required=False, prompt=False)
@click.option('-i', '--smtp-host', type=str, help="SMTP hostname (def. None)", required=False, prompt=False)
@click.option('-j', '--smtp-port', type=int, help="SMTP port number (def. 465)", required=False, prompt=False)
@click.option('-k', '--smtp-user', type=str, help="SMTP username (def. <email_addr>)", required=False, prompt=False)
@click.option('-q', '--imap-host', type=str, help="IMAP hostname (def. None)", required=False, prompt=False)
@click.option('-r', '--imap-port', type=int, help="IMAP port number (def. 465)", required=False, prompt=False)
@click.option('-s', '--imap-user', type=str, help="IMAP username (def. <email_addr>)", required=False, prompt=False)
@click.option('-v', '--verbose', 'opt_verbose', type=bool, help="Verbose output for humans (def. no)", is_flag=True, default=False, required=False)
@pass_session
def config(session,
           host : str,
           port : int,
           email : int,
           smtp_host : str,
           smtp_port: int,
           smtp_user: str,
           imap_host : str,
           imap_port: int,
           imap_user: str,
           opt_verbose: bool):
    """Manage Endpoint and Mail integration configuration"""

    # Some nice banner info
    utils.banner(opt_verbose)
    
    # Supported Scheme for the API
    scheme = "https"
    
    # Supported API Version
    release = 1
    
    # if scheme and scheme != "":
    #     if scheme not in ["http", "https"]:
    #         click.echo(f'Error, Invalid scheme: {scheme}')
    #         return
    #     else:
    #         if (opt_verbose):
    #             print(f"  > Setting scheme to {scheme}")
    #         session.config_set("scheme", scheme)
   
    # Retrieves the Host Configuration, defaults to
    # 127.0.0.1 for development and testing, while
    # the production environment uses the actual
    # hostname of the service (e.g. api.openwebtrust.org)
    if host and host != "":
        if len(host) < 5 or host.find(".") == -1:
            print(f'Error, Invalid host: {host}\n')
            return
        else:
            if (opt_verbose):
                print(f"  > Setting host to {host}")
            session.config_set("host", host)
    
    if port:
        if port not in range(1, 65535):
            print(f'Error, Invalid port: {port}\n')
        else:
            if (opt_verbose):
                print(f"  > Setting port to {port}")
            session.config_set("port", port)

    if release:
        if release not in range(1, 255):
            print(f'ERROR: release value out of range [1..255]: {release}\n')
        if (opt_verbose):
            print(f"  > Setting release to {release}")
        session.config_set("release", release)
    
    if email and email != "":
        if email.find("@") == -1:
            print(f'ERROR: Invalid email address: {email}\n')
            return
        else:
            if (opt_verbose):
                print (f"  > Setting email to {email}")
            session.config_set("email", email)
    else:
        email = session.config_get("email")

    # SMTP Configuration
    if smtp_user and smtp_user != "":
        if (opt_verbose):
            print (f"  > Setting SMTP username to {smtp_user}")
        session.config_set("smtp_user", smtp_user)
    
    if smtp_host and smtp_host != "":
        session.config_set("smtp_host", smtp_host)
        
    else:
        smtp_host = session.config_get("smtp_host")
        if not smtp_host:
            smtp_domain = session.config_get("smtp_domain")
            
            if not smtp_domain:
                smtp_domain = email.split('@')[1]

            for x in dns.resolve(smtp_domain, 'MX'):
                if x and x.to_text() != "":
                    smtp_host = x.to_text().split(' ')[1][:-1]
                    if (opt_verbose):
                        print (f"  > Setting SMTP domain to {smtp_domain}")
                    session.config_set("smtp_domain", smtp_domain)
                    break
                
            if not smtp_host:
                if (opt_verbose):
                    print (f"  > Setting SMTP domain to {smtp_domain}")
                smtp_domain = email.split('@')[1]
                session.config_set("smtp_domain", smtp_domain)

    if smtp_port:
        if smtp_port not in range(1, 65535):
            print(f'Error: invalid SMTP port: {smtp_port}\n')
            exit(1)
        else:
            if (opt_verbose):
                print(f"  > Setting SMTP port to {smtp_port}")
            session.config_set("smtp_port", smtp_port)

    if smtp_user and smtp_user != "":
        if (opt_verbose):
            print (f"  > Setting SMTP username to {smtp_user}")
        session.config_set("smtp_user", smtp_user)
    
    # IMAP Configuration
    if imap_host and imap_host != "":
        session.config_set("imap_host", imap_host)
        
    else:
        imap_host = session.config_get("imap_host")

    if imap_port:
        if imap_port not in range(1, 65535):
            print(f'Error: invalid SMTP port: {imap_port}\n')
            exit(1)
        else:
            if (opt_verbose):
                print(f"  > Setting SMTP port to {imap_port}")
            session.config_set("imap_port", imap_port)
    
    if imap_user and imap_user != "":
        if (opt_verbose):
            print (f"  > Setting IMAP username to {imap_user}")
        session.config_set("imap_user", imap_user)

    # Let's get the full URL
    url = session.get_service_url()
    
    if opt_verbose:
        click.echo(f'\nUpdated Endpoint Configuration ({email}):')
        click.echo(f'- url ......: {url}\n')
        


@click.command("set")
@click.option('-t', '--host', type=str, help="Target hostname (def. 127.0.0.1)", required=False, prompt=False)
@click.option('-p', '--port', type=int, help="Port number (def. 443)", required=False, prompt=False)
@click.option('-r', '--release', type=int, help="Target API Version (def. 1)", required=False, prompt=False)
@click.option('-s', '--scheme', type=str, help="Target API Scheme (def. https)", required=False, prompt=False)
@click.option('-e', '--email', type=str, help="Email From: address (def. me@example.com)", required=False, prompt=False)
@click.option('-m', '--smtp-host', type=str, help="SMTP hostname (def. None)", required=False, prompt=False)
@click.option('-o', '--smtp-port', type=int, help="SMTP port number (def. 465)", required=False, prompt=False)
@click.option('-u', '--smtp-user', type=str, help="SMTP username (def. <email_addr>)", required=False, prompt=False)
@click.option('-d', '--smtp-domain', type=str, help="SMTP domain (def. <email_domain>)", required=False, prompt=False)
@click.option('-m', '--imap-host', type=str, help="IMAP hostname (def. None)", required=False, prompt=False)
@click.option('-o', '--imap-port', type=int, help="IMAP port number (def. 465)", required=False, prompt=False)
@click.option('-u', '--imap-user', type=str, help="IMAP username (def. <email_addr>)", required=False, prompt=False)
@click.option('-v', '--verbose', 'opt_verbose', type=bool, help="Verbose output for humans (def. no)", is_flag=True, default=False, required=False)
@pass_session
def set_option(session, 
               host : str,
               port : int,
               release : int,
               scheme : str,
               email: str,
               smtp_host : str,
               smtp_port: int,
               smtp_user: str,
               smtp_domain: str,
               imap_host : str,
               imap_port: int,
               imap_user: str,
               opt_verbose: bool):
    """Set the Endpoint configuration for the API"""
    utils.banner(opt_verbose)

    if opt_verbose:
        print(f"Applying Configuration Changes:")

    if scheme and scheme != "":
        if scheme not in ["http", "https"]:
            click.echo(f'Error, Invalid scheme: {scheme}')
            return
        else:
            if (opt_verbose):
                print(f"  > Setting scheme to {scheme}")
            session.config_set("scheme", scheme)
   
    if host and host != "":
        if len(host) < 7:
            print(f'Error, Invalid host: {host}\n')
            return
        else:
            if (opt_verbose):
                print(f"  > Setting host to {host}")
            session.config_set("host", host)
    
    if port:
        if port not in range(1, 65535):
            print(f'Error, Invalid port: {port}\n')
        else:
            if (opt_verbose):
                print(f"  > Setting port to {port}")
            session.config_set("port", port)

    if release:
        if release not in range(1, 255):
            print(f'ERROR: release value out of range [1..255]: {release}\n')
        if (opt_verbose):
            print(f"  > Setting release to {release}")
        session.config_set("release", release)
    
    if email != None and email != "":
        if email.find("@") == -1:
            print(f'ERROR: Invalid email address: {email}\n')
            return
        else:
            if (opt_verbose):
                print (f"  > Setting email to {email}")
            session.config_set("email", email)
    else:
        email = session.config_get("email")

    # SMTP Configuration
    if smtp_user and smtp_user != "":
        if (opt_verbose):
            print (f"  > Setting SMTP username to {smtp_user}")
        session.config_set("smtp_user", smtp_user)
    
    if smtp_host and smtp_host != "":
        session.config_set("smtp_host", smtp_host)
        
    else:
        smtp_host = session.config_get("smtp_host")
        if not smtp_host:
            smtp_domain = session.config_get("imap_domain")
            
            if not smtp_domain and email:
                smtp_domain = email.split('@')[1]

            if smtp_domain:
                for x in dns.resolve(smtp_domain, 'MX'):
                    if x and x.to_text() != "":
                        smtp_host = x.to_text().split(' ')[1][:-1]
                        if (opt_verbose):
                            print (f"  > Setting SMTP domain to {smtp_domain}")
                        session.config_set("smtp_domain", smtp_domain)
                        break
                
            # if not smtp_host:
            #     if (opt_verbose):
            #         print (f"  > Setting SMTP domain to {smtp_domain}")
            #     smtp_domain = email.split('@')[1]
            #     session.config_set("smtp_domain", smtp_domain)

    if smtp_port:
        if smtp_port not in range(1, 65535):
            print(f'Error: invalid SMTP port: {smtp_port}\n')
            exit(1)
        else:
            if (opt_verbose):
                print(f"  > Setting SMTP port to {smtp_port}")
            session.config_set("smtp_port", smtp_port)

    if smtp_user and smtp_user != "":
        if (opt_verbose):
            print (f"  > Setting SMTP username to {smtp_user}")
        session.config_set("smtp_user", smtp_user)
    
    # IMAP Configuration
    if imap_host and imap_host != "":
        session.config_set("imap_host", imap_host)
        
    else:
        imap_host = session.config_get("imap_host")

    if imap_port:
        if imap_port not in range(1, 65535):
            print(f'Error: invalid SMTP port: {imap_port}\n')
            exit(1)
        else:
            if (opt_verbose):
                print(f"  > Setting SMTP port to {imap_port}")
            session.config_set("imap_port", imap_port)
    
    if imap_user and imap_user != "":
        if (opt_verbose):
            print (f"  > Setting IMAP username to {imap_user}")
        session.config_set("imap_user", imap_user)

    # Let's get the full URL
    url = session.get_service_url()
    
    if opt_verbose:
        click.echo(f'\nUpdated Endpoint Configuration ({email}):')
        click.echo(f'- url ......: {url}\n')

@click.command("get")
@click.option('-o', '--option', type=str, help="Configuration option to display (leave blank for all)", required=False, prompt=False, default=None)
@click.option('-v', '--verbose', type=bool, help="Verbose output for humans (def. no)", is_flag=True, default=False)
@pass_session
def get_option(session, option: str, verbose: bool):
    """Show the configured URL for API endpoint"""
    utils.banner(verbose)
    if option and option == "url":
        value = session.get_service_url()
        click.echo(f'{option} = {value}')
    elif option:
        value = session.config_get(option)
        click.echo(f'{option} = {value}')
    else:
        for opt in session.config.keys():
            value = session.config_get(opt)
            click.echo(f'{opt} = {value}')
    if verbose:
        if option:
            click.echo('')
        else:
            email = session.config_get("email")
            url = session.get_service_url()
            click.echo(f'\nUpdated Endpoint Configuration ({email}):')
            click.echo(f'- url ......: {url}\n')
