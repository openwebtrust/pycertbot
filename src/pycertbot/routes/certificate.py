
import click

import json
import time

import dns.resolver as dns

from InquirerPy import prompt

from .lib import session
from .lib import tables
from .lib import utils
from .lib import timeutil

pass_session = click.make_pass_decorator(session.OWTSession)

@click.command("export")
@click.option('-p', '--pwd', type=str, help="Master password (config enc/dec)", required=True, prompt=True)
@click.option('-o', '--out', type=str, help="Output file (def. stdout)", required=False, prompt=False)
@click.option('-f', '--format', type=str, help="Export Format (def. pfx, zip)", required=False, prompt=False)
@click.option('-s', '--secret', type=str, help="Export Encryption Secret", required=False, prompt=False)
@click.option('-v', '--verbose', 'opt_verbose', type=bool, help="Verbose output for humans (def. no)", is_flag=True, default=False, required=False)
@pass_session
def _export(session, pwd : str = None, out : str = None, format : str = None, secret : str = None, opt_verbose: bool = False):
    """Export the Certificate and Private Key"""
    utils.banner(opt_verbose)

    if opt_verbose:
        print(f"Exporting Certificate and Private Key:")

    # Load the configuration
    if not session.load_config(pwd):
        return

    # Export the Certificate and Private Key
    if not session.export_cert(out, format, secret):
        return

    # Done
    print(f"Exported Certificate and Private Key to {out}")

    return


@click.command("import")
@click.option('-p', '--pwd', type=str, help="Master password (config enc/dec)", required=True, prompt=True)
@click.option('-i', '--input', type=str, help="Input file (def. stdin)", required=False, prompt=False)
@click.option('-f', '--format', type=str, help="Import Format (def. pfx, zip)", required=False, prompt=False)
@click.option('-s', '--secret', type=str, help="Import Encryption Secret", required=False, prompt=False)
@click.option('-v', '--verbose', 'opt_verbose', type=bool, help="Verbose output for humans (def. no)", is_flag=True, default=False, required=False)
@pass_session
def _import(session, pwd : str = None, input : str = None, format : str = None, secret : str = None, opt_verbose: bool = False):
    """Import the Certificate and Private Key"""
    utils.banner(opt_verbose)

    if opt_verbose:
        print(f"Importing Certificate and Private Key:")

    # Load the configuration
    if not session.load_config(pwd):
        return

    # Import the Certificate and Private Key
    if not session.import_cert(input, format, secret):
        return

    # Done
    print(f"Imported Certificate and Private Key from {input}")

    return
