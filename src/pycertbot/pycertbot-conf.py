#    Copyright 2024 Open Web Trust and Massimiliano Pala
#    All Rights Reserved

#    Licensed under the Apache License, Version 2.0 (the "License");
#    you may not use this file except in compliance with the License.
#    You may obtain a copy of the License at

#        http://www.apache.org/licenses/LICENSE-2.0

#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS,
#    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#    See the License for the specific language governing permissions and
#    limitations under the License.

# Click Import   
import click

# Session Import
from .routes.lib import session, config

# Defines the Session Decorator Object
pass_session = click.make_pass_decorator(session.OWTSession)

# Entrypoint

@click.group()
@click.pass_context
def __start__(ctx):
    """Configuration Tool for OWT PyCertbot."""
    ctx.obj = session.OWTSession()


# Organizations

@click.group()
def account():
    """Manage account"""

account.add_command(account_cmds.login)
account.add_command(account_cmds.logout)
account.add_command(account_cmds.register)
account.add_command(account_cmds.token)

@click.group()
def organization():
    """Manage organizations"""

organization.add_command(organization_cmds.ls)
organization.add_command(organization_cmds.selected)
organization.add_command(organization_cmds.select)

# Products

@click.group()
def product():
    """Manage products"""

product.add_command(product_cmds.ls)

# Orders

@click.group()
def order():
    """Manage orders"""

order.add_command(order_cmds.ls)
order.add_command(order_cmds.create)
order.add_command(order_cmds.delete)
order.add_command(order_cmds.clear)
order.add_command(order_cmds.req)
# order.add_command(order_cmds.upload_csr)
order.add_command(order_cmds.refresh)
order.add_command(order_cmds.submit)
order.add_command(order_cmds.mkzip)
order.add_command(order_cmds.download)

# Renewal Tokens

@click.group()
def renewaltoken():
    """Manage Renewal Tokens"""

renewaltoken.add_command(renewal_token_cmds.ls)
renewaltoken.add_command(renewal_token_cmds.get)
renewaltoken.add_command(renewal_token_cmds.create)
renewaltoken.add_command(renewal_token_cmds.delete)
renewaltoken.add_command(renewal_token_cmds.config)
renewaltoken.add_command(renewal_token_cmds.enable)
renewaltoken.add_command(renewal_token_cmds.disable)

# Jobs

@click.group()
def job():
    """View jobs"""

job.add_command(job_cmds.ls)

# Settings

@click.group()
def config():
    """Manage settings"""

config.add_command(settings_cmds.set_option)
config.add_command(settings_cmds.get_option)

# Main routes
cli.add_command(account)
cli.add_command(organization)
cli.add_command(product)
cli.add_command(order)
cli.add_command(job)
cli.add_command(renewaltoken)
cli.add_command(config)


