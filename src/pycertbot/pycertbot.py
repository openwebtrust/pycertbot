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

# API Imports
from pycertbot.routes import account, certificate, config

# Session Import
from pycertbot.utils.session import OWTSession
from pycertbot.utils.defaults import OWT_CONFIG

# Sets the Configuration Object
GlobConfig = OWT_CONFIG

# Defines the Session Decorator Object
pass_session = click.make_pass_decorator(OWTSession)

# ==========
# Entrypoint
# ==========

@click.group()
@click.pass_context
def __start__(ctx):
    """PyCertbot Tool."""
    ctx.obj = OWTSession()

# =============
# Configuration
# =============

@click.group()
def conf():
    """Manage settings"""

conf.add_command(config.get_option)
conf.add_command(config.set_option)

# Adds the conf command to the main entrypoint
__start__.add_command(conf)

# ======================
# Certificate Management
# ======================

@click.group()
def cert():
    """Manage certificates"""

cert.add_command(certificate._import)
cert.add_command(certificate._export)

__start__.add_command(cert)

# ==================
# Account Management
# ==================

__start__.add_command(account.login)
__start__.add_command(account.logout)
__start__.add_command(account.register)
__start__.add_command(account.remove)

