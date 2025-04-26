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

# API Imports
from .routes import my
from .routes import cert

# Sets the Configuration Object
GlobConfig = session.OWTConfig

# Defines the Session Decorator Object
pass_session = click.make_pass_decorator(session.OWTSession)

# ==========
# Entrypoint
# ==========

@click.group()
@click.pass_context
def __start__(ctx):
    """PyCertbot Tool."""
    ctx.obj = session.OWTSession()


# =============
# Configuration
# =============

__start__.add_command(config.get_option)
__start__.add_command(config.set_option)


# ==================
# Account Management
# ==================

__start__.add_command(my.login)
__start__.add_command(my.logout)
__start__.add_command(my.register)
__start__.add_command(my.remove)


# ======================
# Certificate Management
# ======================

__start__.add_command(cert._import)
__start__.add_command(cert._export)


