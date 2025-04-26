# Description: OWT Session Object
import errno
from pprint import pprint
import sys
import os
import click
import json
import requests

import time

from pathlib import Path
from enum import Enum

from requests_toolbelt.multipart.encoder import MultipartEncoder, MultipartEncoderMonitor

from .crypto import JSONSec, owt_master_secret_is_set, owt_set_master_secret
from .defaults import APP_ROUTES

class OWTConfig(Enum):
    API_VERSION = 1
    BASE_API_URL = "api/"
    # SCHEMA_DEFAULT = "https"
    SCHEMA_DEFAULT = "https"
    # PORT_DEFAULT = 8000
    PORT_DEFAULT = 8000
    # URL_DEFAULT = "pycertbot.openwebtrust.org"
    URL_DEFAULT = "127.0.0.1"

class OWTSession:
    """OWT Session Object."""
    def __init__(self):
        home = str(Path.home())
        self.base_api_url = OWTConfig.SCHEMA_DEFAULT.value + "://" + \
            OWTConfig.URL_DEFAULT.value + ":" + str(OWTConfig.PORT_DEFAULT.value) + \
            OWTConfig.BASE_API_URL.value + "v" + str(OWTConfig.API_VERSION.value) + "/"
        self.config_path = os.path.join(home, ".pycertbot/config.json")
        self.download_path = os.path.join(home, "Downloads")
        self.config = {
            'default' : {}
        }
        self.verbose = False

        if (os.path.isfile(self.config_path)):
            try:
                f = open(self.config_path, "r")
                enc_config_json = f.read()
                # Checks for the master secret, if not there, let's ask for it
                if not owt_master_secret_is_set():
                    secret = click.prompt("Enter the master secret", type=str, hide_input=True)
                    owt_set_master_secret(secret)
                    if not secret:
                        raise Exception("Secret or Data not set")
            
                config_json = JSONSec(enc_data = enc_config_json).data
                self.config = json.loads(config_json)
                self.base_api_url = self.config["url"]
            except:
                pass

                    # ===============
                    # Private Methods
                    # ===============

    def _owt_config_full_url(self, route):
        
        # Gets the base API URL
        base_api_url = self.config_url()
        if base_api_url == None:
            raise Exception("No value found for base API URL")
        
        # let's remove the trailing slash
        if base_api_url[-1] == "/":
            base_api_url = base_api_url[:-1]

        # let's make sure the initial slash is present in the route
        if route[0] != "/":
            route = "/" + route

        # Returns the full API URL properly formatted
        return f"{base_api_url}{route}"

    def _owt_headers(self, include_auth=True):
        headers = {"Content-Type": "application/json"}
        token = self.config.get("token")
        
        if include_auth == True:
            if not token:
                print("\n    WARNING: No token found in config file.\n")
            else:
                headers["Authorization"] = f"Bearer {token}"

        return headers

    def _owt_req_inputs(self, route, body=None, include_auth=True):
        
        full_url = self._owt_config_full_url(route)
        if not full_url:
            raise Exception("No value found for full URL")
        
        headers = self._owt_headers(include_auth=include_auth)
        if not headers:
            raise Exception("No value returned for headers")
        
        data = None
        if body != None:
            data = json.dumps(body)

        return full_url, headers, data 

    def _owt_write_config(self):
        # make directories if needed
        if not os.path.exists(os.path.dirname(self.config_path)):
            try:
                os.makedirs(os.path.dirname(self.config_path))
            except OSError as exc: 
                if exc.errno != errno.EEXIST:
                    raise

        # Checks for the master secret, if not there, let's ask for it
        if not owt_master_secret_is_set():
            secret = click.prompt("Enter the master secret", type=str, hide_input=True)
            owt_set_master_secret(secret)
            if not secret:
                raise Exception("Secret or Data not set")

        # Encrypt the configuration
        enc_data = JSONSec(data = self.config).enc_json
        print(repr(enc_data['data']))
        enc_data = json.dumps(enc_data)

        # write file
        f = open(self.config_path, "w")
        f.write(enc_data)
        f.close()
        
    def _owt_check_download(self):
        # make directories if needed
        if not os.path.exists(os.path.dirname(self.download_path)):
            try:
                os.makedirs(os.path.dirname(self.download_path))
            except OSError as exc: 
                if exc.errno != errno.EEXIST:
                    raise

    def _owt_get_anonymous(self, route):
        full_url, headers, data = self._owt_req_inputs(route=route, body=None, include_auth=False)
        r = requests.get(full_url, headers=headers)
        if r.status_code <= 400:
            return r.json()
        else:
            raise Exception(f"\n    ERROR(s): GET ({route}) (NO AUTH): {r.json()['detail'][0]}\n")

    def _owt_put_anonymous(self, route, body):
        full_url, headers, data = self._owt_req_inputs(route=route, body=body, include_auth=False)
        r = requests.put(full_url, data=data, headers=headers)
        if r.status_code <= 400:
            return r.json()
        else:
            raise Exception(f"\n    ERROR(s): PUT ({route}) [NO AUTH]: {r.json()['detail'][0]}\n")

    def _owt_get_authorized(self, route):
        full_url, headers, data = self._owt_req_inputs(route=route, body=None, include_auth=True)
        r = requests.get(full_url, headers=headers)
        if r.status_code <= 400:
            return r.json()
        else:
            raise Exception(f"\n    ERROR(s): GET ({route}): {r.json()['detail'][0]}\n")

                    # ===============
                    # Exported Methods
                    # ===============


    # ---------------------
    # Configuration Methods
    # ---------------------
                    
    def config_get(self, key, account : str = 'default'):
        account_config = self.config.get(account, None)
        if account_config == None:
            raise Exception(f"Account {account} not found in config file.")
        return account_config.get(key, None)

    def config_set(self, key, value, account : str = 'default'):
        self.config[key] = value
        # update config file
        self._owt_write_config()

        if self.verbose:
            click.echo(f"  config[{key}] = {value}", file=sys.stderr)

    def config_print(self):
        for account, account_config in self.config.items():
            click.echo(f"Account: {account}", file=sys.stderr)
            for key, value in account_config.items():
                click.echo(f"> config[{key}] = {value}", file=sys.stderr)

    def get_service_url(self):
        scheme = self.config.get("scheme", OWTConfig.SCHEMA_DEFAULT.value)
        host = self.config.get("host", OWTConfig.URL_DEFAULT.value)
        port = self.config.get("port", OWTConfig.PORT_DEFAULT.value)
        release = self.config.get("release", OWTConfig.API_VERSION.value)
        return f"{scheme}://{host}:{port}/api/v{release}"

    # ---------------
    # Network Methods
    # ---------------
        
    def get(self, route, use_auth = True):
        if use_auth:
            return self._owt_get_authorized(route)
        else:
            return self._owt_get_anonymous(route)

    def patch(self, route, body):
        full_url, headers, data = self._owt_req_inputs(route=route, body=body, include_auth=True)
        r = requests.patch(full_url, data=data, headers=headers)
        if r.status_code <= 400:
            return r.json()
        else:
            raise Exception(f"\n    ERROR(s): PATCH ({route}): {r.json()['detail'][0]}\n")

    def post(self, route, body, include_auth = True):
        full_url, headers, data = self._owt_req_inputs(route=route, body=body, include_auth=include_auth)
        r = requests.post(full_url, data=data, headers=headers)
        
        if r.status_code <= 400:
            return r.json()
        
        elif r.status_code == 422:
            details = r.json()['detail'][0]
            location = '::'.join(details['loc'])
            msgText = f"\n     ERROR(s): POST ({route}): type = {details['type']}, msg = {details['msg']}, location = {location}\n\n"
            raise Exception(msgText)
        
        else:
            raise Exception(f"\n    ERROR(s): POST ({route}): {r.json()['detail'][0]}\n")

    def put(self, route, body):
        full_url, headers, data = self._owt_req_inputs(route=route, body=body, include_auth=True)
        r = requests.put(full_url, data=data, headers=headers)
        if r.status_code <= 400:
            return r.json()
        elif r.status_code == 422:
            details = r.json()['detail'][0]
            location = '::'.join(details['loc'])
            msgText = f"\n     ERROR(s): PUT ({route}): type = {details['type']}, msg = {details['msg']}, location = {location}\n\n"
            return Exception(msgText)
        else:
            raise Exception(f"\n    ERROR(s): PUT ({route}): {r.json()['detail'][0]}\n")

    def delete(self, route):
        full_url, headers, data = self._owt_req_inputs(route=route, include_auth=True)
        r = requests.delete(full_url, headers=headers)
        if r.status_code <= 400:
            return r
        else:
            raise Exception(f"\n    ERROR(s): DELETE ({route}): {r.json()['message']}\n")

    # ---------------------
    # File Transfer Methods
    # ---------------------

    def get_download(self, route, delay_ms=None, chunk_size=128, file_extension=".zip"):
        # verify downloads dir exists
        self._owt_check_download()
        full_url, headers, data = self._owt_req_inputs(route=route, include_auth=True)

        click.echo("Download started.")
        r = requests.get(full_url, headers=headers, stream=True)

        # check for intentional delay. convert to seconds if one is provided
        delay_s = delay_ms / 1000 if delay_ms != None else None

        if r.status_code <= 400:
            # determine download size
            total_length = r.headers.get('content-length')
            total_length = int(total_length) if total_length != None else None

            # setup download filename
            filename = f"download{file_extension}"
            content_disposition = r.headers.get("Content-Disposition")
            if content_disposition != None:
                cd_split = content_disposition.split("attachment; filename=")
                filename = cd_split[1] if len(cd_split) > 1 else filename
            filepath = os.path.join(self.download_path, filename)

            # if we know the length, provide a progress bar
            if total_length != None:
                with click.progressbar(length=total_length, label="Downloading archive") as bar:
                    with open(filepath, 'wb') as f:
                        for chunk in r.iter_content(chunk_size=chunk_size):
                            if delay_s != None:
                                time.sleep(delay_s)
                            f.write(chunk)
                            bar.update(chunk_size)
            else:
                with open(filepath, 'wb') as f:
                    for chunk in r.iter_content(chunk_size=chunk_size):
                        f.write(chunk)


            click.echo(f"Download finished: {filepath}")
        else:
            raise Exception(f"\n    ERROR(s): PATCH ({route}): {r.json()['message']}\n")

    def put_upload(self, route, mime_type="application/zip", delay_ms=None,  filepath=None, label=""):

        if filepath == None:
            return click.echo("No file provided.")

        full_url, msg_headers, data = self._owt_req_inputs(route=route, include_auth=True)
        encoder = MultipartEncoder(fields={'file': (os.path.basename(filepath), open(filepath, 'rb'), mime_type)})
        total_length = encoder.len

        with click.progressbar(length=total_length, label=label) as bar:
            def get_callback():
                def callback(monitor):
                    nonlocal bar
                    bar.update(monitor.bytes_read)
                return callback

            callback = get_callback()
            monitor = MultipartEncoderMonitor(encoder, callback)

            # Fixes the content type
            msg_headers['Content-Type'] = monitor.content_type

            # Sends the Request
            r = requests.put(full_url, data=monitor, headers=msg_headers)

            if r.status_code <= 400:
                return r.json()
            elif r.status_code == 422:
                details = r.json()['detail'][0]
                location = '::'.join(details['loc'])
                msgText = f"\n     ERROR(s): PUT UPLOAD ({route}): type = {details['type']}, msg = {details['msg']}, location = {location}\n\n"
                return Exception(msgText)
            else:
                error_obj = r.json()
                message = error_obj['message'].strip('""')
                click.echo(f"\n\n    ERROR(s): PUT_UPLOAD ({route}): {r.json()['detail'][0]}\n")
                raise Exception(f"{error_obj['statusCode']} - {error_obj['enum']}")

    # -------------
    # Vault Methods
    # -------------
    
    def vault(self, data):
        # Retrieve the Json response from the vault
        r = self.post(self, route=APP_ROUTES["valut"], body={ "data" : data })
        print(repr(r))
        return r