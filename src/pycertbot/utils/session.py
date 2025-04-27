# Description: OWT Session Object
import errno
import sys
import os
import click
import json
import requests
import time

from pprint import pprint
from pathlib import Path
from enum import Enum

from requests_toolbelt.multipart.encoder import MultipartEncoder, MultipartEncoderMonitor

from pycertbot.utils.crypto import JSONSec, owt_master_secret_is_set, owt_set_master_secret
from pycertbot.utils.defaults import APP_ROUTES, OWT_CONFIG
from pycertbot.utils.logging import OWT_log_msg

# Exports
__all__ = [
    'OWTSession',
]

def has_token(session):
	token = session.config_get("token")
	has_token = True if token is not None else False
	if not has_token:
		OWT_log_msg("User attempted to access services without a valid token.")
	return has_token

class OWTSession:
    """OWT Session Object."""
    def __init__(self):
        home = str(Path.home())
        self.base_api_url = OWT_CONFIG.get('SCHEMA_DEFAULT', 'https') + "://" + \
            OWT_CONFIG.get('URL_DEFAULT', 'localhost') + ":" + str(OWT_CONFIG.get('PORT_DEFAULT', 443)) + \
            OWT_CONFIG.get('BASE_API_URL','') + "v" + str(OWT_CONFIG.get('API_VERSION', 1)) + "/"
        self.config_path = os.path.join(home, ".pycertbot/config.json")
        self.download_path = os.path.join(home, "Downloads")
        self.config = { "version": 1,
                        "download_path": self.download_path,
                        "base_api_url": self.base_api_url,
                        "host": OWT_CONFIG.get('URL_DEFAULT', 'localhost'),
                        "port": OWT_CONFIG.get('PORT_DEFAULT', 443),
                        "scheme": OWT_CONFIG.get('SCHEMA_DEFAULT', 'https'),
                        # "smtp_url": None,
                        # "smtp_user": None,
                        # "smtp_pwd": None,
                        # "smtp_domain": None,
                        # "smtp_from": None,
                        # "smtp_to": None,
                        # "imap_url": None,
                        # "imap_user": None,
                        # "imap_pwd": None,
                        # "imap_domain": None,
                        }
        
        self.verbose = False

        if (os.path.isfile(self.config_path)):
            try:
                
                # Checks for the master secret, if not there, let's ask for it
                if not owt_master_secret_is_set():
                    secret = click.prompt("Enter the master secret", type=str, hide_input=True)
                    if not secret:
                        OWT_log_msg("Secret or Data not set")
                        raise Exception("Secret or Data not set")
                    # Let's set the master secret
                    owt_set_master_secret(secret)
                    
            except Exception as e:
                OWT_log_msg(f"Exception while checking master secret: {e}")
                raise
                        
            try:
                enc_config_json = None
                with open(self.config_path, "r") as f:
                    enc_config_json = f.read()
                    f.close()

                # Sets the configuration data
                encrypted_config = JSONSec(enc_json=enc_config_json)
                
                # Decrypts the configuration data
                self.config = encrypted_config.data
                
                # Checks we got something for the config
                if not self.config:
                    OWT_log_msg("No data found in config file.", is_error=True, raise_exception=True)
                
                    required_fields = ["version", "base_api_url"]
                    for field in required_fields:
                        if field not in self.config:
                            OWT_log_msg(f"Missing required field in config: {field}", is_error=True, raise_exception=True)
                
            except(OSError, IOError):
                OWT_log_msg(f"Unable to read config file: {self.config_path}")
                raise

            except(Exception) as e:
                OWT_log_msg(f"Exception while parsing or decrypt config file: {e}")
                raise

                    # ===============
                    # Private Methods
                    # ===============

    def _owt_config_full_url(self, route):
        """Returns the full API URL for the given route.
        The URL is built using the base API URL and the route provided.
        The base API URL is retrieved from the configuration file.
        The route is appended to the base API URL to form the full URL.
        The trailing slash is removed from the base API URL and the leading slash is added to the route if not present.

        Args:
            route: The route to be appended to the base API URL.

        Raises:
            Exception: If no value is found for the base API URL.

        Returns:
            str: The full API URL.
        """
        
        # Gets the base API URL
        base_api_url = self.config_url()
        if base_api_url is None:
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
        """Returns the headers for the API request.
        
        Returns the headers for the API request and includes the content type and
        authorization token if provided. The content type is set to application/json.
        If the include_auth parameter is set to True, the authorization token is
        included in the headers. If the token is not found in the configuration file,
        a warning message is printed. The headers are returned as a dictionary.
        
        Args:
            include_auth (bool): If True, include the authorization token in the headers.
               If False, do not include the authorization token.
               
        Raises:
            Exception: If no value is found for the authorization token.
            
        Returns:
            dict: The headers for the API request.
        """
        
        headers = {"Content-Type": "application/json"}
        token = self.config.get("token")
        
        if include_auth is True:
            if not token:
                print("\n    WARNING: No token found in config file.\n")
            else:
                headers["Authorization"] = f"Bearer {token}"

        return headers

    def _owt_req_inputs(self, route, body=None, include_auth=True):
        """Returns the full URL, headers, and data for the API request.

        Args:
            route (str): The route to be appended to the base API URL.
            body (dict, optional): The body of the request. Defaults to None.
            include_auth (bool, optional): Whether to include authorization headers. Defaults to True.

        Raises:
            Exception: If no value is found for the full URL.
            Exception: If no value returned for headers.

        Returns:
            tuple: A tuple containing the full URL, headers, and data for the API request.
        """
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
            if not secret:
                raise Exception("Secret or Data not set")
            owt_set_master_secret(secret)

        try:
            # Encrypt the configuration
            enc_data = JSONSec(data=self.config).enc_json
            enc_data = json.dumps(enc_data)
        
        except Exception as e:
            print(f"Unable to encrypt configuration: {e}")
            raise
            
        # write file
        with open(self.config_path, "w") as f:
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
                    
    def config_get(self, key):
        return self.config.get(key, None)
        # account_config = self.config.get(account, None)
        # if account_config == None:
        #     raise Exception(f"Account {account} not found in config file.")

    def config_set(self, key, value):
        
        # Sets the key/velua pair
        self.config[key] = value
        
        # update config file
        self._owt_write_config()
        
        # account_config = self.config.get(account, None)
        # if account_config == None:
        #     raise Exception(f"Account {account} not found in config file.")
        # account_config[key] = value

        if self.verbose:
            click.echo(f"  config[{key}] = {value}", file=sys.stderr)

    def config_print(self):
        try:
            for key, value in self.config.items():
                click.echo(f"> config[{key}] = {value}", file=sys.stderr)
        except Exception as e:
            # No issues with empty configs
            click.echo(f"Unable to print config file: {e}", file=sys.stderr, err=True, color=True)
            
            pass

    def get_service_url(self):
        """Returns the service URL for the API request."""
        
        # Get the account config
        json_config = self.config
        
        # Build the URL using the account config
        scheme = json_config.get("scheme", OWT_CONFIG.get('SCHEMA_DEFAULT', 'https'))
        host = json_config.get("host", OWT_CONFIG.get('URL_DEFAULT', '127.0.0.1'))
        port = json_config.get("port", OWT_CONFIG.get('PORT_DEFAULT', 443))
        release = json_config.get("release", OWT_CONFIG.get('API_VERSION', 1))
        
        # Builds and returns the full URL
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