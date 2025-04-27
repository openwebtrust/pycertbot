# pycertbot
Python Certificate Manager for the Open Web Trust Community

## Introduction

This is a Python Certificate Manager for the Open Web Trust Community. It is a simple command line tool that allows you to manage your certificates and keys in a simple and secure way.

## Installation

To install the certificate manager, you need to have Python 3.6 or higher installed on your system. You can install the certificate manager using pip:

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install .
```

For development installation, you might want to use an editable install. Use the `-e` flag for development:

```
python3 -m venv .venv
. .venv/bin/activate
pip install -e .
```

## Usage

The `pycertbot` tool provides a variety of commands to manage certificates and accounts. The main
script to use is the `pycertbot` command. You can run it from the command line as follows:

```bash
pycertbot [command] [options]
```
You can replace `[command]` with any of the available commands and `[options]` with the
appropriate options for that command.

Below is a list of the available commands, options, and their descriptions:

### Certificate Management (pycertbot.py cert [OPTIONS])
- **`create`**: Generate a new certificate.
- **`renew`**: Renew an existing certificate.
- **`list`**: Display a list of all certificates.
- **`show`**: View detailed information about a specific certificate.
- **`import`**: Import an existing certificate into the system.
- **`export`**: Export a certificate for external use.
- **`install`**: Install a certificate on the system.
- **`check`**: Check the status of a certificate.
- **`verify`**: Verify the validity of a certificate.

### Account Management (pycertbot.py my [OPTIONS])
- **`register`**: Register a new account with the certificate manager.
- **`login`**: Log in to an existing account.
- **`logout`**: Log out of the current account.
- **`delete`**: Remove an existing account from the system.

### Configuration Management (pycertbot.py config [OPTIONS])
- **`set`**: Set a specific configuration option.
- **`get`**: Retrieve the value of a configuration option.

### Help and Support
- **`help`**: Display help information for the tool or specific commands.

For more details on how to use a specific command, run:

```bash
pycertbot [command] --help
```

For more information on how to use the certificate manager, run the `certbot help` command.

## Support

If you have any questions or need help with the certificate manager, please contact us at
support@openwebtrust.org or visit our website at [www.openwebtrust.org](https://www.openwebtrust.org).

## Acknowledgements

This project is supported by the Open Web Trust Community. We would like to thank all our
contributors for their help and support.

## Contributing

If you would like to contribute to the certificate manager, please fork the repository and
submit a pull request. We welcome all contributions. At Open Web Trust Community, we believe
in the power of open source software and the community that supports it and we strive to
deliver the best possible experience for our users.

If you have any questions or need help with contributing, please contact us at:

  - contributions@openwebtrust.org

Looking forward to your contributions and feedback!

Thank you for using pyCertBot!
