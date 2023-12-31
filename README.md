# JSI CLI for Junos Devices

<!-- START doctoc generated TOC please keep comment here to allow auto update -->
<!-- DON'T EDIT THIS SECTION, INSTEAD RE-RUN doctoc TO UPDATE -->
**Table of Contents**

- [Description](#description)
- [Installation](#installation)
  - [Installation Steps:](#installation-steps)
- [Usage](#usage)
  - [Checking Installation and Getting Help](#checking-installation-and-getting-help)
  - [User Authentication](#user-authentication)
  - [Checking Logged-In User Information](#checking-logged-in-user-information)
  - [Org setting](#org-setting)
  - [Device Inventory Management](#device-inventory-management)
  - [Connecting Device to an Organization](#connecting-device-to-an-organization)
  - [Disconnecting Device to an Organization](#disconnecting-device-to-an-organization)
  - [Managing API Tokens](#managing-api-tokens)
  - [Resetting API Token](#resetting-api-token)
  - [Logging Out](#logging-out)
  - [HTTPS access test](#https-access-test)
  - [Phone home](#phone-home)
  - [Log level](#log-level)
- [Logging Sample](#logging-sample)
- [Note](#note)

<!-- END doctoc generated TOC please keep comment here to allow auto update -->

## Description
The JSI CLI is a command-line interface designed for Junos devices. This script offers a range of functionalities, including user authentication, organization and device management, and API token configuration, making it a comprehensive tool for managing Junos devices within the JSI ecosystem.

## Installation
To install the JSI CLI script as a Juniper Op script on Junos Devices, run this command on your Junos Device CLI terminal:

```shell
start shell command "curl -k -s https://raw.githubusercontent.com/simonrho/jsi-cli/main/install.sh | /bin/sh"
```

This command fetches and executes the installation script from this GitHub repository, ensuring you have the latest version of the CLI.

### Installation Steps:

1. The `jsi-cli` script will be downloaded and installed automatically.
2. Once the installation is complete, you can run the `op jsi` command to use the tool.


## Usage

Here are some command samples to get you started:

![JSI CLI Demo](video/jsi-cli.gif)

### Checking Installation and Getting Help

```bash
poc@alpha> op jsi
Help: Main commands: user, device, org, api-token, check, proxy, phone, log
```

### User Authentication

```bash
poc@alpha> op jsi user login
Username: [your_username]
Password: [your_password]
Enter the two-factor authentication code: [your_2FA_code]
```

### Checking Logged-In User Information

```bash
poc@alpha> op jsi user whoami
```
### Org setting

```bash
poc@alpha> op jsi org setting
```

### Device Inventory Management

```bash
poc@alpha> op jsi device inventory
```

### Connecting Device to an Organization

```bash
poc@alpha> op jsi device connect
Enter your choice (1-N): [selected_number]
```

### Disconnecting Device to an Organization

```bash
poc@alpha> op jsi device disconnect
```

### Managing API Tokens

```bash
poc@alpha> op jsi api-token set
API Token: [your_api_token]
```

### Resetting API Token

```bash
poc@alpha> op jsi api-token reset
```

### Logging Out

```bash
poc@alpha> op jsi user logout
```
### HTTPS access test

```bash
poc@alpha> op jsi check https
```

### Phone home

```bash
poc@alpha> op jsi phone home
```

### Log level

```bash
poc@alpha> op jsi log level
poc@alpha> op jsi log debug
```

## Logging Sample
The log file is located at `/var/db/scripts/op/jsi-cli.log`. Refer to the [sample log file](./logs/) for more information.

## Note

For detailed usage and more commands, refer to the built-in help in the tool by running `op jsi`.

