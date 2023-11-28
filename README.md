# JSI CLI for Junos Devices

<!-- START doctoc generated TOC please keep comment here to allow auto update -->
<!-- END doctoc generated TOC please keep comment here to allow auto update -->

## Description
The JSI CLI is a command-line interface designed for Junos devices. This script offers a range of functionalities including user authentication, organization and device management, and API token configuration, making it a comprehensive tool for managing Junos devices within the JSI ecosystem.

## Installation
To install the JSI CLI script as a Juniper Op script on Junos Devices, run this command in your shell:

```shell
start shell command "curl -k -s https://raw.githubusercontent.com/simonrho/jsi-cli/main/install.sh | /bin/sh"
```

This command fetches and executes the installation script from the this GitHub repository, ensuring that you have the latest version of the CLI.

### Installation Steps:

1. The `jsi-cli` script will be downloaded and installed automatically.
2. Once the installation is complete, you can start using the tool by running the `op jsi` command.


## Usage

Here are some common command samples to get you started:

![JSI CLI Demo](video/jsi-cli.gif)


### Checking Installation and Getting Help

```bash
poc@alpha> op jsi
Help: Main commands: user, device, api-token
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

## Note

For detailed usage and more commands, refer to the in-built help in the tool by running `op jsi`.

