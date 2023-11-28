# JSI CLI for Junos Devices

<!-- START doctoc generated TOC please keep comment here to allow auto update -->
<!-- END doctoc generated TOC please keep comment here to allow auto update -->

## Description
The JSI CLI is a command-line interface designed for Junos devices. This script offers a range of functionalities including user authentication, organization and device management, and API token configuration, making it a comprehensive tool for managing Junos devices within the JSI ecosystem.

## Installation
To install the JSI CLI script as a Juniper Op script on Junos Devices, run this command in your shell:

```shell
curl -k -s https://raw.githubusercontent.com/simonrho/jsi-cli/main/install.sh | /bin/sh
```

This command fetches and executes the installation script from the this GitHub repository, ensuring that you have the latest version of the CLI.

## Command Samples
Here are some examples of how to use the JSI CLI commands:

1. **User Login**:
   ```shell
   jsi-cli user login
   ```

2. **User Logout**:
   ```shell
   jsi-cli user logout
   ```

3. **Display Current User Information**:
   ```shell
   jsi-cli user whoami
   ```

4. **Create a New Organization**:
   ```shell
   jsi-cli org create
   ```

5. **Delete an Existing Organization**:
   ```shell
   jsi-cli org delete
   ```

6. **List All Available Organizations**:
   ```shell
   jsi-cli org list
   ```

7. **Retrieve Organization Settings**:
   ```shell
   jsi-cli org setting
   ```

8. **Connect a Device to the Cloud**:
   ```shell
   jsi-cli device connect
   ```

9. **Disconnect a Device from the Cloud**:
   ```shell
   jsi-cli device disconnect
   ```

10. **Retrieve Device Inventory Information**:
    ```shell
    jsi-cli device inventory
    ```

11. **Set an API Token**:
    ```shell
    jsi-cli api-token set
    ```

12. **Delete the API Token**:
    ```shell
    jsi-cli api-token reset
    ```

For more detailed information on each command and its options, refer to the script's help section or the comprehensive documentation provided with the CLI tool.
