# JSI CLI for Junos Devices

## Description
The JSI CLI is a command-line interface designed for Junos devices, facilitating various operations related to user management, device connectivity, organizational management, and API token handling. This script offers a range of functionalities including user authentication, organization and device management, and API token configuration, making it a comprehensive tool for managing Junos devices within the JSI ecosystem.

## Background
This script is tailored for network administrators and engineers who manage Junos devices. It simplifies the process of connecting devices to the cloud, handling user sessions, creating or deleting organizations, and setting API tokens for secure operations. The CLI is built with user-friendly commands, ensuring a smooth workflow for managing Junos devices and their interactions with the cloud.

## Installation
To install the JSI CLI for Junos Devices, run the following command in your shell:

```shell
curl -k -s https://raw.githubusercontent.com/simonrho/jsi-cli/main/install.sh | /bin/sh
```

This command fetches and executes the installation script from the official Juniper repository, ensuring that you have the latest version of the CLI.

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
