#!/usr/bin/env python3

import os
import re
import sys
import jcs
import time
import yaml
import json
import base64
import pickle
import datetime
import requests
import subprocess
from lxml import etree
from requests.packages.urllib3.exceptions import InsecureRequestWarning

# Disable warnings for unverified HTTPS requests
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# Global configuration paths and constants
JSI_CONFIG_PATH = './tmp/jsi'
DEFAULT_ORG_NAME = 'Default'
DEFAULT_SITE_NAME = 'Primary Site'
DEFAULT_ALARM_TEMPLATE_NAME = 'Default'
JSI_OSC_CONFIG = '/var/tmp/adoption-config.conf'
DEFAULT_DEVICE_CONNECT_INFO_FILE = f'{JSI_CONFIG_PATH}/connect'

# Class for creating and displaying tables from data
class Tabulate:
    def __init__(self, table, headers):
        self.table = table
        self.headers = headers

    # Format a single row for display
    def format_row(self, row, col_widths):
        return '  '.join(f"{str(item).ljust(width)}" for item, width in zip(row, col_widths))

    # Calculate column widths based on content
    def get_col_widths(self):
        widths = [len(str(header)) for header in self.headers]
        for row in self.table:
            for i, cell in enumerate(row):
                widths[i] = max(widths[i], len(str(cell)))
        return widths

    # Create and format the entire table as a string
    def create_table(self):
        col_widths = self.get_col_widths()
        header_row = self.format_row(self.headers, col_widths)
        separator = '  '.join('-' * width for width in col_widths)
        rows = [self.format_row(row, col_widths) for row in self.table]
        return '\n'.join([header_row, separator] + rows)

    # Override string representation to return the formatted table
    def __str__(self):
        return self.create_table()

# Class for Junos OS related operations
class JunosOS:
    def __init__(self):
        pass

    # Static method to check if running Junos / Junos Evo
    @classmethod
    def is_junos(cls):
        return os.path.exists('/usr/sbin/cli') # Junos or Junos Evo

    # Execute a Junos CLI command and return output
    @classmethod
    def junos_cli(cls, command):
        cmd = f"/usr/sbin/cli -c '{command}'"
        output = subprocess.check_output(cmd, shell=True, env=os.environ)
        return output.decode('utf-8')         

    # Check if 'phone-home' configuration is present in Junos
    @classmethod
    def is_phone_home_config(cls):
        result = JunosOS.junos_cli('show configuration system phone-home')
        return 'server' in result

    # Check if a 'mist' user is configured in Junos
    @classmethod
    def is_user_mist_config(cls):
        result = JunosOS.junos_cli('show configuration system login user mist | display xml')
        return 'mist' in result

    # Check if 'outbound-ssh' client 'mist' is configured in Junos
    @classmethod
    def is_outbound_ssh_mist_config(cls):
        result = JunosOS.junos_cli('show configuration system services outbound-ssh client mist | display xml')
        return 'mist' in result

    # Remove namespaces from XML and return cleaned XML text
    @classmethod
    def remove_namespaces(cls, xml_text):
        root = etree.fromstring(xml_text)
        for elem in root.getiterator():
            if not hasattr(elem.tag, 'find'):
                continue
            i = elem.tag.find('}')
            if i >= 0:
                elem.tag = elem.tag[i + 1:]

        for elem in root.iter():
            elem.attrib.clear()

        etree.cleanup_namespaces(root)

        return etree.tostring(root).decode('utf-8')

    # Get device serial number from system information
    @classmethod
    def get_device_sn(cls):
        system_info_xml = JunosOS.junos_cli('show system information | display xml')
        system_info_xml = JunosOS.remove_namespaces(system_info_xml)

        root = etree.ElementTree(etree.fromstring(system_info_xml).find('.//system-information'))
        sn = root.find('serial-number').text
        return sn

    # Convert UNIX timestamp to human-readable datetime format
    @classmethod
    def unix_timestamp_to_datetime(cls, unix_timestamp):
        t = datetime.datetime.fromtimestamp(unix_timestamp)
        return t.strftime('%Y-%m-%d %H:%M:%S')

    # Print dictionary data in a Junos CLI style format
    @classmethod
    def print_junos_style(cls, d, parent_key=None, indent=0):
        def _print_junos_style(d, indent=0):
            for key, value in d.items():
                prefix = ' ' * indent

                if isinstance(value, dict):
                    print(f"{prefix}{key} {{")
                    _print_junos_style(value, indent + 4)
                    print(f"{prefix}}}")
                else:
                    if isinstance(value, str) and len(value) == 0:
                        value = "''"
                    else:
                        value = str(value).lower() if isinstance(value, bool) else value
                    print(f"{prefix}{key}: {value};")

        if parent_key:
            d = {
                f'{parent_key}': d
            }

        _print_junos_style(d, indent=indent)

    # Print a message with a line above and below for emphasis
    @classmethod
    def print_with_line(cls, message, base='-'):
        print(base * len(message))
        print(message)
        print(base * len(message))

# Class representing Juniper Security Intelligence (JSI) operations
class JSI:
    # Nested class to represent a name and ID pair
    class NameID:
        def __init__(self, name, id):
            self.name = name
            self.id = id

        def __str__(self):
            return self.name
        
        def __repr__(self):
            return self.name

    # Initialize JSI with directory creation and configuration reading
    def __init__(self):
        os.makedirs(JSI_CONFIG_PATH, exist_ok=True)
        self.config_file = f'{JSI_CONFIG_PATH}/config'
        self.api_url = ''
        self.cookies = []
        self.api_token = ''
        self._self_info = {}
        self.privileges = {}
        self.config_read()

    # Read and parse configuration from the config file
    def config_read(self):
        if os.path.exists(self.config_file):
            with open(self.config_file, 'r') as file:
                config = file.read()
                config = config if config else '{}'
                self.config = json.loads(config)
                self.api_url = self.config.get('api_url', '')
                self.api_token = self.config.get('api_token', '')
                if self.api_token:
                    self.api_token =  pickle.loads(base64.b64decode(self.api_token))
                self.cookies = self.config.get('cookies', [])
                if self.cookies:
                    self.cookies = pickle.loads(base64.b64decode(self.cookies))

    # Write configuration data to the config file
    def config_write(self):
        config = {
            'api_url': self.api_url,
            'api_token': base64.b64encode(pickle.dumps(self.api_token)).decode('utf-8'),
            'cookies': base64.b64encode(pickle.dumps(self.cookies)).decode('utf-8'),
        }

        with open(self.config_file, 'w') as file:
            file.write(json.dumps(config, indent=4) + '\n')

    # Remove and reset configuration data
    def config_remove(self):
        self.api_url = ''
        self.cookies = []
        self._self_info = {}
        self.privileges = {}

        with open(self.config_file, 'w') as file:
            file.write('{}\n')

    # Lookup user details by email in the Mist API
    def user_lookup(self, email):
        url = 'https://api.mist.com/api/v1/sso/lookup'
        headers = {'Content-Type': 'application/json'}
        data = {'email': email}

        self.config_read()
        response = requests.post(url, headers=headers,
                                 json=data, cookies=self.cookies, verify=False)

        if response.status_code == 200:
            self.api_url = response.json()['accounts'][0]['api_url']

        return response

    # Retrieve cloud region information from Mist API
    def cloud_regions(self):
        url = 'https://manage.mist.com/env.json'
        headers = {'Content-Type': 'application/json'}

        response = requests.get(url, headers=headers, verify=False)
        return response

    # Extract CSRF token from cookies
    def get_csrftoken(self):
        for cookie in self.cookies:
            if 'csrftoken' in cookie.name:  # process csrftoken or csrftoken.eu or csrftoken.xyz
                return cookie.value

        return False

    # Set API token for authentication and update configurations based on valid regions
    def api_token_set(self, token):
        if token:
            self.api_token = token

            response = self.cloud_regions()
            if response and response.status_code == 200:
                regions = response.json().get('cloudRegions')
                regions.insert(0, {
                    "name": "Global",
                    "ui": "https://manage.mist.com"
                })

                found = False
                for region in regions:
                    api_url = region.get('ui').replace('manage', 'api')
                    region_name = region.get('name')
                    response = self.user_self(api_url=api_url)
                    if response and response.status_code == 200:
                        self.api_url = api_url
                        self.config_write()
                        found = True
                        print(f"API token is valid for the '{region_name}' region. Configurations updated; subsequent commands will target this region.")
                        break
                if not found:
                    print("Error: The provided API token is not associated with any accessible regions. Please verify your API token and try again.")
            else:
                print("Error: Unable to retrieve region information. Check your network connection and try again.")
        else:
            print("Error: No API token provided. Please enter a valid API token.")

    # Delete the stored API token and update configurations
    def api_token_delete(self):
        if self.api_token:
            self.api_token = ''
            self.config_write()

    # Fetch user details from the Mist API using the current API URL
    def user_self(self, api_url=None):
        if api_url:
            url = f'{api_url}/api/v1/self'
        else:
            if self.api_url:
                url = f'{self.api_url}/api/v1/self'
            else:
                return False

        headers = {'Content-Type': 'application/json'}
        if self.api_token: headers.update({'Authorization': f'Token {self.api_token}'})

        response = requests.get(url, headers=headers, cookies=self.cookies, verify=False)

        return response

    # Log in a user using email and password, updating cookies on success
    def user_login(self, email, password):
        url = f'{self.api_url}/api/v1/login'
        headers = {'Content-Type': 'application/json'}
        data = {
            "email": email,
            "password": password,
        }

        response = requests.post(url, headers=headers,
                                 json=data, cookies=self.cookies, verify=False)
        if response.status_code == 200:
            self.cookies = response.cookies
            self.config_write()

        return response

    # Log out the current user and remove configuration data
    def user_logout(self):
        url = f'{self.api_url}/api/v1/logout'
        headers = {
            'Content-Type': 'application/json',
            'X-Csrftoken': self.cookies.get('csrftoken'),
        }

        response = requests.post(url, headers=headers,
                                 data='null', cookies=self.cookies, verify=False)
        if response.status_code == 200:
            self.config_remove()

        return response

    # Handle two-factor authentication process for a user
    def user_two_factor_auth(self, code):
        url = f'{self.api_url}/api/v1/login/two_factor'
        headers = {
            'Content-Type': 'application/json',
            'X-Csrftoken': self.cookies.get('csrftoken')
        }
        data = {'two_factor': code}

        response = requests.post(url, headers=headers,
                                 json=data, cookies=self.cookies, verify=False)

        return response

    # Retrieve a list of organizations accessible to the user
    def org_list(self):
        response = self.user_self()
        if response and response.status_code == 200:
            self_info = response.json()
            privileges = self_info.get('privileges', [])
            orgs = [org for org in privileges if org.get('scope', '') == 'org']
            return orgs

        return []

    # Get organization ID based on organization name
    def get_org_id(self, org_name):
        orgs = self.org_list()
        for org in orgs:
            if org['name'] == org_name:
                return org['org_id']

        return None

    # Fetch information about a specific organization using its ID
    def org_info(self, org_id):
        url = f'{self.api_url}/api/v1/orgs/{org_id}'
        headers = {
            'Content-Type': 'application/json',
        }
        if self.api_token: headers.update({'Authorization': f'Token {self.api_token}'})
        response = requests.get(url, headers=headers, cookies=self.cookies, verify=False)
        return response

    # Retrieve an organization's ID by its name
    def org_id(self, org_name):
        org_list = self.org_list()
        for org in org_list:
            if org.get('name', '') == org_name:
                return org.get('org_id', '')
            
        return None

    # Get the name of an organization based on its ID
    def org_name(self, org_id): 
        response = self.org_info(org_id)

        if response and response.status_code == 200:
            org_info = response.json()
            org_name = org_info.get('name', '')
            return org_name
        
        return None

    # Create a new organization with the given name
    def org_create(self, org_name):
        url = f'{self.api_url}/api/v1/orgs'

        csrftoken = self.get_csrftoken()
        if csrftoken:
            headers = {
                'Content-Type': 'application/json',
                'X-Csrftoken': csrftoken,
            }
        else:
            headers = {
                'Content-Type': 'application/json',
            }

        if self.api_token: headers.update({'Authorization': f'Token {self.api_token}'})

        data = {
            "name": org_name,
            "allow_mist": True,
        }

        response = requests.post(url, headers=headers,
                                 json=data, cookies=self.cookies, verify=False)

        return response

    # Delete an organization by its ID
    def org_delete(self, org_id):
        url = f'{self.api_url}/api/v1/orgs/{org_id}'

        csrftoken = self.get_csrftoken()
        if csrftoken:
            headers = {
                'Content-Type': 'application/json',
                'X-Csrftoken': csrftoken,
            }
        else:
            headers = {
                'Content-Type': 'application/json',
            }

        if self.api_token: headers.update({'Authorization': f'Token {self.api_token}'})

        response = requests.delete(url, headers=headers, cookies=self.cookies, verify=False)

        return response

    # Fetch settings of a specific organization using its ID
    def org_setting(self, org_id):
        url = f'{self.api_url}/api/v1/orgs/{org_id}/setting'

        headers = {
            'Content-Type': 'application/json',
        }

        if self.api_token: headers.update({'Authorization': f'Token {self.api_token}'})

        response = requests.get(url, headers=headers, cookies=self.cookies, verify=False)

        return response

    # Construct a table representation of organization data based on privileges
    def org_dict(self, privileges):
        org_table = {}
        for p in privileges:
            scope = p.get('scope', '')
            if scope == 'org':
                org_name = p.get('name', '')
                org_role = p.get('role', '')
                org_id = p.get('org_id', '')

                if org_name and org_role and org_id:
                    org_table.update({
                        org_name: {
                            'id': org_id,
                            'role': org_role,
                            'sites': {}
                        }
                    })

                    sites = self.sites_list(org_id)
                    for site in sites:
                        site_name = site.get('name', '')
                        site_id = site.get('id', '')
                        site_role = '-'
                        if site_name and site_id:
                            org_table[org_name]['sites'].update({
                                site_name: {
                                    'id': site_id,
                                    'role': site_role,
                                }
                            })

            elif scope == 'site':
                org_name = p.get('org_name', '') 
                org_id = p.get('org_id', '')
                org_role = '-'
                site_name = p.get('name', '')
                site_id = p.get('site_id', '')
                site_role = p.get('role', '')

                if org_name and org_id and site_name and site_id and site_role:
                    org_table.update({
                        org_name: {
                            'id': org_id,
                            'role': org_role,
                            'sites': {
                                site_name: {
                                    'id': site_id,
                                    'role': site_role,
                                }
                            }
                        }
                    })

        return org_table

    # Create a table format to display organization data
    def org_table(self, privileges):
        org_table = self.org_dict(privileges)

        table = []

        i = 1
        for org_name, org in org_table.items():
            org_role = org.get('role', '')
            org_id = org.get('id', '')
            _org = self.NameID(org_name, org_id)
            found_site = False
            for site_name, site in org.get("sites").items():
                site_role = site.get('role', '')
                site_id = site.get('id', '')
                _site = self.NameID(site_name, site_id)
                table.append([f'{i:3}', _org, org_role, _site, site_role])
                i += 1
                found_site = True
            if not found_site:
                table.append([f'{i:3}', _org, org_role, '', '-'])
                i += 1

        return table

    # Create a new site within an organization
    def site_create(self, org_id, site_name):
        url = f'{self.api_url}/api/v1/orgs/{org_id}/sites'

        csrftoken = self.get_csrftoken()
        if csrftoken:
            headers = {
                'Content-Type': 'application/json',
                'X-Csrftoken': csrftoken,
            }
        else:
            headers = {
                'Content-Type': 'application/json',
            }

        if self.api_token: headers.update({'Authorization': f'Token {self.api_token}'})

        data = {
            "name": site_name,
        }

        response = requests.post(url, headers=headers,
                                 json=data, cookies=self.cookies, verify=False)

        return response

    # Delete a site by its ID
    def site_delete(self, site_id):
        url = f'{self.api_url}/api/v1/sites/{site_id}'

        csrftoken = self.get_csrftoken()
        if csrftoken:
            headers = {
                'Content-Type': 'application/json',
                'X-Csrftoken': csrftoken,
            }
        else:
            headers = {
                'Content-Type': 'application/json',
            }

        if self.api_token: headers.update({'Authorization': f'Token {self.api_token}'})

        response = requests.delete(url, headers=headers, cookies=self.cookies, verify=False)

        return response

    # Retrieve details of a specific site using its ID
    def site(self, site_id):
        url = f'{self.api_url}/api/v1/sites/{site_id}'

        headers = {
            'Content-Type': 'application/json',
        }

        if self.api_token: headers.update({'Authorization': f'Token {self.api_token}'})

        response = requests.get(url, headers=headers, cookies=self.cookies, verify=False)

        return response

    # Fetch all sites associated with an organization ID
    def sites(self, org_id):
        url = f'{self.api_url}/api/v1/orgs/{org_id}/sites'

        headers = {
            'Content-Type': 'application/json',
        }

        if self.api_token: headers.update({'Authorization': f'Token {self.api_token}'})

        response = requests.get(url, headers=headers, cookies=self.cookies, verify=False)

        return response

    # List all sites under an organization based on its ID
    def sites_list(self, org_id):
        response = self.sites(org_id)
        if response and response.status_code == 200:
            return response.json()
        return []

    # Get the name of a site by its ID
    def site_name(self, site_id):
        response = self.site(site_id)
        if response and response.status_code == 200:
            site_info = response.json()
            site_name = site_info.get('name', '')
            if site_name:
                return site_name
        return None

    # Retrieve site ID based on organization ID and site name
    def site_id(self, org_id, site_name):
        sites = self.sites_list(org_id)
        for site in sites:
            if site['name'] == site_name:
                return site['id']
        return None

    # Alternative method to retrieve site ID using organization name and site name
    def site_id2(self, org_name, site_name):
        org_id = self.org_id(org_name)
        if org_id:
            return self.site_id(org_id, site_name)
        return None

    # Fetch statistical data of a specific site using its ID
    def site_stats(self, site_id):
        url = f'{self.api_url}/api/v1/sites/{site_id}/stats'

        headers = {
            'Content-Type': 'application/json',
        }

        if self.api_token: headers.update({'Authorization': f'Token {self.api_token}'})

        response = requests.get(url, headers=headers, cookies=self.cookies, verify=False)

        return response

    # Create an alarm template for an organization
    def alarm_template_create(self, org_id, template_name=DEFAULT_ALARM_TEMPLATE_NAME):
        url = f'{self.api_url}/api/v1/orgs/{org_id}/alarmtemplates'

        csrftoken = self.get_csrftoken()
        if csrftoken:
            headers = {
                'Content-Type': 'application/json',
                'X-Csrftoken': csrftoken,
            }
        else:
            headers = {
                'Content-Type': 'application/json',
            }

        if self.api_token: headers.update({'Authorization': f'Token {self.api_token}'})

        data = {
            "name": template_name,
            "delivery": {
                "enabled": False,
                "to_org_admins": False,
                "to_site_admins": False,
                "additional_emails": [],
            },
            "rules": {}
        }

        response = requests.post(url, headers=headers,
                                 json=data, cookies=self.cookies, verify=False)

        return response

    # Delete an alarm template by its ID within an organization
    def alarm_template_delete(self, org_id, template_id):
        url = f'{self.api_url}/api/v1/orgs/{org_id}/alarmtemplates/{template_id}'

        csrftoken = self.get_csrftoken()
        if csrftoken:
            headers = {
                'Content-Type': 'application/json',
                'X-Csrftoken': csrftoken,
            }
        else:
            headers = {
                'Content-Type': 'application/json',
            }

        if self.api_token: headers.update({'Authorization': f'Token {self.api_token}'})


        response = requests.delete(url, headers=headers, cookies=self.cookies, verify=False)

        return response

    # List all alarm templates for a specific organization
    def alarm_template_list(self, org_id):
        url = f'{self.api_url}/api/v1/orgs/{org_id}/alarmtemplates'

        csrftoken = self.get_csrftoken()
        if csrftoken:
            headers = {
                'Content-Type': 'application/json',
                'X-Csrftoken': csrftoken,
            }
        else:
            headers = {
                'Content-Type': 'application/json',
            }

        if self.api_token: headers.update({'Authorization': f'Token {self.api_token}'})

        response = requests.get(url, headers=headers, cookies=self.cookies, verify=False)

        return response
    
    # Retrieve the command for device adoption in an organization (and optionally a site)
    def get_adoption_cmd(self, org_id, site_id=None):
        url = f'{self.api_url}/api/v1/orgs/{org_id}/ocdevices/outbound_ssh_cmd'

        if site_id:
            url += f"?site_id={site_id}"

        headers = {
            "Content-Type": "application/json"
        }

        if self.api_token: headers.update({'Authorization': f'Token {self.api_token}'})

        response = requests.get(url, headers=headers, cookies=self.cookies, verify=False)

        return response

    # Get inventory information for a specific serial number within an organization
    def get_inventory(self, org_id, sn):
        url = f'{self.api_url}/api/v1/orgs/{org_id}/inventory?serial={sn}'

        headers = {
            "Content-Type": "application/json"
        }

        if self.api_token: headers.update({'Authorization': f'Token {self.api_token}'})

        response = requests.get(url, headers=headers, cookies=self.cookies, verify=False)

        return response

    # Search through all organizations to find inventory information for a given serial number
    def get_inventory_from_orgs(self, sn):
        orgs = self.org_list()
        for org in orgs:
            org_id = org.get('org_id', None)
            if org_id:
                response = self.get_inventory(org_id, sn)
                if response and response.status_code == 200:
                    return response
        return None    

    # Remove a device from the inventory of an organization using its serial number
    def inventory_delete(self, org_id, sn):
        url = f'{self.api_url}/api/v1/orgs/{org_id}/inventory'

        csrftoken = self.get_csrftoken()
        if csrftoken:
            headers = {
                'Content-Type': 'application/json',
                'X-Csrftoken': csrftoken,
            }
        else:
            headers = {
                'Content-Type': 'application/json',
            }

        if self.api_token: headers.update({'Authorization': f'Token {self.api_token}'})

        data = {
            "op": "delete",
            "serials": [
                sn,
            ],
        }

        response = requests.put(url, headers=headers, json=data, cookies=self.cookies, verify=False)

        return response

# Display information about the currently logged-in user
def user_whoami():
    jsi = JSI()
    response = jsi.user_self()
    if response and response.status_code == 200:
        self_info = response.json()

        if jsi.api_token:
            info = f"Api Token Name: {self_info['name']}\n"
        else:
            info = f"Email: {self_info['email']}\n"
            info += f"First Name: {self_info['first_name']}\n"
            info += f"Last Name: {self_info['last_name']}\n"
            info += f"Session Expiry: {self_info['session_expiry']}\n"

        print(info)

        privileges = self_info.get('privileges', [])

        if len(privileges) > 0:
            print('Orgs and Sites you have access to:')
            headers = ["Number", "Org name", "Org permission", "Site name", "Site permission"]
            table = jsi.org_table(privileges)
            tabulated_table = Tabulate(table, headers)
            print(tabulated_table)
    else:
        print("You are not currently logged in. Please log in and try again.")

# Handle the process of user login including email/password and two-factor authentication
def user_login():
    login_ok = lambda email: print(f'{email} login successfully\n')
    login_error = lambda email: print(f'{email} login failed. check your email/password\n')
    two_factor_code_input = lambda: input("Enter the two-factor authentication code: ")

    jsi = JSI()
    response = jsi.user_self()

    if response and response.status_code == 200:
        if jsi.api_token:
            print("API token detected. You can proceed with API token-based operations without the need for manual login.")
        else:
            print("You are currently logged in using login credentials. No API token is in use.")
    else:
        print("To connect your device to the JSI service, log in with your Mist Cloud ID. If you don't have one? head over to https://manage.mist.com")
        
        email = input("Username: ")

        response = jsi.user_lookup(email)
        if response and response.status_code == 200:
            password = jcs.get_secret('Password: ')

            response = jsi.user_login(email, password)
            if response and response.status_code == 200:  # login check
                response = jsi.user_self()
                if response and response.status_code == 200:  # self check
                    self_info = response.json()
                    if 'two_factor_required' in self_info and 'two_factor_passed' in self_info:  # two factor auth check
                        if self_info['two_factor_required'] and not self_info['two_factor_passed']:
                            code = two_factor_code_input()
                            response = jsi.user_two_factor_auth(code)
                            if response and response.status_code == 200:  # two factor auth result
                                login_ok(email)
                            else:
                                login_error(email)
                                return
                        else:
                            login_ok(email)
                    else:
                        login_ok(email)
                else:
                    login_error(email)
                    return
            else:
                login_error(email)
                return
        else:
            login_error(email)
            return

    orgs = jsi.org_list()
    if len(orgs) == 0:
        org_create(org_name=DEFAULT_ORG_NAME)

# Log out the current user from the system
def user_logout():
    jsi = JSI()
    response = jsi.user_self()

    if response and response.status_code == 200:
        if jsi.api_token:
            print("Logout operation is not applicable when using an API token. Log out is bypassed.")
        else:
            myself = response.json()
            response = jsi.user_logout()
            if response and response.status_code == 200:
                print(f"User '{myself['email']}' has been successfully logged out.")
            else:
                print("Error: The logout process could not be completed. Please try again.")
    else:
        print("You appear to be not logged in. Please log in to proceed with logout.")

# Create a new organization with a default site and alarm template
def org_create():
    jsi = JSI()
    response = jsi.user_self()
    if response and response.status_code == 200:

        while True:
            org_name = input("Please enter the name of the organization you wish to create: ")
            pattern = r'^[A-Za-z][A-Za-z0-9 _-]*$'
            if re.match(pattern, org_name):
                print(f"Organization name '{org_name}' is valid.")
                break
            else:
                print("Invalid name. Must start with a letter and include only letters, numbers, spaces, '-', '_'.")

        orgs = jsi.org_list()
        orgs_name_list = [org['name'] for org in orgs]
        if org_name in orgs_name_list:
            print(f"Organization '{org_name}' already exists. No action taken.")
        else:
            response = jsi.org_create(org_name)
            if response and response.status_code == 200:
                print(f"Organization '{org_name}' created successfully.")
                org = response.json()
                org_id = org['id']
                site_name = DEFAULT_SITE_NAME
                response = jsi.site_create(org_id, site_name)
                if response and response.status_code == 200:
                    print(f"Site '{site_name}' created successfully within '{org_name}'.")
                else:
                    print(f"Error: Failed to create site '{site_name}' in '{org_name}'.")
                    return
                
                response = jsi.alarm_template_create(org_id, template_name=DEFAULT_ALARM_TEMPLATE_NAME)
                if response and response.status_code == 200:
                    alarm_template = response.json()
                    alarm_template_name = alarm_template['name']
                    alarm_template_id = alarm_template['id']
                    print(f"Alarm template '{alarm_template_name}' created successfully in '{org_name}'.")
                else:
                    print(f"Error: Failed to create an alarm template in '{org_name}'.")
                    return

            else:
                print(f"Error: Unable to create organization '{org_name}'. Please check the details and try again.")
    else:
        print("User authentication required. Please log in to create an organization.")

# Delete an existing organization after user confirmation
def org_delete():
    jsi = JSI()
    response = jsi.user_self()
    if response and response.status_code == 200:
        current_orgs = jsi.org_list()
        if current_orgs:
            headers = ["Number", "Org name", "Role", "Id"]
            table = [[index, org['name'], org['role'], org['org_id']] for index, org in enumerate(current_orgs, start=1)]
            tabulated_table = Tabulate(table, headers)

            print("Available Organizations:")
            print(tabulated_table)

            while True:
                choice_input = input(f"Enter your choice (1-{len(table)}): ")
                try:
                    choice = int(choice_input)
                    if 1 <= choice <= len(table):
                        choice -= 1
                        org_name = table[choice][1]
                        break
                    else:
                        print(f"Please enter a number between 1 and {len(table)}.")
                except ValueError:
                    print("Invalid input. Please enter a numeric value.")
            
            # Add confirmation input
            confirm = input(f"Are you sure you want to delete the organization '{org_name}'? (y/n): ").lower()
            if confirm != 'y':
                print("Deletion cancelled.")
                return

            org_found = False
            for org in current_orgs:
                if org['name'] == org_name:
                    org_found = True
                    response = jsi.org_delete(org['org_id'])
                    if response and response.status_code == 200:
                        print(f"Organization '{org_name}' has been successfully deleted.")
                        return
                    else:
                        error_message = response.json().get('detail', 'Unknown error. Please try again.')
                        print(f'Error: Unable to delete organization \'{org_name}\'. Reason: "{error_message}"')
                        return
            if not org_found:
                print(f"Error: Organization '{org_name}' not found. Please verify the organization name.")
        else:
            print("No organizations found. You are either not a member of any organizations or there are no organizations available.")
    else:
        print("User authentication required. Please log in to perform deletion of an organization.")

# List all organizations that the current user has access to
def org_list():
    jsi = JSI()
    response = jsi.user_self()
    if response and response.status_code == 200:
        current_orgs = jsi.org_list()
        if current_orgs:
            headers = ["Number", "Org name", "Role", "Id"]
            table = [[index, org['name'], org['role'], org['org_id']] for index, org in enumerate(current_orgs, start=1)]
            tabulated_table = Tabulate(table, headers)

            print("Available Organizations:")
            print(tabulated_table)
        else:
            print("No organizations found. You are either not a member of any organizations or there are no organizations available.")
    else:
        print("Authentication required. Please log in to view the list of organizations.")

# Retrieve and display settings for a specific organization
def org_setting():
    jsi = JSI()
    response = jsi.user_self()
    if response and response.status_code == 200:
        current_orgs = jsi.org_list()
        if current_orgs:
            headers = ["Number", "Org name", "Role", "Id"]
            table = [[index, org['name'], org['role'], org['org_id']] for index, org in enumerate(current_orgs, start=1)]
            tabulated_table = Tabulate(table, headers)

            print("Available Organizations:")
            print(tabulated_table)

            while True:
                choice_input = input(f"Enter your choice (1-{len(table)}): ")
                try:
                    choice = int(choice_input)
                    if 1 <= choice <= len(table):
                        choice -= 1
                        org_id = table[choice][3]
                        org_name = table[choice][1]
                        break
                    else:
                        print(f"Please enter a number between 1 and {len(table)}.")
                except ValueError:
                    print("Invalid input. Please enter a numeric value.")

            response = jsi.org_setting(org_id)
            if response and response.status_code == 200:
                org_setting = response.json()
                JunosOS.print_with_line(f"Organization '{org_name}' setting:")
                JunosOS.print_junos_style(org_setting, parent_key='setting')
            else:
                print(f"Error: Unable to retrive organization '{org_name}' settings. Please check the details and try again.")
        else:
            print("No organizations found. You are either not a member of any organizations or there are no organizations available.")
    else:
        print("User authentication required. Please log in to perform deletion of an organization.")
            
# Connect a device to an organization and site, including handling various configurations
def device_connect():
    jsi = JSI()
    response = jsi.user_self()
    if response and response.status_code == 200:
        self_info = response.json()
        privileges = self_info.get('privileges', [])

        sn = JunosOS.get_device_sn()
        response = jsi.get_inventory_from_orgs(sn)
        if response and response.status_code == 200:
            inventory = response.json()
            if inventory:
                inventory = inventory[0]
                ivt_org_id = inventory.get('org_id', '')
                ivt_site_id = inventory.get('site_id', '')
                org_name = jsi.org_name(ivt_org_id)
                site_name = jsi.site_name(ivt_site_id)

                print(f"Device is currently connected to organization '{org_name}' and site '{site_name}'.")
                print("To proceed with a new connection, please disconnect the device from the current organization and site first.")
                return
            else:
                pass
        else:
            pass

        org = None
        site = None
        if privileges:
            org_table = jsi.org_table(privileges)
            if len(org_table) == 1:
                org = org_table[0][1]
                site = org_table[0][3]
            elif len(org_table) > 1:
                print("Available Organizations and Sites:")
                headers = ["Number", "Organization Name", "Org Permission", "Site Name", "Site Permission"]
                tabulated_table = Tabulate(org_table, headers)
                print(tabulated_table)
                print("Please select the number corresponding to your choice of Organization and Site.")
                while True:
                    choice_input = input(f"Enter your choice (1-{len(org_table)}): ")
                    try:
                        choice = int(choice_input)
                        if 1 <= choice <= len(org_table):
                            choice -= 1
                            org = org_table[choice][1]
                            site = org_table[choice][3]
                            break
                        else:
                            print(f"Please enter a number between 1 and {len(org_table)}.")
                    except ValueError:
                        print("Invalid input. Please enter a numeric value.")
            else:
                print("No organizations or sites available to connect a device.")
                return
        else:
            print("You do not have access to any organizations or sites to connect a device.")
            return

        if site:
            response = jsi.get_adoption_cmd(org_id=org.id, site_id=site.id)
        else:
            response = jsi.get_adoption_cmd(org_id=org.id)

        if response and response.status_code == 200:
            cmds = response.json()["cmd"]

            if JunosOS.is_junos():
                if JunosOS.is_user_mist_config():
                    cmds = 'delete system login user mist\n' + cmds
                if JunosOS.is_outbound_ssh_mist_config():
                    cmds = 'delete system services outbound-ssh client mist\n' + cmds

                cmds = cmds if JunosOS.is_phone_home_config() else cmds.replace('delete system phone-home', '')
                cmds = cmds.replace('set system authentication-order', '')

                with open(JSI_OSC_CONFIG, 'w') as file:
                    file.write(cmds)

                result = JunosOS.junos_cli(f'edit;load set {JSI_OSC_CONFIG};commit and-quit')
                if 'commit complete' in result:
                    print('Device connection commands have been successfully applied.')
                else:
                    print(f'Error applying connection commands: {result}')
            else:
                print('Device connection commands (for manual execution):')
                print(cmds)
        else:
            print('Error: Failed to retrieve device connection commands. Please check your cloud connectivity.')
    else:
        print('Authentication required. Please log in and try again.')

# Retrieve and display inventory information for a device
def device_inventory():
    if not JunosOS.is_junos():
        print('Error: This command is available only on Junos or Junos Evo devices.')
        return
    
    jsi = JSI()
    response = jsi.user_self()
    if response and response.status_code == 200:
        sn = JunosOS.get_device_sn()
        response = jsi.get_inventory_from_orgs(sn)
        if response and response.status_code == 200:
            inventory = response.json()
            if inventory:
                JunosOS.print_with_line("Device Inventory Details:")
                for device in inventory:
                    org_id = device.pop('org_id', '')
                    site_id = device.pop('site_id', '')
                    device.pop('id', '')
                    device.update({
                        'org': jsi.org_name(org_id),
                        'site': jsi.site_name(site_id),
                    }) 
                    created_time = int(device['created_time'])
                    modified_time = int(device['modified_time'])
                    device['created_time'] = JunosOS.unix_timestamp_to_datetime(created_time)
                    device['modified_time'] =  JunosOS.unix_timestamp_to_datetime(modified_time)
                    JunosOS.print_junos_style(device, parent_key='inventory')
            else:
                print("No inventory data found for this device.")
        else:
            print("No existing device connection found. Please connect the device first.")
    else:
        print("User authentication required. Please log in and try again.")

# Disconnect a device from its current organization and site, and handle relevant configurations
def device_disconnect():
    if not JunosOS.is_junos():
        print('Error: This command can only be executed on a Junos/Junos Evo device.')
        return
    
    jsi = JSI()
    response = jsi.user_self()
    if response and response.status_code == 200:
        jsi = JSI()
        sn = JunosOS.get_device_sn()
        response = jsi.get_inventory_from_orgs(sn)
        if response and response.status_code == 200:
            inventory = response.json()
            if inventory:
                if len(inventory) == 0:
                    print('No existing connection found for this device. It appears the device was not connected previously.')
                    return
                org_id = inventory[0].get('org_id', '')

                if org_id:
                    confirm = input("Confirm device disconnection (y/n): ").lower().strip()
                    if confirm == 'y':
                        print("Proceeding with device disconnection...")
                    elif confirm == 'n':
                        print("Device disconnection cancelled.")
                        return
                    else:
                        print("Invalid input. Device disconnection not executed.")
                        return

                response = jsi.inventory_delete(org_id, sn)
                if response and response.status_code == 200:
                    inventory = response.json()
                    print('Device has been successfully disconnected and removed from inventory.')   
                    JunosOS.print_junos_style(inventory, parent_key='inventory')

                    # if JunosOS.is_junos():
                    #     print('Please wait for 30 seconds...')
                    #     time.sleep(27)
                    #     cmds = ''
                    #     if JunosOS.is_user_mist_config():
                    #         cmds += 'delete system login user mist\n'
                    #     if JunosOS.is_outbound_ssh_mist_config():
                    #         cmds += 'delete system services outbound-ssh client mist\n'

                    #     with open(JSI_OSC_CONFIG, 'w') as file:
                    #         file.write(cmds)

                    #     result = JunosOS.junos_cli(f'edit;load set {JSI_OSC_CONFIG};commit and-quit')
                    #     if 'commit complete' in result:
                    #         print('Device connection deletion commands have been successfully applied.')
                    #     else:
                    #         print(f'Error applying connection commands: {result}')
                    # else:
                    #     print('Device connection commands (for manual execution):')
                    #     print(cmds)

                else:
                    print('Error: Unable to disconnect the device. Please check the connection status or try again.')
                    inventory = response.json()
                    JunosOS.print_junos_style(inventory, parent_key='inventory')
            else:
                print('No existing connection found. Please ensure the device was connected previously.')
        else:
            print('No existing connection found for this device. It appears the device was not connected previously.')
    else:
        print('You must be logged in to perform this operation. Please log in and try again.')

# Set an API token for authenticating subsequent commands
def api_token_set():
    jsi = JSI()

    if jsi.api_token:
        print("An API token is already set. Please remove the current API token before attempting to set a new one.")
        return
    
    print("Enter the API Token to authenticate your requests. This token will be used for all subsequent commands.\n")
    token = jcs.get_secret("API Token: ")
    
    if token:
        jsi.api_token_set(token)
    else:
        print('No API Token provided. Please enter a valid API token to proceed.')

# Remove the currently set API token
def api_token_delete():
    jsi = JSI()

    jsi.api_token_delete()
    print('Api Token is removed!')    

# A class to handle CLI options and their associated actions
class CLIOptions:
    schema = {}

    def __init__(self, schema):
        self.scan_schema(schema)

    def scan_schema(self, schema):
        self._scan_alias(self.schema, self.schema, schema)

    def _scan_alias(self, parent, myself, schema):
        for key, value in schema.items():
            if isinstance(value, dict):
                myself.update({key: {}})
                self._scan_alias(myself, myself[key], value)
            else:
                if key == '_alias':
                    for a in value:
                        parent[a] = myself
                else:
                    myself[key] = value

    def run(self, cli_options):
        schema = self.schema
        for opt in cli_options:
            if opt in schema:
                value = schema[opt]
                if '_action' in value:
                    _action = value['_action']
                    _action()
                    return
                if isinstance(value, dict):
                    schema = value
                    continue
            else:
                break

        _help = schema.get('_help', '')
        print(f'\nHelp: {_help}\n')


# The main entry point of the script, handling command line arguments
if __name__ == '__main__':
    my_schema = {
        'user': {
            'login': {
                '_action': lambda: user_login(),
                '_help': "Log in to your cloud account.",
                '_alias': ['--login', '-login'],
            },
            'logout': {
                '_action': lambda: user_logout(),
                '_help': "Log out of your current cloud session.",
                '_alias': ['--logout', '-logout'],
            },
            'whoami': {
                '_action': lambda: user_whoami(),
                '_help': "Display the current user's identity.",
                '_alias': ['--whoami', '-whoami'],
            },
            '_help': "Manage user sessions: login, logout, identity check.",
            '_alias': ['--user', '-user'],
        },
        'org': {
            'create': {
                '_action': lambda: org_create(),
                '_help': "Create a new organization.",
                '_alias': ['--create', '-create'],
            },
            'delete': {
                '_action': lambda: org_delete(),
                '_help': "Delete an existing organization.",
                '_alias': ['--delete', '-delete'],
            },
            'list': {
                '_action': lambda: org_list(),
                '_help': "List all available organizations.",
                '_alias': ['--list', '-list'],
            },
            'setting': {
                '_action': lambda: org_setting(),
                '_help': "show organizations setting.",
                '_alias': ['--setting', '-setting'],
            },
            '_help': "Organizational operations: create, delete, list, setting.",
            '_alias': ['--org', '-org'],
        },
        'device': {
            'connect': {
                '_action': lambda: device_connect(),
                '_help': "Connect a device to the cloud.",
                '_alias': ['--connect', '-connect'],
            },
            'disconnect': {
                '_action': lambda: device_disconnect(),
                '_help': "Disconnect a device from the cloud.",
                '_alias': ['--disconnect', '-disconnect'],
            },
            'inventory': {
                '_action': lambda: device_inventory(),
                '_help': "Retrieve inventory information for a device.",
                '_alias': ['--inventory', '-inventory'],
            },
            '_help': "Device management: connect, disconnect, inventory.",
            '_alias': ['--device', '-device'],
        },
        'api-token': {
            'set': {
                '_action': lambda: api_token_set(),
                '_help': "set an api token.",
                '_alias': ['--set', '-set'],
            },
            'reset': {
                '_action': lambda: api_token_delete(),
                '_help': "remove the api token.",
                '_alias': ['--reset', '-reset'],
            },
            '_help': "Mange api token: set, reset.",
            '_alias': ['--api-token', '-api-token'],
        },
        '_help': "Main commands: user, device, api-token",
    }

    commands = sys.argv[1:]
    CLIOptions(my_schema).run(commands)
