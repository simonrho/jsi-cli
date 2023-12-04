#!/usr/bin/env python3

import os
import re
import sys
import time
import json
import stat
import base64
import pickle
import datetime
import socket
import tempfile
import subprocess
from urllib.parse import urlparse, urlunparse
import ipaddress
import inspect
from typing import Any

import requests
from requests.auth import HTTPBasicAuth
from requests.exceptions import ReadTimeout, ProxyError
from requests.packages.urllib3.exceptions import InsecureRequestWarning, SubjectAltNameWarning
from lxml import etree

import logging
from logging.handlers import RotatingFileHandler

import jcs

# Disable warnings for unverified HTTPS requests
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
requests.packages.urllib3.disable_warnings(SubjectAltNameWarning)

# Log file and logger setup
log_file = '/var/log/jsi-cli.log'

if not os.path.exists(log_file):
    open(log_file, 'a').close()
    os.chmod(log_file, stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP | stat.S_IWGRP | stat.S_IROTH | stat.S_IWOTH)

log_formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
file_handler = RotatingFileHandler(log_file, maxBytes=1048576, backupCount=5)
file_handler.setFormatter(log_formatter)

logger = logging.getLogger('jsi-cli-logger')
logger.setLevel(logging.INFO)
logger.addHandler(file_handler)

# Global configuration paths and constants
JSI_CONFIG_PATH = './.jsi'
DEFAULT_ORG_NAME = 'Default'
DEFAULT_SITE_NAME = 'Primary Site'
DEFAULT_ALARM_TEMPLATE_NAME = 'Default'
JSI_OSC_CONFIG = '/var/tmp/adoption-config.conf'
DEFAULT_DEVICE_CONNECT_INFO_FILE = f'{JSI_CONFIG_PATH}/connect'

def cout(message, log_level='info', log_output=True):
    print(message)
    if log_output:
        loggers = {
            'info': logger.info,
            'warning': logger.warning,
            'error': logger.error,
            'critical': logger.critical,
            'debug': logger.debug,
        }
        if isinstance(message, str):
            if message.count('\n') > 0:
                loggers[log_level.lower()](f'\n{message}')
            else:
                loggers[log_level.lower()](message)
        else:
            loggers[log_level.lower()](f'\n{message}')

# A class encapsulating the result of an operation with its status, supporting boolean, string, integer, and iterable representations.
class OpResult:
    def __init__(self, object: Any, result: bool, message: str = ''):
        self.object = object
        self.result = result
        self.message = message
        if isinstance(object, requests.Response):
            self.response = object
            self.status_code = object.status_code

    def __bool__(self):
        return bool(self.result)

    def __str__(self):
        return str(self.object)
    
    def __int__(self):
        if isinstance(self.object, int):
            return self.object
        else:
            raise ValueError(f"Cannot convert {type(self.object).__name__} to int")

    def __iter__(self):
        if isinstance(self.object, list):
            return iter(self.object)
        else:
            raise ValueError(f"Cannot convert {type(self.object).__name__} to iter")

    def __repr__(self):
        return f"OpResult(object={self.object!r}, result={self.result!r})"
                
    def json(self):
        if isinstance(self.object, requests.Response):
            return self.object.json()
        raise TypeError("The object attribute is not a requests.Response instance")



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
        return os.path.exists('/usr/sbin/cli')  # Junos or Junos Evo

    # Execute a Junos CLI command and return output
    @classmethod
    def junos_cli(cls, command):
        cmd = f"/usr/sbin/cli -c '{command}'"
        output = subprocess.check_output(cmd, shell=True, env=os.environ)
        return output.decode('utf-8')

    # Commit a Junos xml configuration
    @classmethod
    def junos_commit_xml(cls, config, action='merge'):

        config = f'''
            <rpc>
                <load-configuration action="{action}" format="xml">
                    {config}
                </load-configuration>
            </rpc>
        '''
        with tempfile.NamedTemporaryFile(delete=False, mode='w') as config_file:
            config_file.write(config)
            config_file_path = config_file.name
        
        cmd = f"/usr/sbin/cli xml-mode netconf < {config_file_path}"        
        output = subprocess.check_output(cmd, shell=True, env=os.environ).decode('utf-8')        
        os.remove(config_file_path)

        if "<ok/>" not in output:
            return OpResult(output, False)

        cmd = f'echo "<rpc><commit-configuration/></rpc>" | /usr/sbin/cli xml-mode netconf'
        output = subprocess.check_output(cmd, shell=True, env=os.environ).decode('utf-8')

        return OpResult(output, "<ok/>" in output)


    # Check if 'phone-home' configuration is present in Junos
    @classmethod
    def is_phone_home_config(cls):
        result = JunosOS.junos_cli('show configuration system phone-home')
        return 'server' in result

    # Check if a 'mist' user is configured in Junos
    @classmethod
    def is_user_mist_config(cls):
        result = JunosOS.junos_cli(
            'show configuration system login user mist | display xml')
        return 'mist' in result

    # Check if 'outbound-ssh' client 'mist' is configured in Junos
    @classmethod
    def is_outbound_ssh_mist_config(cls):
        result = JunosOS.junos_cli(
            'show configuration system services outbound-ssh client mist | display xml')
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
        system_info_xml = JunosOS.junos_cli(
            'show system information | display xml')
        system_info_xml = JunosOS.remove_namespaces(system_info_xml)

        root = etree.ElementTree(etree.fromstring(
            system_info_xml).find('.//system-information'))
        sn = root.find('serial-number').text
        return sn

    # Convert UNIX timestamp to human-readable datetime format
    @classmethod
    def unix_timestamp_to_datetime(cls, unix_timestamp):
        t = datetime.datetime.fromtimestamp(unix_timestamp)
        return t.strftime('%Y-%m-%d %H:%M:%S')

    # String out of dictionary data in a Junos text config style format
    @classmethod
    def jout(cls, d, parent_key=None, indent=0):
        def _print_junos_style(d, indent=0, result=''):
            for key, value in d.items():
                prefix = ' ' * indent

                if isinstance(value, dict):
                    result += f"{prefix}{key} {{\n"
                    result, _ = _print_junos_style(value, indent + 4, result)
                    result += f"{prefix}}}\n"
                else:
                    if isinstance(value, str) and len(value) == 0:
                        value = "''"
                    else:
                        value = str(value).lower() if isinstance(value, bool) else value
                    result += f"{prefix}{key}: {value};\n"
            return result, True

        if parent_key:
            d = {f'{parent_key}': d}

        result, _ = _print_junos_style(d, indent=indent)
        return result
    
    # Print a dictionary in a Junos text config style format
    @classmethod
    def jprint(cls, d, parent_key=None, indent=0):
        m = JunosOS.jout(d, parent_key=parent_key, indent=indent)
        print(m)
        logger.info('\n'+ m)

    # Print a message with a line above and below for emphasis
    @classmethod
    def msg_style(cls, message, style='-', length=0):
        ml = len(message)
        if length > ml:
            style_len = length
            space_len = int((length - ml)/2)
        else:
            style_len = len(message)
            space_len = 0

        m = style * style_len + "\n"
        m += ' ' * space_len + message + ' ' * space_len + "\n"
        m += style * style_len + "\n"

        return m

    @classmethod
    def print_with_style(cls, message, style='-', length=0):
        m = JunosOS.msg_style(message, style, length)
        print(m)
        logger.info('\n'+ m)

# Class representing Juniper Security Intelligence (JSI) operations
class JSI:
    # Nested class to represent a name and ID pair
    class ObjectID:
        def __init__(self, object, id):
            self.object = object
            self.id = id

        def __str__(self):
            return self.object

        def __repr__(self):
            return self.object

    # Initialize JSI with directory creation and configuration reading
    def __init__(self, user_login_session_check=True):
        os.makedirs(JSI_CONFIG_PATH, exist_ok=True)
        self.config_file = f'{JSI_CONFIG_PATH}/config'
        self.api_url = ''
        self.cookies = []
        self.api_token = ''
        self.web_proxy = {}
        self.log_level = 'info'

        self.config_read()
        self.set_log_level(self.log_level)

        if user_login_session_check:
            logger.info("user login session check flag is on, let's check if there is an active user session...")
            opResult = self.user_self()
            if opResult and opResult.status_code == 200:
                self_info = opResult.json()
                if 'privileges' not in self_info:
                    logger.info('An active user session exists, but user privileges were not found. The user login session is incomplete.')
                    logger.info('Calling user_logout() to remove the incomplete user session.')
                    self.user_logout()

    def set_log_level(self, level):
        levels = {
            'info': logging.INFO,
            'warning': logging.WARNING,
            'error': logging.ERROR,
            'critical': logging.CRITICAL,
            'debug': logging.DEBUG,
        }
        logger.setLevel(levels[level])
        file_handler.setLevel(levels[level])
        self.log_level = level
        self.config_write()

    # Assistant methods to decode configuration data
    def _serialize_value(self, value):
        return base64.b64encode(pickle.dumps(value)).decode('utf-8')

    def _unSerialize_value(self, value):
        return pickle.loads(base64.b64decode(value))

    # Read and parse configuration from the config file
    def config_read(self):
        if not os.path.exists(self.config_file):
            return

        with open(self.config_file, 'r') as file:
            config = file.read() or '{}'
            config = json.loads(config)

        self.api_url = config.get('api_url', '')
        self.api_token = self._unSerialize_value(config.get('api_token', ''))
        self.web_proxy = self._unSerialize_value(config.get('web_proxy', {}))
        self.cookies = self._unSerialize_value(config.get('cookies', []))
        self.log_level = config.get('log_level', 'info')

    # Write configuration data to the config file
    def config_write(self):
        config = {
            'api_url': self.api_url,
            'api_token': self._serialize_value(self.api_token),
            'cookies': self._serialize_value(self.cookies),
            'web_proxy': self._serialize_value(self.web_proxy),
            'log_level': self.log_level,
        }

        with open(self.config_file, 'w') as file:
            file.write(json.dumps(config, indent=4) + '\n')

    # Remove and reset configuration data but not api token key until api-token reset
    def config_remove(self):
        self.api_url = ''
        self.cookies = []
        self.web_proxy = {}
        
        self.config_write()


    def is_valid_proxy_url(self, url):
        regex = re.compile(
            r'^(\w+)://'  # HTTP, HTTPS protocols
            r'([\w.-]+)'  # Domain name or IP address
            r':?(\d+)?'  # Optional port
            , re.IGNORECASE)

        match = regex.match(url)
        if match is None:
            return OpResult("URL scheme is not valid", False)

        protocol = match.group(1)
        domain_or_ip = match.group(2)
        port = match.group(3)
        
        if protocol is None or protocol not in ['https', 'http']:
            return OpResult("Protocol is not valid", False)

        if domain_or_ip is None:
            return OpResult("Domain is not valid", False)

        if domain_or_ip.replace('.', '').isdigit():
            try:
                ipaddress.ip_address(domain_or_ip)
            except ValueError:
                return OpResult("IP is not valid", False)

        if port is not None:
            port = int(port)
            if port < 1 or port > 65535:
                return OpResult("Port is not valid", False)
        
        return OpResult("Valid URL!", True)

    # Mask login name and password with asterisks in the encoded web proxy URL
    def web_proxy_mask(self, url):
        regex = re.compile(
            r'(\w+://)(.+):(.*)@' 
        )
        def mask(match):
            username_mask = '*' * len(match.group(2))
            password_mask = '*' * len(match.group(3)) if match.group(3) else ''
            return f"{match.group(1)}{username_mask}:{password_mask}@"

        masked_url = regex.sub(mask, url)

        return OpResult(masked_url, url != masked_url)

    # Set web proxy settings
    def web_proxy_set(self, protocol, proxy_url, username='', password=''):
        if self.is_valid_proxy_url(proxy_url):
            if username:
                proxy_url = proxy_url.replace('://', f'://{username}:{password}@')

            if self.web_proxy == {}:
                self.web_proxy = {
                    protocol: proxy_url
                }
            else:
                self.web_proxy.update({protocol: proxy_url})

            self.config_write()
            return OpResult('OK', True)
        return OpResult("Invalid URL!", False)

    # Return web proxy settings
    def web_proxy_get(self):
        return self.web_proxy

    def web_proxy_remove(self):
        self.web_proxy = {}
        self.config_write()
        return OpResult('OK', True)


    def build_call_log(self, response):
        def indent(message, indent=0):
            return '\n'.join([' ' * indent + line for line in message.split("\n")])

        def mask_string(text, pattern, mask_char='x'):
            def replacer(match):
                asterisk = mask_char * len(match.group(2))
                return f"{match.group(1)}{asterisk}{match.group(3)}"

            masked_text = re.sub(pattern, replacer, text)
            return masked_text

        request = response.request

        # For request
        try:
            request_headers = dict(request.headers)
            request_headers = json.dumps(request_headers, indent=4)
        except:
            request_headers = str(request.headers)

        try:
            request_body = json.loads(request.body.decode('utf-8'))
            request_body = f"{json.dumps(request_body, indent=4)}"
        except:
            request_body = str(request.body)

        # For response
        try:
            response_headers = dict(response.headers)
            response_headers = json.dumps(response_headers, indent=4)
        except:
            response_headers = str(response.headers)

        try:
            response_payload = str(json.dumps(json.loads(str(response.text)), indent=4))
        except:
            response_payload = str(response.text)

        # Build up log message
        message = f"""
============ BEGIN ============

<<<<<<<<<<<< Send
    Request URL: "{request.url}"
    Request Method: {request.method}
    Request Headers:
{indent(request_headers, indent=8)}
    Request Payload:
{indent(request_body, indent=8)}

>>>>>>>>>>>> Receive
    Response URL: "{response.request.url}"
    Response Status Code: {response.status_code}
    Response Headers:
{indent(response_headers, indent=8)}
    Response Payloads:
{indent(response_payload, indent=8)}

============ END ==============
"""
        message = mask_string(message, pattern=r'("X-Csrftoken":\s*")(.+)(")')
        message = mask_string(message, pattern=r'(csrftoken[.]?[\w+]?=)(\w+)(;)')
        message = mask_string(message, pattern=r'("password":\s*")(.+)(")')
        message = mask_string(message, pattern=r'("Authorization": "Token\s*)(.+)(")')

        return message

    def api_request(self, method='GET', url='', data=None, headers=None, cookies=None, verify=False, proxies=None):
        request_method = {
            'GET': requests.get,
            'POST': requests.post,
            'PUT': requests.put,
            'DELETE': requests.delete,
        }[method.upper()]

        if headers is None:
            headers = {'Content-Type': 'application/json'}
            if self.api_token:
                headers.update({'Authorization': f'Token {self.api_token}'})
            else:
                csrf_token = self.get_csrftoken()
                if csrf_token:
                    headers.update({'X-Csrftoken': csrf_token})

        if cookies is None:
            cookies = self.cookies

        if proxies is None:
            proxies = self.web_proxy

        try:
            response = request_method(url, json=data, headers=headers, cookies=cookies, proxies=proxies, verify=verify)

            log_message = self.build_call_log(response)
            logger.debug(log_message)

            return OpResult(response, result=response.status_code == 200, message='OK' if response.status_code == 200 else response.reason)
        except requests.exceptions.RequestException as ex:
            return OpResult(str(ex), False)

    # Retrieve cloud region information from Mist API
    def cloud_regions(self):
        logger.debug(f'call "{inspect.currentframe().f_code.co_name}" function...')

        opResult = self.api_request('get', 'https://manage.mist.com/env.json')
        return opResult

    # Extract CSRF token from cookies
    def get_csrftoken(self):
        logger.debug(f'call "{inspect.currentframe().f_code.co_name}" function...')

        for cookie in self.cookies:
            if 'csrftoken' in cookie.name:  # process csrftoken or csrftoken.eu or csrftoken.xyz
                return cookie.value

        return False

    # Set API token for authentication and update configurations based on valid regions
    def api_token_set(self, token):
        logger.debug(f'call "{inspect.currentframe().f_code.co_name}" function...')

        if token:
            self.api_token = token

            logger.info('Getting cloud region information...')
            response = self.cloud_regions()
            if response and response.status_code == 200:
                regions = response.json().get('cloudRegions')
                regions.insert(0, {
                    "name": "Global",
                    "ui": "https://manage.mist.com"
                })

                logger.info(f'region information: {json.dumps(regions, indent=4)}')

                found = False
                for region in regions:
                    api_url = region.get('ui').replace('manage', 'api')
                    region_name = region.get('name')

                    logger.info(f'Call user_self for checking which API endpoint owns token: region "{region_name}" - "{api_url}"')

                    response = self.user_self(api_url=api_url)
                    if response and response.status_code == 200:
                        logger.info(f'API token is valid for the "{region_name}" region')
                        self.api_url = api_url
                        self.config_write()
                        logger.info(f'API endpoint for the "{region_name}" region is {self.api_url}')

                        found = True
                        cout(f"API token is valid for the '{region_name}' region. Configurations updated; subsequent commands will target this region.")
                        break
                if not found:
                    cout("Error: The provided API token is not associated with any accessible regions. Please verify your API token and try again.")
            else:
                cout("Error: Unable to retrieve region information. Check your network connection and try again.")
        else:
            cout("Error: No API token provided. Please enter a valid API token.")

    # Delete the stored API token and update configurations
    def api_token_delete(self):
        logger.debug(f'call "{inspect.currentframe().f_code.co_name}" function...')

        if self.api_token:
            self.api_token = ''
            self.config_write()

    # Fetch user details from the Mist API using the current API URL
    def user_self(self, api_url=None):
        logger.debug(f'call "{inspect.currentframe().f_code.co_name}" function...')

        base_url = api_url or self.api_url
        if not base_url:
            return OpResult("No API URL provided. Please enter a valid API URL.", False)

        opResult = self.api_request('get', f'{base_url}/api/v1/self')

        return opResult

    # Lookup user details by email in the Mist API
    def user_lookup(self, email):
        logger.debug(f'call "{inspect.currentframe().f_code.co_name}" function...')

        opResult = self.api_request('post', 'https://api.mist.com/api/v1/sso/lookup', {'email': email})

        if opResult and opResult.status_code == 200:
            self.api_url = opResult.json()['accounts'][0]['api_url']

        return opResult

    # Log in a user using email and password, updating cookies on success
    def user_login(self, email, password):
        logger.debug(f'call "{inspect.currentframe().f_code.co_name}" function...')

        opResult = self.api_request('post', f'{self.api_url}/api/v1/login', data={"email": email,"password": password})

        if opResult.status_code == 200:
            self.cookies = opResult.response.cookies
            self.config_write()

        return opResult

    # Log out the current user and remove configuration data
    def user_logout(self):
        logger.debug(f'call "{inspect.currentframe().f_code.co_name}" function...')

        opResult = self.api_request('post', f'{self.api_url}/api/v1/logout', data={})

        if opResult.status_code == 200:
            self.config_remove()

        return opResult

    # Handle two-factor authentication process for a user
    def user_two_factor_auth(self, code):
        logger.debug(f'call "{inspect.currentframe().f_code.co_name}" function...')

        return self.api_request('post', f'{self.api_url}/api/v1/login/two_factor', data={'two_factor': code})
    
    # Retrieve a list of organizations accessible to the user
    def org_list(self):
        logger.debug(f'call "{inspect.currentframe().f_code.co_name}" function...')

        response = self.user_self()
        if response and response.status_code == 200:
            self_info = response.json()
            privileges = self_info.get('privileges', [])
            orgs = [org for org in privileges if org.get('scope', '') == 'org']
            return orgs

        return []

    # Fetch information about a specific organization using its ID
    def org_info(self, org_id):
        logger.debug(f'call "{inspect.currentframe().f_code.co_name}" function...')

        return self.api_request('get', f'{self.api_url}/api/v1/orgs/{org_id}')

    # Retrieve an organization's ID by its name
    def org_id(self, org_name):
        logger.debug(f'call "{inspect.currentframe().f_code.co_name}" function...')

        org_list = self.org_list()
        for org in org_list:
            if org.get('name', '') == org_name:
                return org.get('org_id', '')

        return None

    # Get the name of an organization based on its ID
    def org_name(self, org_id):
        logger.debug(f'call "{inspect.currentframe().f_code.co_name}" function...')

        response = self.org_info(org_id)

        if response and response.status_code == 200:
            org_info = response.json()
            org_name = org_info.get('name', '')
            return org_name

        return None

    # Create a new organization with the given name
    def org_create(self, org_name):
        logger.debug(f'call "{inspect.currentframe().f_code.co_name}" function...')

        return self.api_request('post', f'{self.api_url}/api/v1/orgs', data={ "name": org_name, "allow_mist": True })

    # Delete an organization by its ID
    def org_delete(self, org_id):
        logger.debug(f'call "{inspect.currentframe().f_code.co_name}" function...')

        return self.api_request('delete', f'{self.api_url}/api/v1/orgs/{org_id}')

    # Fetch settings of a specific organization using its ID
    def org_setting(self, org_id):
        logger.debug(f'call "{inspect.currentframe().f_code.co_name}" function...')

        return self.api_request('get', f'{self.api_url}/api/v1/orgs/{org_id}/setting')
    
    # Create a dictionary table format to display organization data
    def _org_dict(self, privileges):
        logger.debug(f'call "{inspect.currentframe().f_code.co_name}" function...')

        org_dict_table = {}
        for p in privileges:
            scope = p.get('scope', '')
            if scope == 'org':
                org_name = p.get('name', '')
                org_role = p.get('role', '')
                org_id = p.get('org_id', '')

                if org_name and org_role and org_id:
                    org_dict_table.update({
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
                            org_dict_table[org_name]['sites'].update({
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
                    org_dict_table.update({
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

        return org_dict_table

    # Create a table format to display organization data
    def org_table(self, privileges):
        logger.debug(f'call "{inspect.currentframe().f_code.co_name}" function...')

        org_dict_table = self._org_dict(privileges)

        table = []

        i = 1
        for org_name, org in org_dict_table.items():
            org_role = org.get('role', '')
            org_id = org.get('id', '')
            _org = self.ObjectID(org_name, org_id)
            found_site = False
            for site_name, site in org.get("sites").items():
                site_role = site.get('role', '')
                site_id = site.get('id', '')
                _site = self.ObjectID(site_name, site_id)
                table.append([f'{i:3}', _org, org_role, _site, site_role])
                i += 1
                found_site = True
            if not found_site:
                table.append([f'{i:3}', _org, org_role, '', '-'])
                i += 1

        return table

    # Create a new site within an organization
    def site_create(self, org_id, site_name):
        logger.debug(f'call "{inspect.currentframe().f_code.co_name}" function...')

        return self.api_request('post', f'{self.api_url}/api/v1/orgs/{org_id}/sites', data={"name": site_name})

    # Delete a site by its ID
    def site_delete(self, site_id):
        logger.debug(f'call "{inspect.currentframe().f_code.co_name}" function...')

        return self.api_request('delete', f'{self.api_url}/api/v1/sites/{site_id}')

    # Retrieve details of a specific site using its ID
    def site(self, site_id):
        logger.debug(f'call "{inspect.currentframe().f_code.co_name}" function...')

        return self.api_request('get', f'{self.api_url}/api/v1/sites/{site_id}')

    # Fetch all sites associated with an organization ID
    def sites(self, org_id):
        logger.debug(f'call "{inspect.currentframe().f_code.co_name}" function...')

        return self.api_request('get', f'{self.api_url}/api/v1/orgs/{org_id}/sites')

    # List all sites under an organization based on its ID
    def sites_list(self, org_id):
        logger.debug(f'call "{inspect.currentframe().f_code.co_name}" function...')

        response = self.sites(org_id)
        if response and response.status_code == 200:
            return response.json()
        return []

    # Get the name of a site by its ID
    def site_name(self, site_id):
        logger.debug(f'call "{inspect.currentframe().f_code.co_name}" function...')

        response = self.site(site_id)
        if response and response.status_code == 200:
            site_info = response.json()
            site_name = site_info.get('name', '')
            if site_name:
                return site_name
        return None

    # Retrieve site ID based on organization ID and site name
    def site_id(self, org_id, site_name):
        logger.debug(f'call "{inspect.currentframe().f_code.co_name}" function...')

        sites = self.sites_list(org_id)
        for site in sites:
            if site['name'] == site_name:
                return site['id']
        return None

    # Alternative method to retrieve site ID using organization name and site name
    def site_id2(self, org_name, site_name):
        logger.debug(f'call "{inspect.currentframe().f_code.co_name}" function...')

        org_id = self.org_id(org_name)
        if org_id:
            return self.site_id(org_id, site_name)
        return None

    # Fetch statistical data of a specific site using its ID
    def site_stats(self, site_id):
        logger.debug(f'call "{inspect.currentframe().f_code.co_name}" function...')

        return self.api_request('get', f'{self.api_url}/api/v1/sites/{site_id}/stats')

    # Create an alarm template for an organization
    def alarm_template_create(self, org_id, template_name=DEFAULT_ALARM_TEMPLATE_NAME):
        logger.debug(f'call "{inspect.currentframe().f_code.co_name}" function...')

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
        return self.api_request('post', f'{self.api_url}/api/v1/orgs/{org_id}/alarmtemplates', data=data)

    # Delete an alarm template by its ID within an organization
    def alarm_template_delete(self, org_id, template_id):
        logger.debug(f'call "{inspect.currentframe().f_code.co_name}" function...')

        return self.api_request('delete', f'{self.api_url}/api/v1/orgs/{org_id}/alarmtemplates/{template_id}')

    # List all alarm templates for a specific organization
    def alarm_template_list(self, org_id):
        logger.debug(f'call "{inspect.currentframe().f_code.co_name}" function...')

        return self.api_request('get', f'{self.api_url}/api/v1/orgs/{org_id}/alarmtemplates')

    # Retrieve the command for device adoption in an organization (and optionally a site)
    def get_adoption_cmd(self, org_id, site_id=''):
        logger.debug(f'call "{inspect.currentframe().f_code.co_name}" function...')

        url = f'{self.api_url}/api/v1/orgs/{org_id}/ocdevices/outbound_ssh_cmd'
        if site_id:
            url += f'?site_id={site_id}'

        return self.api_request('get', url)

    # Get inventory information for a specific serial number within an organization
    def get_inventory(self, org_id, sn):
        logger.debug(f'call "{inspect.currentframe().f_code.co_name}" function...')

        return self.api_request('get', f'{self.api_url}/api/v1/orgs/{org_id}/inventory?serial={sn}')

    # Search through all organizations to find inventory information for a given serial number
    def get_inventory_from_orgs(self, sn):
        logger.debug(f'call "{inspect.currentframe().f_code.co_name}" function...')

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
        logger.debug(f'call "{inspect.currentframe().f_code.co_name}" function...')

        data = {
            "op": "delete",
            "serials": [
                sn,
            ],
        }
        return self.api_request('put', f'{self.api_url}/api/v1/orgs/{org_id}/inventory', data=data)

# Display information about the currently logged-in user
def user_whoami():
    logger.info(f"\n{JunosOS.msg_style('USER WHOAMI COMMAND', style='*', length=80)}")
    jsi = JSI()
    logger.info(f"checking if user is already logged in...?")
    response = jsi.user_self()
    if response and response.status_code == 200:
        logger.info(f"Yes, user is already logged in!")
        self_info = response.json()

        logger.info('Extract privileges from user info')
        privileges = self_info.get('privileges', [])

        if jsi.api_token:
            info = f"Api Token Name: {self_info['name']}\n"
        else:
            info = f"Email: {self_info.get('email', '')}\n"
            info += f"First Name: {self_info.get('first_name', '')}\n"
            info += f"Last Name: {self_info.get('last_name', '')}\n"
            info += f"Session Expiry: {self_info.get('session_expiry', '')}\n"

        if len(privileges) > 0:
            headers = ["Number", "Org name", "Org permission",
                       "Site name", "Site permission"]
            table = jsi.org_table(privileges)
            tabulated_table = Tabulate(table, headers)
            cout(f"Orgs and Sites you have access to:\n{info}\n{tabulated_table}")
        else:
            cout(info)

    else:
        cout("You are not currently logged in. Please log in and try again.")

# Handle the process of user login including email/password and two-factor authentication
def user_login():
    logger.info(f"\n{JunosOS.msg_style('USER LOGIN COMMAND', style='*', length=80)}")

    def login_ok(email): 
        cout(f'{email} login successfully\n')

    def login_error(email): 
        cout(f'{email} login failed. check your email/password\n')

    def two_factor_error(): 
        cout('Two-factor authentication failed. Please try logging in again.\n')

    jsi = JSI()

    logger.info(f"checking if user is already logged in...?")
    response = jsi.user_self()
    if response and response.status_code == 200:
        logger.info(f"Yes, user is already logged in!")
        if jsi.api_token:
            cout("API token detected. You can proceed with API token-based operations without the need for manual login.")
        else:
            cout("You are currently logged in using login credentials. No API token is in use.")
    else:
        logger.info('input username')
        cout("To connect your device to the JSI service, log in with your Mist Cloud ID. If you don't have one? head over to https://manage.mist.com")
        email = input("Username: ")

        logger.info('Calling user lookup function to check if username is registered and available')
        response = jsi.user_lookup(email)

        if response and response.status_code == 200:
            logger.info('username found! and ask for password')
            password = jcs.get_secret('Password: ')

            logger.info('Call user login function using username(email format) and password')
            response = jsi.user_login(email, password)
            if response and response.status_code == 200:  # login check
                logger.info('login successful! But check if two-factor authentication is required')
                response = jsi.user_self()
                if response and response.status_code == 200:  # user-self check
                    self_info = response.json()
                    logger.info('Checking if two-factor authentication is required???')
                    if 'two_factor_required' in self_info and 'two_factor_passed' in self_info:  # two factor auth check
                        if self_info['two_factor_required'] and not self_info['two_factor_passed']:
                            logger.info('Ok, two-factor authentication required and get the two-factor authentication code')
                            logger.info('Ask a user to enter the two-factor authentication code')

                            code = input("Enter the two-factor authentication code: ")

                            logger.info(f"two-factor authentication code: {code}")
                            logger.info('Submit a two-factor authentication code to the server')
                            response = jsi.user_two_factor_auth(code) # two factor auth code check
                            if response and response.status_code == 200:
                                # user privileges info check - there might be a race condition issue with two factor authentication
                                logger.info("two-factor authentication passed! Let's check if user privileges info is available?")
                                response = jsi.user_self()
                                if response and response.status_code == 200:  # user-self check
                                    if 'privileges' not in response.json(): 
                                        logger.info("user session-expiry info is not available. Let's logout and try again.")
                                        jsi.user_logout()
                                        login_error(email)
                                        two_factor_error()
                                    else:
                                        logger.info('Good! - user session is active and privileges info is available.')
                                        login_ok(email)
                                else:
                                    jsi.user_logout()
                                    login_error(email)
                            else:
                                two_factor_error()
                        else:
                            login_ok(email)
                    else:
                        login_ok(email)
                else:
                    login_error(email)
            else:
                login_error(email)
        else:
            login_error(email)
        

# Log out the current user from the system
def user_logout():
    logger.info(f"\n{JunosOS.msg_style('USER LOGOUT COMMAND', style='*', length=80)}")

    jsi = JSI()
    response = jsi.user_self()

    logger.info(f"checking if user is already logged in...?")
    response = jsi.user_self()
    if response and response.status_code == 200:
        logger.info(f"Yes, user is already logged in!")
        if jsi.api_token:
            cout("Logout operation is not applicable when using an API token. Log out is bypassed.")
        else:
            self_info = response.json()
            response = jsi.user_logout()
            if response and response.status_code == 200:
                cout(f"User '{self_info['email']}' has been successfully logged out.")
            else:
                cout("Error: The logout process could not be completed. Please try again.")
    else:
        cout("You appear to be not logged in. Please log in to proceed with logout.")

# Create a new organization with a default site and alarm template
def org_create():
    logger.info(f"\n{JunosOS.msg_style('ORG CREATE COMMAND', style='*', length=80)}")

    jsi = JSI()
    logger.info(f"checking if user is already logged in...?")
    response = jsi.user_self()
    if response and response.status_code == 200:
        logger.info(f"Yes, user is already logged in!")

        while True:
            org_name = input("Please enter the name of the organization you wish to create: ")
            pattern = r'^[A-Za-z][A-Za-z0-9 _-]*$'
            if re.match(pattern, org_name):
                cout(f"Organization name '{org_name}' is valid.")
                break
            else:
                cout("Invalid name. Must start with a letter and include only letters, numbers, spaces, '-', '_'.")

        orgs = jsi.org_list()
        orgs_name_list = [org['name'] for org in orgs]
        if org_name in orgs_name_list:
            cout(f"Organization '{org_name}' already exists. No action taken.")
        else:
            response = jsi.org_create(org_name)
            if response and response.status_code == 200:
                cout(f"Organization '{org_name}' created successfully.")
                org = response.json()
                org_id = org['id']
                site_name = DEFAULT_SITE_NAME
                response = jsi.site_create(org_id, site_name)
                if response and response.status_code == 200:
                    cout(f"Site '{site_name}' created successfully within '{org_name}'.")
                else:
                    cout(f"Error: Failed to create site '{site_name}' in '{org_name}'.")
                    return

                response = jsi.alarm_template_create(
                    org_id, template_name=DEFAULT_ALARM_TEMPLATE_NAME)
                if response and response.status_code == 200:
                    alarm_template = response.json()
                    alarm_template_name = alarm_template['name']
                    alarm_template_id = alarm_template['id']
                    cout(f"Alarm template '{alarm_template_name}[{alarm_template_id}]' created successfully in '{org_name}'.")
                else:
                    cout(f"Error: Failed to create an alarm template in '{org_name}'.")
                    return

            else:
                cout(f"Error: Unable to create organization '{org_name}'. Please check the details and try again.")
    else:
        cout("User authentication required. Please log in to create an organization.")

# Delete an existing organization after user confirmation
def org_delete():
    logger.info(f"\n{JunosOS.msg_style('ORG DELETE COMMAND', style='*', length=80)}")

    jsi = JSI()
    logger.info(f"checking if user is already logged in...?")
    response = jsi.user_self()
    if response and response.status_code == 200:
        logger.info(f"Yes, user is already logged in!")
        current_orgs = jsi.org_list()
        if current_orgs:
            headers = ["Number", "Org name", "Role", "Id"]
            table = [[index, org['name'], org['role'], org['org_id']]
                     for index, org in enumerate(current_orgs, start=1)]
            tabulated_table = Tabulate(table, headers)

            cout("Available Organizations:")
            cout(tabulated_table)

            while True:
                choice_input = input(f"Enter your choice (1-{len(table)}): ")
                try:
                    choice = int(choice_input)
                    if 1 <= choice <= len(table):
                        choice -= 1
                        org_name = table[choice][1]
                        break
                    else:
                        cout(
                            f"Please enter a number between 1 and {len(table)}.")
                except ValueError:
                    cout("Invalid input. Please enter a numeric value.")

            # Add confirmation input
            confirm = input(f"Are you sure you want to delete the organization '{org_name}'? (y/n): ").lower()
            if confirm != 'y':
                cout("Deletion cancelled.")
                return

            org_found = False
            for org in current_orgs:
                if org['name'] == org_name:
                    org_found = True
                    response = jsi.org_delete(org['org_id'])
                    if response and response.status_code == 200:
                        cout(f"Organization '{org_name}' has been successfully deleted.")
                        return
                    else:
                        error_message = response.json().get('detail', 'Unknown error. Please try again.')
                        cout(f'Error: Unable to delete organization \'{org_name}\'. Reason: "{error_message}"')
                        return
            if not org_found:
                cout(f"Error: Organization '{org_name}' not found. Please verify the organization name.")
        else:
            cout("No organizations found. You are either not a member of any organizations or there are no organizations available.")
    else:
        cout("User authentication required. Please log in to perform deletion of an organization.")

# List all organizations that the current user has access to
def org_list():
    logger.info(f"\n{JunosOS.msg_style('ORG LIST COMMAND', style='*', length=80)}")

    jsi = JSI()
    logger.info(f"checking if user is already logged in...?")
    response = jsi.user_self()
    if response and response.status_code == 200:
        logger.info(f"Yes, user is already logged in!")
        current_orgs = jsi.org_list()
        if current_orgs:
            headers = ["Number", "Org name", "Role", "Id"]
            table = [[index, org['name'], org['role'], org['org_id']]
                     for index, org in enumerate(current_orgs, start=1)]
            tabulated_table = Tabulate(table, headers)

            cout("Available Organizations:")
            cout(tabulated_table)
        else:
            cout("No organizations found. You are either not a member of any organizations or there are no organizations available.")
    else:
        cout("Authentication required. Please log in to view the list of organizations.")

# Retrieve and display settings for a specific organization
def org_setting():
    logger.info(f"\n{JunosOS.msg_style('ORG SETTING COMMAND', style='*', length=80)}")

    jsi = JSI()
    logger.info(f"checking if user is already logged in...?")
    response = jsi.user_self()
    if response and response.status_code == 200:
        logger.info(f"Yes, user is already logged in!")
        current_orgs = jsi.org_list()
        if current_orgs:
            headers = ["Number", "Org name", "Role", "Id"]
            table = [[index, org['name'], org['role'], org['org_id']]
                     for index, org in enumerate(current_orgs, start=1)]
            tabulated_table = Tabulate(table, headers)

            cout("Available Organizations:")
            cout(tabulated_table)

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
                        cout(f"Please enter a number between 1 and {len(table)}.")
                except ValueError:
                    cout("Invalid input. Please enter a numeric value.")

            response = jsi.org_setting(org_id)
            if response and response.status_code == 200:
                org_setting = response.json()
                JunosOS.print_with_style(f"Organization '{org_name}' setting:")
                JunosOS.jprint(org_setting, parent_key='setting')
            else:
                cout(f"Error: Unable to retrieve organization '{org_name}' settings. Please check the details and try again.")
        else:
            cout("No organizations found. You are either not a member of any organizations or there are no organizations available.")
    else:
        cout("User authentication required. Please log in to perform deletion of an organization.")

# Connect a device to an organization and site, including handling various configurations
def device_connect():
    logger.info(f"\n{JunosOS.msg_style('DEVICE CONNECT COMMAND', style='*', length=80)}")

    jsi = JSI()
    logger.info(f"checking if user is already logged in...?")
    response = jsi.user_self()
    if response and response.status_code == 200:
        logger.info(f"Yes, user is already logged in!")
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

                cout(f"Device is currently connected to organization '{org_name}' and site '{site_name}'.")
                cout("To proceed with a new connection, please disconnect the device from the current organization and site first.")
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
                cout("Available Organizations and Sites:")
                headers = ["Number", "Organization Name",
                           "Org Permission", "Site Name", "Site Permission"]
                tabulated_table = Tabulate(org_table, headers)
                cout(tabulated_table)
                cout("Please select the number corresponding to your choice of Organization and Site.")
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
                            cout(f"Please enter a number between 1 and {len(org_table)}.")
                    except ValueError:
                        cout("Invalid input. Please enter a numeric value.")
            else:
                cout("No organizations or sites available to connect a device.")
                return
        else:
            cout("You do not have access to any organizations or sites to connect a device.")
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

                result = JunosOS.junos_cli(
                    f'edit;load set {JSI_OSC_CONFIG};commit and-quit')
                if 'commit complete' in result:
                    cout('Device connection commands have been successfully applied.')
                else:
                    cout(f'Error applying connection commands: {result}')
            else:
                cout('Device connection commands (for manual execution):')
                cout(cmds)
        else:
            cout('Error: Failed to retrieve device connection commands. Please check your cloud connectivity.')
    else:
        cout('Authentication required. Please log in and try again.')

# Retrieve and display inventory information for a device
def device_inventory():
    logger.info(f"\n{JunosOS.msg_style('DEVICE INVENTORY COMMAND', style='*', length=80)}")

    if not JunosOS.is_junos():
        cout('Error: This command is available only on Junos or Junos Evo devices.')
        return

    jsi = JSI()
    logger.info(f"checking if user is already logged in...?")
    response = jsi.user_self()
    if response and response.status_code == 200:
        logger.info(f"Yes, user is already logged in!")
        sn = JunosOS.get_device_sn()
        response = jsi.get_inventory_from_orgs(sn)
        if response and response.status_code == 200:
            inventory = response.json()
            if inventory:
                JunosOS.print_with_style("Device Inventory Details:")
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
                    device['created_time'] = JunosOS.unix_timestamp_to_datetime(
                        created_time)
                    device['modified_time'] = JunosOS.unix_timestamp_to_datetime(
                        modified_time)
                    JunosOS.jprint(device, parent_key='inventory')
            else:
                cout("No inventory data found for this device.")
        else:
            cout("No existing device connection found. Please connect the device first.")
    else:
        cout("User authentication required. Please log in and try again.")

# Disconnect a device from its current organization and site, and handle relevant configurations
def device_disconnect():
    logger.info(f"\n{JunosOS.msg_style('DEVICE DISCONNECT COMMAND', style='*', length=80)}")

    if not JunosOS.is_junos():
        cout('Error: This command can only be executed on a Junos/Junos Evo device.')
        return

    jsi = JSI()
    logger.info(f"checking if user is already logged in...?")
    response = jsi.user_self()
    if response and response.status_code == 200:
        logger.info(f"Yes, user is already logged in!")
        jsi = JSI()
        sn = JunosOS.get_device_sn()
        response = jsi.get_inventory_from_orgs(sn)
        if response and response.status_code == 200:
            inventory = response.json()
            if inventory:
                if len(inventory) == 0:
                    cout('No existing connection found for this device. It appears the device was not connected previously.')
                    return
                org_id = inventory[0].get('org_id', '')

                if org_id:
                    confirm = input("Confirm device disconnection (y/n): ").lower().strip()
                    if confirm == 'y':
                        cout("Proceeding with device disconnection...")
                    elif confirm == 'n':
                        cout("Device disconnection cancelled.")
                        return
                    else:
                        cout("Invalid input. Device disconnection not executed.")
                        return

                response = jsi.inventory_delete(org_id, sn)
                if response and response.status_code == 200:
                    inventory = response.json()
                    cout('Device has been successfully disconnected and removed from inventory.')
                    cout('The login Username and outbound-SSH service used for cloud device attachment remain. Please locate and delete them if you want.')

                    # Comment out the following commands, as there is a chance they might remove the login username and outbound SSH 
                    # even before MIST completes its configuration cleanup, such as config groups, events, etc.
                    # Let's park this block until we figure out how to wait until the configuration cleanup is complete.
                    # ----------------------------------------------------------------
                    # if JunosOS.is_junos():
                    #     cout('Please wait for 30 seconds...')
                    #     time.sleep(30)
                    #     cmds = ''
                    #     if JunosOS.is_user_mist_config():
                    #         cmds += 'delete system login user mist\n'
                    #     if JunosOS.is_outbound_ssh_mist_config():
                    #         cmds += 'delete system services outbound-ssh client mist\n'

                    #     with open(JSI_OSC_CONFIG, 'w') as file:
                    #         file.write(cmds)

                    #     result = JunosOS.junos_cli(f'edit;load set {JSI_OSC_CONFIG};commit and-quit')
                    #     if 'commit complete' in result:
                    #         cout('Device connection deletion commands have been successfully applied.')
                    #     else:
                    #         cout(f'Error applying connection commands: {result}')
                    # else:
                    #     cout('Device connection commands (for manual execution):')
                    #     cout(cmds)
                    # ----------------------------------------------------------------

                else:
                    cout('Error: Unable to disconnect the device. Please check the connection status or try again.')
                    inventory = response.json()
                    JunosOS.jprint(inventory, parent_key='inventory')
            else:
                cout(
                    'No existing connection found. Please ensure the device was connected previously.')
        else:
            cout('No existing connection found for this device. It appears the device was not connected previously.')
    else:
        cout('You must be logged in to perform this operation. Please log in and try again.')

# Set an API token for authenticating subsequent commands
def api_token_set():
    logger.info(f"\n{JunosOS.msg_style('API-TOKEN SET COMMAND', style='*', length=80)}")

    jsi = JSI()

    if jsi.api_token:
        cout("An API token is already set. Please remove the current API token before attempting to set a new one.")
        return

    cout("Enter the API Token to authenticate your requests. This token will be used for all subsequent commands.\n")
    token = jcs.get_secret("API Token: ")

    if token:
        jsi.api_token_set(token)
    else:
        cout('No API Token provided. Please enter a valid API token to proceed.')

# Remove the currently set API token
def api_token_delete():
    logger.info(f"\n{JunosOS.msg_style('API-TOKEN RESET COMMAND', style='*', length=80)}")

    jsi = JSI(user_login_session_check=False)
    jsi.api_token_delete()
    cout('Api Token is removed!')

# Check if the device is connected to the Internet
def check_https(default_check_url='https://api.mist.com'):
    logger.info(f"\n{JunosOS.msg_style('CHECK HTTPS COMMAND', style='*', length=80)}")

    def extract_hostname(url):
        parsed_url = urlparse(url)
        return parsed_url.netloc

    hostname = extract_hostname(default_check_url)

    # DNS resolution check
    try:
        logger.info(f"Checking DNS resolution using socket.gethostbyname('{default_check_url}')")
        socket.gethostbyname(hostname)
        cout("PASS 1: DNS resolution working!")
    except socket.error as e:
        cout(f"FAIL: DNS resolution failed for {hostname}. Details: {e}")
        return False

    # HTTPS connection check
    try:
        jsi = JSI(user_login_session_check=False)
        logger.info(f"Checking HTTPS connection using requests.get('{default_check_url}'")
        requests.get(default_check_url, timeout=10, verify=False, proxies=jsi.web_proxy)
        cout("PASS 2: HTTPS connection working!")
    except requests.exceptions.Timeout:
        cout("FAIL: The HTTPS request timed out. Check your network path or your firewall configuration.")
        return False
    except requests.exceptions.RequestException as e:
        cout(f"FAIL: An unspecified error occurred during the HTTPS request. Details: {e}")
        return False

    cout("All checks have passed; the device has HTTPS access.")
    return True

# Set https proxy URL
def web_proxy_set(protocol):
    logger.info(f"\n{JunosOS.msg_style('PROXY SET COMMAND', style='*', length=80)}")

    jsi = JSI()

    while True:
        proxy = input(f"Enter the {protocol.upper()} proxy url: ")
        is_valid = jsi.is_valid_proxy_url(proxy)
        if is_valid:
            break
        cout("Invalid proxy URL. Please try again.")

    username = input("Enter Username (press Enter if no username required): ")
    password = jcs.get_secret("Enter Password (press Enter if no password required): ")
    
    username = username.strip()
    password = password.strip()

    jsi.web_proxy_set(protocol=protocol, proxy_url=proxy, username=username, password=password)
    
# List the current web proxy settings
def web_proxy_list():
    logger.info(f"\n{JunosOS.msg_style('PROXY LIST COMMAND', style='*', length=80)}")

    jsi = JSI()

    JunosOS.print_with_style(f'Web Proxy Settings:')
    web_proxy = jsi.web_proxy_get()

    https_proxy = web_proxy.get('https', '')
    http_proxy = web_proxy.get('http', '')

    proxies = {}
    if https_proxy:
        https_proxy = jsi.web_proxy_mask(https_proxy)
        proxies.update({'https': str(https_proxy)})

    if http_proxy:
        http_proxy = jsi.web_proxy_mask(http_proxy)
        proxies.update({'http': str(http_proxy)})

    JunosOS.jprint(proxies, parent_key='proxy')

# Delete the current web proxy settings
def web_proxy_remove():
    logger.info(f"\n{JunosOS.msg_style('PROXY REMOVE COMMAND', style='*', length=80)}")

    jsi = JSI()

    web_proxy = jsi.web_proxy_get()
    if web_proxy:
        # Proxy Removal confirmation input
        confirm = input(f"Are you sure you want to delete the web proxy setting? (y/n): ").lower()
        if confirm != 'y':
            cout("Web Proxy removal cancelled.")
            return

        jsi.web_proxy_remove()
        cout('Web Proxy Settings are removed!')
    else:
        cout('Web Proxy Settings are not set.')

# Phone home client class    
class PHC:
    def __init__(self, serial_number):
        self.serial_number = serial_number
        self.jsi = JSI(user_login_session_check=False)

    def fetch_jnpr_redirect_info(self):
        logger.info(f"\n{JunosOS.msg_style('Fetching a bootstrap info from Juniper Redirector', style='*', length=80)}")
        url = f'https://redirect.juniper.net/restconf/data/juniper-zerotouch-bootstrap-server:devices/device={self.serial_number}'
        for i in range(1, 11):
            try:
                logger.info(f'requesting {url}')
                response = requests.get(url, auth=HTTPBasicAuth(self.serial_number, ''), verify=False, timeout=30, proxies=self.jsi.web_proxy)
                if response.status_code == 500:
                    if i == 10:
                        cout("        Error: Redirect server reports continuous internal errors.")
                        sys.exit(0)
                    cout(f"        try {i} - Redirect server internal error. continue to try again.")
                    time.sleep(5)
                    continue
                break
            except ReadTimeout:
                if i == 10:
                    cout("        Error: redirect server is not responding. Please check your network path or your firewall configuration.")
                    sys.exit(0)
                cout(f"        try {i} - The redirect request timed out. continue to try again.")
                time.sleep(5)
                continue
            except ProxyError:
                cout(f"        Error: Cannot connect to proxy. Please check your proxy settings.")
                sys.exit(0)
            except requests.exceptions.RequestException as e:
                cout(f"An error occurred: {e}")
                sys.exit(0)

        if response.status_code == 200:
            logger.debug(f'Status Code: {response.status_code}')
            logger.debug(f'\n{response.text}')
            root = etree.ElementTree(etree.fromstring(response.text.encode('utf-8')))

            ns = {'ns': 'http://juniper.net/zerotouch-bootstrap-server'}
            bootstrap_servers = root.findall('.//ns:bootstrap-server', namespaces=ns)
            phs = []
            for server in bootstrap_servers:
                address = server.find('ns:address', namespaces=ns).text
                port = server.find('ns:port', namespaces=ns).text
                trust_anchor = server.find('ns:trust-anchor', namespaces=ns).text.strip()
                trust_anchor = f'-----BEGIN CERTIFICATE-----\n{trust_anchor}\n-----END CERTIFICATE-----\n'
                phs.append({
                    'address': address,
                    'port': port,
                    'trust_anchor': trust_anchor
                })
            return OpResult(phs, True)
        return OpResult(response.status_code, False)
        

    def fetch_bootstrap_config(self, address, port, trust_anchor):
        logger.info(f"\n{JunosOS.msg_style('Fetching a initial configuration from PHS', style='*', length=80)}")

        url = f'https://{address}:{port}/restconf/data/juniper-zerotouch-bootstrap-server:devices/device={self.serial_number}'

        with tempfile.NamedTemporaryFile(delete=False, mode='w') as ca_file:
            ca_file.write(trust_anchor)
            ca_file_path = ca_file.name
        
        for i in range(1, 11):
            try:
                logger.info(f'requesting {url}')
                response = requests.get(url, auth=HTTPBasicAuth(self.serial_number, ''), verify=ca_file_path, timeout=30, proxies=self.jsi.web_proxy)
                if response.status_code == 500:
                    if i == 10:
                        cout("        Error: Continuous internal errors reported by the bootstrap server.")
                        sys.exit(0)
                    cout(f"        Attempt {i} - Failed: Internal error at the phone home server. Retrying...")
                    time.sleep(5)
                    continue
                break
            except ReadTimeout:
                if i == 10:
                    cout("        Error: The bootstrap server is not responding. Please verify your network connection and firewall settings.")
                    sys.exit(0)
                cout(f"        Attempt {i} - Request timed out. Attempting to reconnect...")
                time.sleep(5)
                continue
            except ProxyError:
                cout("        Error: Cannot connect to proxy. Please check your proxy settings.")
                sys.exit(0)
            except requests.exceptions.RequestException as e:
                cout(f"An error occurred: {e}")
                sys.exit(0)

        os.remove(ca_file_path)

        if response.status_code == 404:
            return OpResult(response.status_code, False)

        if response.status_code == 200:
            config = str(response.text)
            logger.info(f'config:\n{config}')
            config = config.replace(' xmlns="http://juniper.net/zerotouch-bootstrap-server"', '')
            root = etree.ElementTree(etree.fromstring(config))
            config_element = root.find('.//config/configuration')
            config_string = etree.tostring(config_element, pretty_print=True).decode()                
            return OpResult(config_string, True)
        
        return OpResult(response.status_code, False)

# Call home (phone home) client
def phone_home():
    logger.info(f"\n{JunosOS.msg_style('PHONE HOME COMMAND', style='*', length=80)}")

    JunosOS.print_with_style(f'Tech Preview - Phone Home Client (PHC) Starts:')
    sn = JunosOS.get_device_sn()

    phc = PHC(sn)

    cout('STEP 1: Fetching a redirect info from https://redirect.juniper.net')
    phone_home_servers = phc.fetch_jnpr_redirect_info()

    if phone_home_servers:
        for server in phone_home_servers:
            cout(f'STEP 2: Fetching a initial bootstrap configuration from https://{server["address"]}:{server["port"]}')
            result = phc.fetch_bootstrap_config(server['address'], server['port'], server['trust_anchor'])
            if result:
                config_xml = str(result)
                cout(f'STEP 3: Config commit starts...')
                result = JunosOS.junos_commit_xml(config_xml) 
                if result:
                    cout(f'        Done! - Config commit successful.')
                    JunosOS.print_with_style(f'Phone Home Client (PHC) ends successfully')
                else:
                    cout(f'Error: PHC completes but config commit failed.')
                break
            else:
                status_code = int(result)
                cout(f'Error: PHC failed to fetch bootstrap info from https://{server["address"]}:{server["port"]}.')
                cout(f'       Received status code {status_code}.')
    else:
        status_code = int(phone_home_servers)
        if status_code == 404:
            cout(f'Error: Received status code {status_code}.')
            cout(f'       Device with serial number ({sn}) has not been claimed. Please claim the device before retrying.')
        else:
            cout(f'Error: Received status code {status_code}.')

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

def set_log_level(level):
    jsi = JSI()
    jsi.set_log_level(level)
    print(f'Log level is set to "{level}"')

def get_log_level():
    jsi = JSI()
    print(f'Log level is "{jsi.log_level}"')

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
            # Comment out the following commands, as they may cause a significant impact on JSI operations.
            # 'create': {
            #     '_action': lambda: org_create(),
            #     '_help': "Create a new organization.",
            #     '_alias': ['--create', '-create'],
            # },
            # 'delete': {
            #     '_action': lambda: org_delete(),
            #     '_help': "Delete an existing organization.",
            #     '_alias': ['--delete', '-delete'],
            # },
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
        'check': {
            'https': {
                '_action': lambda: check_https(),
                '_help': "Check https access.",
                '_alias': ['--check', '-check'],
            },
            '_help': "Check access to https endpoints.",
            '_alias': ['--check', '-check'],
        },
        'proxy': {
            'https': {
                '_action': lambda: web_proxy_set('https'),
                '_help': "Set https proxy.",
                '_alias': ['--https', '-https'],
            },
            'http': {
                '_action': lambda: web_proxy_set('http'),
                '_help': "Set http proxy.",
                '_alias': ['--http', '-http'],
            },
            'list': {
                '_action': lambda: web_proxy_list(),
                '_help': "List web proxy setting.",
                '_alias': ['--list', '-list'],
            },
            'remove': {
                '_action': lambda: web_proxy_remove(),
                '_help': "Remove web proxy setting.",
                '_alias': ['--remove', '-remove'],
            },
            '_help': "Mange proxy: https, http, remove.",
            '_alias': ['--proxy', '-proxy'],
        },
        'phone': {
            'home': {
                '_action': lambda: phone_home(),
                '_help': "Call home to get an initial configuration.",
                '_alias': ['--home', '-home'],
            },
            '_help': "Run phone-home client: home",
            '_alias': ['--phone', '-phone'],
        },
        'log': {
            'level': {
                '_action': lambda: get_log_level(),
                '_help': "Show logging level",
                '_alias': ['--level', '-level'],
            },
            'info': {
                '_action': lambda: set_log_level('info'),
                '_help': "Set logging level to info.",
                '_alias': ['--info', '-info'],
            },
            'warning': {
                '_action': lambda: set_log_level('warning'),
                '_help': "Set logging level to warning.",
                '_alias': ['--warning', '-warning'],
            },
            'error': {
                '_action': lambda: set_log_level('error'),
                '_help': "Set logging level to error.",
                '_alias': ['--error', '-error'],
            },
            'critical': {
                '_action': lambda: set_log_level('critical'),
                '_help': "Set logging level to critical.",
                '_alias': ['--critical', '-critical'],
            },
            'debug': {
                '_action': lambda: set_log_level('debug'),
                '_help': "Set logging level to debug.",
                '_alias': ['--debug', '-debug'],
            },
            '_help': "Set log level: level, info, warning, error, critical, debug.",
            '_alias': ['--log', '-log'],
        },
        '_help': "Main commands: user, device, org, api-token, check, proxy, phone, log",
    }

    logger.info(f"\n{JunosOS.msg_style('[ JSI CLI STARTS ]', style='#', length=80)}")
    logger.info(f"sys.argv: {sys.argv}")

    commands = sys.argv[1:]
    CLIOptions(my_schema).run(commands)

    logger.info(f"\n{JunosOS.msg_style('Bye! JSI CLI ends.', style=' ', length=80)}")


