#!/usr/bin/env python
# -*- coding: utf-8 -*-
import base64
import logging
import requests
import json


requests.packages.urllib3.disable_warnings()

LOG = logging.getLogger('hillstone_log')


def password_base64(password):
    password = base64.b64encode(password.encode('utf-8')).decode('utf-8')
    return password


# path
URL_BASE = 'https://{host}/{resource}'
LOGIN_PATH = 'rest/doc/login'


class HillStoneRestAPI:

    def __init__(self, host):
        self.userName = 'hillstone'
        self.password = password_base64('hillstone')
        self.lang = "zh_CN"
        self.host = host
        self.auth = {
            'userName': self.userName,
            'password': self.password,
            'lang': self.lang
        }
        self.token = None
        self.timeout = 10.0
        self.status = requests.codes.OK
        self.session = requests.Session()
        self.result = {}
        self.cookies = {}

    def authenticate(self):
        url = URL_BASE.format(host=self.host, resource=LOGIN_PATH)
        response = requests.post(url, data=json.dumps(self.auth), verify=False).json()
        if response.get('success'):
            self.token = response.get('result').get('token')
            self.result = response.get('result')
            self.cookies = {
                'fromrootvsys': self.result.get('fromrootvsys'),
                'role': self.result.get('role'),
                'vsysId': self.result.get('vsysId'),
                'token': self.token,
                'username': 'hillstone',
                'lang': 'zh_CN',
            }
            return True
        return False

    def _request(self, method, resource, payload=None):
        """Perform a REST request to a Hillstone resource."""
        if self.token is None:
            self.authenticate()
        url = URL_BASE.format(host=self.host, resource=resource)
        LOG.info('%s  Request URL is: %s' % (method, url))
        cookies = self.cookies
        response = self.session.request(method, url=url, data=json.dumps(payload), cookies=cookies, verify=False).json()
        return response

    def get_request(self, resource):
        """Perform a REST GET requests for a Hillstone resource."""
        return self._request('GET', resource)

    def post_request(self, resource, payload=None):
        """Perform a POST request to a Hillstone resource."""
        return self._request('POST', resource, payload)

    def delete_request(self, resource, payload=None):
        """Perform a DELETE request on a Hillstone resource."""
        return self._request('DELETE', resource, payload=payload)

    def get_info(self, resource):
        return self.get_request(resource)

    def create_rule(self, resource, payload):
        return self.post_request(resource, payload)

    def delete_rule(self, resource, payload):
        return self.delete_request(resource, payload)

    def create_address(self, name, addresses):
        ip = []
        for address in addresses.split(','):
            temp = {
                "ip_addr": address.split('/')[0],
                "netmask": address.split('/')[1],
                "flag": 0
            }
            ip.append(temp)

        payload = {
            "name": name,
            "ip": ip
        }
        return self.create_rule('rest/doc/addrbook', payload)

    def create_service(self, name, ports):
        row = []
        for port in ports.split(','):
            port1 = port.split('-')
            temp = [{
                "protocol": "6",
                "dp_low": min(port1),
                "dp_high": max(port1),
                'sp_low': '0',
                'sp_high': '0',

            }, {
                "protocol": "17",
                "dp_low": min(port1),
                "dp_high": max(port1),
                'sp_low': '0',
                'sp_high': '0',
            }]
            row.extend(temp)
        payload = {
            "name": name,
            "type": "0",
            "row": row
        }
        return self.create_rule('rest/doc/servicebook', payload)

    def create_policy(self, name, src_zone, src_name, dst_zone, dst_name, service):
        payload = [{
            "action": "2",
            # "enable": 0,
            "name": {
                "name": name
            },
            "src_zone": {
                "name": src_zone
            },
            "src_addr": {
                "member": src_name,
                "type": "0"
            },
            "dst_zone": {
                "name": dst_zone
            },
            "dst_addr": {
                "member": dst_name,
                "type": "0"
            },
            "service": [{
                "member": service
            }],
        }]

        return self.create_rule('rest/doc/policy', payload)
