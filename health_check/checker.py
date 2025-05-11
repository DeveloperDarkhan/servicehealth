import requests
from bs4 import BeautifulSoup
import re
import dns.resolver
import ipaddress
import socket

from datetime import datetime

def check_dns(domain):
    try:
        answers = dns.resolver.resolve(domain, 'A')
        ip_list = [rdata.address for rdata in answers]
        return True, ip_list
    except dns.resolver.NXDOMAIN:
        return False, []
    except dns.resolver.NoAnswer:
        return False, []
    except dns.resolver.Timeout:
        return False, []

def is_public_ip(ip):
    ip_obj = ipaddress.ip_address(ip)
    return not (ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_reserved)

# def check_port(ip, port, timeout=3):
#     try:
#         with socket.create_connection((ip, port), timeout=timeout):
#             return True
#     except (socket.timeout, socket.error):
#         return False
    
def check_ports(ip, ports, timeout=3):
    results = {}
    for port in ports:
        try:
            with socket.create_connection((ip, port), timeout=timeout):
                results[port] = True
        except (socket.timeout, socket.error):
            results[port] = False
    return results


def check_http(url, keyword, timeout, logger):
    try:
        resp = requests.get(url, timeout=timeout)
        if resp.status_code == 200:
            soup = BeautifulSoup(resp.text, 'html.parser')
            text = soup.get_text(separator=' ', strip=True)
            pattern = r'\b' + re.escape(keyword) + r'\b'
            if re.search(pattern, text, re.IGNORECASE):
                now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                print(f'[{now}] [INFO] [HTTP_CHECK] - Status code is 200 and response body contains a keyword "{keyword}"')
                return True
            else:
                # if logger:
                logger.error('[HTTP_CHECK] - Status code 200 but keyword "%s" not found in response text', keyword)
                return False
        else:
            # if logger:
            logger.error('[HTTP_CHECK] - Status code %d received', resp.status_code)
            return False
    except Exception as e:
        # if logger:
        logger.error('[HTTP_CHECK] - Exception: %s', str(e))
        # return False
