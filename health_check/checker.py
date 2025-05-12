import requests
from bs4 import BeautifulSoup
import re
import dns.resolver
import ipaddress
import socket

from datetime import datetime


def verify_dns(domain, logger, ports=[80, 443]):
    """
    Comprehensive DNS check and IP address/port availability for a given domain (default ports 80 and 443).

    Args:
        domain (str): Domain name to check.
        logger (Logger): Logger object for event logging.
        ports (list): List of ports to check (default [80, 443]).

    Logic:
        1. Checks if the domain can be resolved to IP (standard DNS, then public).
        2. If resolution fails, writes error to log.
        3. If IP addresses are found — checks port availability.
        4. If at least one IP has port 443 open — returns True.
        5. If port 443 is not open on any IP — logs error.
    """
    resolvable, ips = check_dns(domain)
    if not resolvable:
        resolvable, ips = check_dns(domain, customnameservers=True)

    if not resolvable:
        logger.error("[DNS_CHECK] - DNS resolution failed for %s", domain)

    else:

        for ip in ips:

            ports_to_check = ports

            port_access_found = False  # flag if at least one IP has an open port
            results = check_ports(ip, ports_to_check)

            for port in ports_to_check:
                if results[port]:

                    if port == 443:
                        port_access_found = True

        if not port_access_found:
            logger.info(
                "[DNS_CHECK] - DNS resolution successful, IPs: %s", ", ".join(ips)
            )
            logger.error(
                "[IP_CHECK] - IP addresses are private or behind a firewall, IPs: %s",
                ", ".join(ips),
            )

        # Check if at least one port 443 is available
        if port_access_found:
            return True


def check_dns(domain, customnameservers=False):
    """
    Checks if the domain can be resolved to IP addresses.

    Args:
        domain (str): Domain name.
        customnameservers (bool): Use public DNS (True) or default (False).

    Returns:
        tuple: (resolvable (bool), list of IPs (list))

    Logic:
        1. Gets A-records for the domain.
        2. Uses public DNS if customnameservers=True.
        3. On success returns (True, list of IPs), else (False, []).
    """
    try:
        answers = dns.resolver.resolve(domain, "A")
        if customnameservers:
            answers.nameservers = ["8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1"]
        ip_list = [rdata.address for rdata in answers]
        return True, ip_list
    except dns.resolver.NXDOMAIN:
        return False, []
    except dns.resolver.NoAnswer:
        return False, []
    except dns.resolver.Timeout:
        return False, []


def is_public_ip(ip):
    """
    Determines whether the IP address is public.

    Args:
        ip (str): IP address.

    Returns:
        bool: True if the IP is public, else False.

    Logic:
        - Converts the string to an ipaddress object.
        - Checks if the address is not private, loopback, or reserved.
    """
    ip_obj = ipaddress.ip_address(ip)
    return not (ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_reserved)


def check_ports(ip, ports, timeout=2):
    """
    Checks the availability of the specified ports on the given IP address.

    Args:
        ip (str): IP address.
        ports (list): List of ports to check.
        timeout (int): Connection timeout in seconds (default 2).

    Returns:
        dict: Dictionary {port: bool}, where True means the port is open, False means closed.

    Logic:
        - For each port in the list, tries to establish a TCP connection.
        - If the connection is successful — the port is considered open.
        - In case of error or timeout — the port is considered closed.
        - Returns a dictionary with results for each port.
    """
    results = {}
    for port in ports:
        try:
            with socket.create_connection((ip, port), timeout=timeout):
                results[port] = True
        except (socket.timeout, socket.error):
            results[port] = False
    return results


def check_http(domain, url, keyword, timeout, logger):
    """
    Checks if the specified URL is available and if the response contains the keyword.

    Args:
        domain (str): Domain (not used directly but can be useful for logging).
        url (str): URL to check.
        keyword (str): Keyword to search for in the response.
        timeout (int): Request timeout in seconds.
        logger (Logger): Logger object for event logging.

    Returns:
        bool: True if status code is 200 and the keyword is found in the response body. Otherwise False.

    Logic:
        - Performs an HTTP GET request to the specified URL.
        - If status code is 200, extracts text from the HTML and searches for the keyword (case-insensitive).
        - If found — prints a positive result to the console, returns True.
        - If not found — logs an error, returns False.
        - If status code is not 200 — logs an error, returns False.
        - In case of request error — logs it as an error.
    """
    try:
        resp = requests.get(url, timeout=timeout)
        if resp.status_code == 200:
            soup = BeautifulSoup(resp.text, "html.parser")
            text = soup.get_text(separator=" ", strip=True)
            pattern = r"\b" + re.escape(keyword) + r"\b"
            if re.search(pattern, text, re.IGNORECASE):
                now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                print(
                    f'[{now}] [INFO] - [HTTP_CHECK] - Status code is %d and response body contains a keyword "%s"'
                    % (resp.status_code, keyword)
                )
                return True
            else:
                logger.error(
                    '[HTTP_CHECK] - Check failed for url %s. Keyword "%s" not found in response text.',
                    url,
                    keyword,
                )
                return False
        else:
            logger.error("[HTTP_CHECK] - Status code %d received", resp.status_code)
            return False

    except requests.exceptions.RequestException as e:
        logger.error("[HTTP_CHECK] - Request failed: %s", str(e))
