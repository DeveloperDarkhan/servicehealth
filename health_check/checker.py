import requests
from bs4 import BeautifulSoup
import re
import dns.resolver
import ipaddress
import socket

from datetime import datetime


def verify_dns(domain, logger, ports=[80, 443]):
    resolvable, ips = check_dns(domain)
    if not resolvable:
        resolvable, ips = check_dns(domain, customnameservers=True)

    if not resolvable:
        logger.error("[DNS_CHECK] - DNS resolution failed for %s", domain)

    else:
        # logger.info("[DNS_CHECK] - DNS resolution successful, IPs: %s", ', '.join(ips))
        for ip in ips:
            # if is_public_ip(ip):
            # logger.info("[IP_CHECK] - %s is public IP", ip)

            ports_to_check = ports
            # port_access = False
            port_access_found = False  # флаг, если хотя бы один IP с открытым портом
            results = check_ports(ip, ports_to_check)

            for port in ports_to_check:
                if results[port]:
                    # logger.info("[PORT_ACCESS] - Access to %s:%s is available", ip, port)
                    if port == 443:
                        port_access_found = True
                # else:
                #     logger.error("[PORT_ACCESS] - Access to %s:%s is not available", ip, port)

            # else:
        if not port_access_found:
            logger.info(
                "[DNS_CHECK] - DNS resolution successful, IPs: %s", ", ".join(ips)
            )
            logger.error(
                "[IP_CHECK] - IP addresses are private or behind a firewall, IPs: %s",
                ", ".join(ips),
            )

        # Проверка если один порт 443 доступен
        if port_access_found:
            return True


def check_dns(domain, customnameservers=False):

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
    ip_obj = ipaddress.ip_address(ip)
    return not (ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_reserved)


def check_ports(ip, ports, timeout=2):
    results = {}
    for port in ports:
        try:
            with socket.create_connection((ip, port), timeout=timeout):
                results[port] = True
        except (socket.timeout, socket.error):
            results[port] = False
    return results


def check_http(domain, url, keyword, timeout, logger):

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
                # if logger:
                logger.error(
                    '[HTTP_CHECK] - Check failed for url %s. Keyword "%s" not found in response text.',
                    url,
                    keyword,
                )
                # logger.error('[HTTP_CHECK] - Status code %d but keyword "%s" not found in response text', resp.status_code, keyword)
                return False
        else:
            # if logger:
            logger.error("[HTTP_CHECK] - Status code %d received", resp.status_code)
            return False

    except requests.exceptions.RequestException as e:
        logger.error("[HTTP_CHECK] - Request failed: %s", str(e))


# Get local IP address
def get_local_ip(logger):
    try:
        # Connect to an external host; doesn't have to be reachable
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
        logger.info("[OWN_IP] - Local IP Address: %s", local_ip)
    except Exception as e:
        logger.error("[OWN_IP] - Exception obtaining local IP: %s", str(e))


# Get public IP address
def get_public_ip(logger):
    try:
        response = requests.get("https://api.ipify.org?format=json")
        response.raise_for_status()
        public_ip = response.json()["ip"]
        logger.info("[OWN_IP] - Public IP Address: %s", public_ip)
    except Exception as e:
        logger.error("[OWN_IP] - Exception obtaining public IP: %s", str(e))
