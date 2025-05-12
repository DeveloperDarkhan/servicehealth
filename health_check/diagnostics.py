import re
import ssl
import time
import socket
import certifi
import ipaddress
import requests
import http.client
import subprocess
import urllib.parse
import dns.resolver

from datetime import datetime


def check_dns(domain):
    try:
        answers = dns.resolver.resolve(domain, "A")
        ip_list = [rdata.address for rdata in answers]
        return True, ip_list
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout):
        return False, []


def is_public_ip(ip):
    ip_obj = ipaddress.ip_address(ip)
    return not (ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_reserved)


def check_ports(ip, ports, timeout=3):
    results = {}
    for port in ports:
        try:
            with socket.create_connection((ip, port), timeout=timeout):
                results[port] = True
        except (socket.timeout, socket.error):
            results[port] = False
    return results


def nslookup(domain, logger):
    try:
        output = subprocess.check_output(
            ["nslookup", domain], stderr=subprocess.STDOUT, text=True
        )
        server_match = re.search(r"Server:\s*(.*)", output)
        server = server_match.group(1).strip() if server_match else "unknown"
        addresses = re.findall(r"Address:\s*([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)", output)
        addresses = [addr for addr in addresses if addr != server]
        addresses_str = ", ".join(addresses) if addresses else "none"
        logger.info(
            "[DNS_CHECK] - nslookup result for %s. Addresses: [%s]",
            domain,
            addresses_str,
        )
    except Exception as err:
        logger.error("[DNS_CHECK] - nslookup failed: %s", str(err))


def port_check(domain, logger, port=443, timeout=5):
    try:
        with socket.create_connection((domain, port), timeout=timeout):
            logger.info("[PORT_CHECK] - Port %s/TCP is open for %s", port, domain)
    except Exception as err:
        logger.warning(
            "[PORT_CHECK] - Port %s/TCP is NOT open for %s: %s", port, domain, str(err)
        )


def ssl_check(domain, logger, port=443):
    try:
        context = ssl.create_default_context(cafile=certifi.where())
        with socket.create_connection((domain, port)) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                expire_date = datetime.strptime(
                    cert["notAfter"], "%b %d %H:%M:%S %Y %Z"
                )
                days_left = (expire_date - datetime.utcnow()).days
            logger.info(
                "[SSL_CHECK] - Certificate expires in %d days for %s", days_left, domain
            )
    except Exception as err:
        logger.warning(
            "[SSL_CHECK] - Certificate check failed for %s: %s", domain, str(err)
        )


def latency_measure(url, logger, timeout=10):
    start = time.time()
    try:
        requests.get(url, timeout=timeout)
        latency = int((time.time() - start) * 1000)
        logger.info("[LATENCY] - Latency for %s: %dms", url, latency)
    except Exception as err:
        logger.warning(
            "[LATENCY] - Failed to measure latency for %s: %s", url, str(err)
        )


def get_local_ip(logger):
    """
    Get local IP address
    """
    try:
        # Connect to an external host; doesn't have to be reachable
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
        # logger.info("[OWN_IP] - Local IP Address: %s", local_ip)
        return local_ip
    except Exception as e:
        logger.error("[OWN_IP] - Exception obtaining local IP: %s", str(e))



def get_public_ip(logger):
    """
    Get public IP address
    """
    try:
        response = requests.get("https://api.ipify.org?format=json")
        response.raise_for_status()
        public_ip = response.json()["ip"]
        # logger.info("[OWN_IP] - Public IP Address: %s", public_ip)
        return public_ip
    except Exception as e:
        logger.error("[OWN_IP] - Exception obtaining public IP: %s", str(e))


def get_own_ip(logger):
    """
    Get you local address and NAT public address
    """
    private_ip = get_local_ip(logger)
    public_ip = get_public_ip(logger)
    logger.info("[GET_OWN_IP] - Here is your local IP %s and Public IP %s that looks at the Internet", private_ip, public_ip)

def icmp_ping(domain, logger, count=3):
    try:
        output = subprocess.check_output(
            ["ping", "-c", str(count), domain], stderr=subprocess.STDOUT, text=True
        )
        output_lines = output.strip().splitlines()

        # Parse packet statistics line
        stats_line = output_lines[-2]
        match_stats = re.search(
            r"(\d+) packets transmitted, (\d+) packets received, ([\d.]+)% packet loss",
            stats_line,
        )
        if match_stats:
            transmitted = int(match_stats.group(1))
            received = int(match_stats.group(2))
            packet_loss = match_stats.group(3)
        else:
            transmitted = received = 0
            packet_loss = "N/A"

        # Parse RTT statistics line
        rtt_line = output_lines[-1]
        match_rtt = re.search(r"=\s*([\d.]+)/([\d.]+)/([\d.]+)/([\d.]+)", rtt_line)
        if match_rtt:
            min_rtt = match_rtt.group(1)
            avg_rtt = match_rtt.group(2)
            max_rtt = match_rtt.group(3)
            stddev_rtt = match_rtt.group(4)
        else:
            min_rtt = avg_rtt = max_rtt = stddev_rtt = "N/A"

        logger.info(
            "[ICMP] - Ping statistics: %d packets transmitted, %d packets received, %s%% packet loss",
            transmitted,
            received,
            packet_loss,
        )
        logger.info(
            "[ICMP] - Round-trip time: min/avg/max/stddev = %s/%s/%s/%s ms",
            min_rtt,
            avg_rtt,
            max_rtt,
            stddev_rtt,
        )
    except Exception as err:
        logger.warning("[ICMP] - Ping failed or forbidden for %s: %s", domain, str(err))


def http_timing_metrics(url, logger, timeout=10):
    try:
        parsed = urllib.parse.urlparse(url)
        host = parsed.hostname
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        path = parsed.path or "/"
        conn_cls = (
            http.client.HTTPSConnection
            if parsed.scheme == "https"
            else http.client.HTTPConnection
        )
        ssl_context = ssl.create_default_context(cafile=certifi.where())
        t0 = time.time()

        if parsed.scheme == "https":
            conn = conn_cls(host, port, timeout=timeout, context=ssl_context)
        else:
            conn = conn_cls(host, port, timeout=timeout)

        t1 = time.time()
        conn.connect()
        t2 = time.time()
        conn.request("GET", path)
        t3 = time.time()
        resp = conn.getresponse()
        t4 = time.time()
        resp.read()
        t5 = time.time()

        logger.info(
            "[HTTP_TIMING] - DNS: %dms, Connect: %dms, TTFB: %dms, Transfer: %dms",
            int((t1 - t0) * 1000),
            int((t2 - t1) * 1000),
            int((t4 - t3) * 1000),
            int((t5 - t4) * 1000),
        )
    except Exception as err:
        logger.warning(
            "[HTTP_TIMING] - Failed to get timing metrics for %s: %s", url, str(err)
        )


def http_headers_check(url, logger, timeout=10):
    try:
        response = requests.get(url, timeout=timeout)
        headers = response.headers
        issues = []
        if "Strict-Transport-Security" not in headers:
            issues.append("Missing HSTS")
        if "Content-Security-Policy" not in headers:
            issues.append("Missing CSP")
        if "Cache-Control" not in headers:
            issues.append("Missing cache control")
        if issues:
            logger.warning("[HEADERS] - Headers issues: %s", ", ".join(issues))
        else:
            logger.info("[HEADERS] - All required headers present.")
    except Exception as err:
        logger.warning("[HEADERS] - Failed to check headers for %s: %s", url, str(err))


def redirect_chain_analysis(url, logger, timeout=10, max_redirects=3):
    try:
        session = requests.Session()
        response = session.get(url, timeout=timeout, allow_redirects=True)
        redirects = response.history
        if len(redirects) > max_redirects:
            logger.warning(
                "[REDIRECTS] - %d redirects detected (max allowed: %d)",
                len(redirects),
                max_redirects,
            )
        else:
            logger.info("[REDIRECTS] - %d redirects in chain", len(redirects))
    except Exception as err:
        logger.warning(
            "[REDIRECTS] - Failed to analyze redirect chain for %s: %s", url, str(err)
        )


# --- Диагностические контроллеры ---


def run_basic_diagnostics(domain, url, logger, timeout=10):
    nslookup(domain, logger)
    port_check(domain, logger)
    ssl_check(domain, logger)
    latency_measure(url, logger, timeout)


def run_full_diagnostics(domain, url, logger, timeout=10):
    run_basic_diagnostics(domain, url, logger, timeout)
    get_own_ip(logger)
    icmp_ping(domain, logger)
    http_timing_metrics(url, logger, timeout)
    http_headers_check(url, logger, timeout)
    redirect_chain_analysis(url, logger, timeout)
