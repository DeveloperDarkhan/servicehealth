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
    """
    Checks whether it is possible to resolve a domain name to IP addresses (A records).

    Args:
        domain (str): The domain to resolve.

    Returns:
        tuple: (bool, list) - Success flag and list of IP addresses.

    Logic:
        - Performs a DNS query for A records.
        - On success, returns a list of IPs.
        - In case of NXDOMAIN, NoAnswer, or Timeout, returns False and an empty list.
    """
    try:
        answers = dns.resolver.resolve(domain, "A")
        ip_list = [rdata.address for rdata in answers]
        return True, ip_list
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout):
        return False, []

def is_public_ip(ip):
    """
    Determines whether an IP is public (not private, not loopback, not reserved).

    Args:
        ip (str): The IP address.

    Returns:
        bool: True if public, otherwise False.

    Logic:
        - Analyzes the IP using ipaddress.
        - Returns True only for public addresses.
    """
    ip_obj = ipaddress.ip_address(ip)
    return not (ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_reserved)

def check_ports(ip, ports, timeout=3):
    """
    Checks the availability of specified TCP ports on an IP.

    Args:
        ip (str): The IP address.
        ports (list): Ports to check.
        timeout (int): Connection timeout.

    Returns:
        dict: {port: bool} - True if the port is open, otherwise False.

    Logic:
        - Attempts to establish a TCP connection for each port.
        - Records the result for each port.
    """
    results = {}
    for port in ports:
        try:
            with socket.create_connection((ip, port), timeout=timeout):
                results[port] = True
        except (socket.timeout, socket.error):
            results[port] = False
    return results

def nslookup(domain, logger):
    """
    Performs an nslookup for the domain and logs the result.

    Args:
        domain (str): The domain to check.
        logger (Logger): Logger for recording the result.

    Logic:
        - Runs the nslookup system utility.
        - Extracts and logs IP addresses and the responding server.
        - In case of error, logs the error.
    """
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
    """
    Checks the availability of the TCP port (default 443) for the domain.

    Args:
        domain (str): The domain to check.
        logger (Logger): Logger for recording the result.
        port (int): The port to check.
        timeout (int): Connection timeout.

    Logic:
        - Attempts to connect to the domain on the specified port.
        - Logs the result (open or not).
    """
    try:
        with socket.create_connection((domain, port), timeout=timeout):
            logger.info("[PORT_CHECK] - Port %s/TCP is open for %s", port, domain)
    except Exception as err:
        logger.warning(
            "[PORT_CHECK] - Port %s/TCP is NOT open for %s: %s", port, domain, str(err)
        )


def ssl_check(domain, logger, port=443):
    """
    Checks the validity and expiration date of the SSL certificate for the domain.

    Args:
        domain (str): The domain for which to perform the check.
        logger (Logger): Logger for recording results.
        port (int): The SSL port (default 443).

    Logic:
        - Establishes a secure SSL connection with the server (using certifi for trusted root CAs).
        - Retrieves the server's SSL certificate.
        - Extracts the expiration date of the certificate.
        - Calculates how many days are left until expiration.
        - Logs the result (number of days until expiration).
        - In case of error, logs a warning.
    """
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
    """
    Measures the network latency for the specified URL.

    Args:
        url (str): The resource URL to measure latency.
        logger (Logger): Logger for recording results.
        timeout (int): HTTP request timeout.

    Logic:
        - Records the start time before sending the HTTP request.
        - After receiving the response, calculates the time difference in milliseconds.
        - Logs the result (latency).
        - In case of an error, logs a warning.
    """
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
    Obtains the local IP address of the current device.

    Args:
        logger (Logger): Logger for recording results or errors.

    Returns:
        str: The local IP address (or None if an error occurs).

    Logic:
        - Opens a UDP socket and "connects" to an external address (e.g., Google DNS).
        - Retrieves its local IP used for internet access.
        - Returns the IP if successful, otherwise logs an error.
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
    Retrieves the public (external) IP address of the current device via an external service.

    Args:
        logger (Logger): Logger for recording results or errors.

    Returns:
        str: The public IP address (or None if an error occurs).

    Logic:
        - Performs an HTTP request to https://api.ipify.org?format=json.
        - Extracts the public IP from the response.
        - Returns the IP if successful, otherwise logs an error.
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
    Retrieves and logs both the local (private) and external (public) IP addresses of the machine.

    Args:
        logger (Logger): Logger for recording results.

    Logic:
        - Uses get_local_ip(logger) to get the local IP.
        - Uses get_public_ip(logger) to get the public IP via an external service.
        - Logs both values in a single message to show the current local network and internet-facing addresses.
    """
    private_ip = get_local_ip(logger)
    public_ip = get_public_ip(logger)
    logger.info("[GET_OWN_IP] - Here is your local IP %s and Public IP %s that looks at the Internet", private_ip, public_ip)


def icmp_ping(domain, logger, count=3):
    """
    Performs an ICMP ping to the domain and logs packet loss statistics and round-trip times.

    Args:
        domain (str): The domain to ping.
        logger (Logger): Logger for recording results.
        count (int): Number of ICMP echo requests (default 3).

    Logic:
        - Executes the system ping utility with the specified number of packets.
        - Parses the output: number of sent/received packets, packet loss percentage, round-trip time statistics (min/avg/max/stddev).
        - Logs the transmission and timing statistics.
        - In case of errors (e.g., ICMP forbidden or failure), logs a warning.
    """
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
    """
    Analyzes main timing metrics of an HTTP request: DNS resolution, connection, TTFB, data transfer.

    Args:
        url (str): The URL for diagnostics.
        logger (Logger): Logger for recording results.
        timeout (int): HTTP request timeout.

    Logic:
        - Parses the URL, determines scheme, host, port, path.
        - Measures individual stages: DNS resolution, connection, waiting for the first byte (TTFB), transferring all content.
        - Logs metrics for each stage in milliseconds.
        - In case of an error, logs a warning.
    """
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
    """
    Checks the presence of essential security and caching HTTP headers.

    Args:
        url (str): The URL to check.
        logger (Logger): Logger for recording results.
        timeout (int): HTTP request timeout.

    Logic:
        - Performs a GET request to the URL.
        - Checks for headers: Strict-Transport-Security, Content-Security-Policy, Cache-Control.
        - If any are missing — logs a warning with their list.
        - If all are present — logs an informational message.
        - In case of an error, logs a warning.
    """
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
    """
    Analyzes the chain of HTTP redirects for a given URL and logs their count.

    Args:
        url (str): The URL to analyze.
        logger (Logger): Logger for recording results.
        timeout (int): HTTP request timeout.
        max_redirects (int): Maximum allowed number of redirects (default 3).

    Logic:
        - Performs a GET request allowing redirects.
        - Counts the number of redirects.
        - If more than max_redirects — logs a warning.
        - If within limits — logs an informational message with the count.
        - In case of an error, logs a warning.
    """
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


# --- Diagnostic controllers ---
def run_basic_diagnostics(domain, url, logger, timeout=10):
    """
    Performs basic diagnostic checks for the service.

    Args:
        domain (str): The domain for network and SSL checks.
        url (str): The URL for latency measurement.
        logger (Logger): Logger for recording results.
        timeout (int): Timeout for network operations.

    Logic:
        - Performs nslookup (DNS check).
        - Checks availability of port 443.
        - Checks SSL certificate validity.
        - Measures network latency.
    """
    nslookup(domain, logger)
    port_check(domain, logger)
    ssl_check(domain, logger)
    latency_measure(url, logger, timeout)


def run_full_diagnostics(domain, url, logger, timeout=10):
    """
    Performs a full set of diagnostic checks (basic + extended).

    Args:
        domain (str): The domain for network and SSL checks.
        url (str): The URL for all HTTP diagnostics.
        logger (Logger): Logger for recording results.
        timeout (int): Timeout for network operations.

    Logic:
        - Runs basic checks (run_basic_diagnostics).
        - Additionally:
            - Logs local and external IP addresses.
            - Performs ICMP ping.
            - Analyzes HTTP timings (DNS, connect, TTFB, transfer).
            - Checks important HTTP headers.
            - Analyzes redirect chain.
    """
    run_basic_diagnostics(domain, url, logger, timeout)
    get_own_ip(logger)
    icmp_ping(domain, logger)
    http_timing_metrics(url, logger, timeout)
    http_headers_check(url, logger, timeout)
    redirect_chain_analysis(url, logger, timeout)
