import socket
import ssl
import subprocess
import time
import re
import certifi
from datetime import datetime
import requests
import http.client
import urllib.parse

def nslookup(domain, logger):
    try:
        output = subprocess.check_output(['nslookup', domain], stderr=subprocess.STDOUT, text=True)
        # Парсинг сервера
        server_match = re.search(r'Server:\s*(.*)', output)
        server = server_match.group(1).strip() if server_match else "unknown"
        # Парсинг всех адресов
        addresses = re.findall(r'Address:\s*([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)', output)
        # Оставляем только уникальные адреса, убираем адрес сервера
        addresses = [addr for addr in addresses if addr != server]
        addresses_str = ', '.join(addresses) if addresses else "none"
        logger.info("[DNS_CHECK] - nslookup result for %s: - Server [%s], Addresses: [%s]", domain, server, addresses_str)
    except Exception as e:
        logger.error("[DNS_CHECK] - nslookup failed: %s", str(e))

def port_check(domain, logger, port=443, timeout=5):
    try:
        with socket.create_connection((domain, port), timeout=timeout):
            logger.info("[PORT_CHECK] - Port %s/TCP is open for %s", port, domain)
    except Exception as e:
        logger.warning("[PORT_CHECK] - Port %s/TCP is NOT open for %s: %s", port, domain, str(e))

def ssl_check(domain, logger, port=443):
    try:
        context = ssl.create_default_context(cafile=certifi.where())
        with socket.create_connection((domain, port)) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                expire_date = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                days_left = (expire_date - datetime.utcnow()).days
            logger.info("[SSL_CHECK] - Certificate expires in %d days for %s", days_left, domain)
    except Exception as e:
        logger.warning("[SSL_CHECK] - Certificate check failed for %s: %s", domain, str(e))

def latency_measure(url, logger, timeout=10):
    start = time.time()
    try:
        r = requests.get(url, timeout=timeout)
        latency = int((time.time() - start) * 1000)
        logger.info("[LATENCY] - Latency for %s: %dms", url, latency)
    except Exception as e:
        logger.warning("[LATENCY] - Failed to measure latency for %s: %s", url, str(e))

# --- Расширенные проверки ---
def icmp_ping(domain, logger, count=3):
    try:
        output = subprocess.check_output(['ping', '-c', str(count), domain], stderr=subprocess.STDOUT, text=True)
        logger.info("[ICMP] - Ping result for %s:\n%s", domain, output.strip())
    except Exception as e:
        logger.warning("[ICMP] - Ping failed for %s: %s", domain, str(e))

def http_timing_metrics(url, logger, timeout=10):
    try:
        parsed = urllib.parse.urlparse(url)
        host = parsed.hostname
        port = parsed.port or (443 if parsed.scheme == 'https' else 80)
        path = parsed.path or '/'
        conn_cls = http.client.HTTPSConnection if parsed.scheme == 'https' else http.client.HTTPConnection

        t_dns = t_connect = t_req = t_resp = 0
        t0 = time.time()
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
        logger.info("[HTTP_TIMING] - DNS: %dms, Connect: %dms, TTFB: %dms, Transfer: %dms",
            int((t1-t0)*1000), int((t2-t1)*1000), int((t4-t3)*1000), int((t5-t4)*1000)
        )
    except Exception as e:
        logger.warning("[HTTP_TIMING] - Failed to get timing metrics for %s: %s", url, str(e))

def http_headers_check(url, logger, timeout=10):
    try:
        r = requests.get(url, timeout=timeout)
        headers = r.headers
        issues = []
        if 'Strict-Transport-Security' not in headers:
            issues.append("Missing HSTS")
        if 'Content-Security-Policy' not in headers:
            issues.append("Missing CSP")
        if 'Cache-Control' not in headers:
            issues.append("Missing cache control")
        if issues:
            logger.warning("[HEADERS] - Headers issues: %s", ", ".join(issues))
        else:
            logger.info("[HEADERS] - All required headers present.")
    except Exception as e:
        logger.warning("[HEADERS] - Failed to check headers for %s: %s", url, str(e))

def redirect_chain_analysis(url, logger, timeout=10, max_redirects=3):
    try:
        session = requests.Session()
        resp = session.get(url, timeout=timeout, allow_redirects=True)
        redirects = resp.history
        if len(redirects) > max_redirects:
            logger.warning("[REDIRECTS] - %d redirects detected (max allowed: %d)", len(redirects), max_redirects)
        else:
            logger.info("[REDIRECTS] - %d redirects in chain", len(redirects))
    except Exception as e:
        logger.warning("[REDIRECTS] - Failed to analyze redirect chain for %s: %s", url, str(e))


def geolocation_test(url, logger):
    # MVP: просто логируем, что тест выполнен.
    try:
        logger.info("[GEOLOCATION] - Geolocation test simulated for %s (implement real test in production)", url)
    except Exception as e:
        logger.warning("[GEOLOCATION] - Failed to run geolocation test for %s: %s", url, str(e))


# --- Контроллеры диагностики ---

def run_basic_diagnostics(domain, url, logger, timeout=10):
    nslookup(domain, logger)
    port_check(domain, logger)
    ssl_check(domain, logger)
    latency_measure(url, logger, timeout)


def run_full_diagnostics(domain, url, logger, timeout=10):
    run_basic_diagnostics(domain, url, logger, timeout)
    icmp_ping(domain, logger)
    http_timing_metrics(url, logger, timeout)
    http_headers_check(url, logger, timeout)
    redirect_chain_analysis(url, logger, timeout)
    geolocation_test(url, logger)
