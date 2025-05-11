import socket
import ssl
import subprocess
import time
import re
import certifi
from datetime import datetime
import dns.resolver
import ipaddress
import requests
import http.client
import urllib.parse

# resolvable, ips = check_dns(domain)

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
        output = subprocess.check_output(['nslookup', domain], stderr=subprocess.STDOUT, text=True)
        # Парсинг сервера
        server_match = re.search(r'Server:\s*(.*)', output)
        server = server_match.group(1).strip() if server_match else "unknown"
        # Парсинг всех адресов
        addresses = re.findall(r'Address:\s*([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)', output)
        # Оставляем только уникальные адреса, убираем адрес сервера
        addresses = [addr for addr in addresses if addr != server]
        addresses_str = ', '.join(addresses) if addresses else "none"
        logger.info("[DNS_CHECK] - nslookup result for %s. Addresses: [%s]", domain, addresses_str)
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
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    try:
        output = subprocess.check_output(['ping', '-c', str(count), domain], stderr=subprocess.STDOUT, text=True)
        output_lines = output.strip().splitlines()

        # Парсим статистику пакетов
        stats_line = output_lines[-2]  # Обычно перед последней строкой
        # Пример: '3 packets transmitted, 3 packets received, 0.0% packet loss'
        match_stats = re.search(r'(\d+) packets transmitted, (\d+) packets received, ([\d.]+)% packet loss', stats_line)
        if match_stats:
            transmitted = int(match_stats.group(1))
            received = int(match_stats.group(2))
            packet_loss = match_stats.group(3)
        else:
            transmitted = received = 0
            packet_loss = 'N/A'

        # Парсим статистику времени RTT
        rtt_line = output_lines[-1]  # Последняя строка
        # Пример: 'round-trip min/avg/max/stddev = 109.355/110.760/113.046/1.631 ms'
        match_rtt = re.search(r'=\s*([\d.]+)/([\d.]+)/([\d.]+)/([\d.]+)', rtt_line)
        if match_rtt:
            min_rtt = match_rtt.group(1)
            avg_rtt = match_rtt.group(2)
            max_rtt = match_rtt.group(3)
            stddev_rtt = match_rtt.group(4)
        else:
            min_rtt = avg_rtt = max_rtt = stddev_rtt = 'N/A'

        # Логируем в нужном формате
        logger.info("[ICMP] - Ping statistics: {} packets transmitted, {} packets received, {}% packet loss".format(
            transmitted, received, packet_loss))
        logger.info("[ICMP] - Round-trip time: min/avg/max/stddev = {}/{}/{}/{} ms".format(
            min_rtt, avg_rtt, max_rtt, stddev_rtt))
    except Exception as e:
        logger.warning("[ICMP] - Ping failed or forbidden for %s", domain)

def http_timing_metrics(url, logger, timeout=10):
    try:
        parsed = urllib.parse.urlparse(url)
        host = parsed.hostname
        port = parsed.port or (443 if parsed.scheme == 'https' else 80)
        path = parsed.path or '/'
        # Выбираем класс соединения
        conn_cls = http.client.HTTPSConnection if parsed.scheme == 'https' else http.client.HTTPConnection

        # Создаем контекст SSL с сертификатами certifi
        ssl_context = ssl.create_default_context(cafile=certifi.where())

        t_dns = t_connect = t_req = t_resp = 0
        t0 = time.time()

        if parsed.scheme == 'https':
            # Передаем ssl_context при создании соединения
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