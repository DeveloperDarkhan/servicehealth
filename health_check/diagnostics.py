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
    Проверяет, возможно ли разрешить доменное имя в IP-адреса (A-записи).

    Args:
        domain (str): Домен для разрешения.

    Returns:
        tuple: (bool, list) - Флаг успешного разрешения и список IP-адресов.

    Логика:
        - Выполняет DNS-запрос на A-записи.
        - При успехе возвращает список IP.
        - В случае NXDOMAIN, NoAnswer или Timeout возвращает False и пустой список.
    """
    try:
        answers = dns.resolver.resolve(domain, "A")
        ip_list = [rdata.address for rdata in answers]
        return True, ip_list
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout):
        return False, []


def is_public_ip(ip):
    """
    Определяет, является ли IP публичным (не частным, не loopback, не зарезервированным).

    Args:
        ip (str): IP-адрес.

    Returns:
        bool: True если публичный, иначе False.

    Логика:
        - Анализирует IP через ipaddress.
        - Возвращает True только для публичных адресов.
    """
    ip_obj = ipaddress.ip_address(ip)
    return not (ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_reserved)


def check_ports(ip, ports, timeout=3):
    """
    Проверяет доступность указанных TCP-портов на IP.

    Args:
        ip (str): IP-адрес.
        ports (list): Порты для проверки.
        timeout (int): Таймаут попытки подключения.

    Returns:
        dict: {порт: bool} - True если порт открыт, иначе False.

    Логика:
        - Для каждого порта пытается установить TCP-соединение.
        - Фиксирует результат для каждого порта.
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
    Выполняет nslookup для домена и логирует результат.

    Args:
        domain (str): Домен для проверки.
        logger (Logger): Логгер для записи результата.

    Логика:
        - Запускает системную утилиту nslookup.
        - Извлекает и логирует IP-адреса и сервер, который ответил.
        - В случае ошибки пишет ошибку в лог.
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
    Проверяет доступность TCP-порта (по умолчанию 443) для домена.

    Args:
        domain (str): Домен для проверки.
        logger (Logger): Логгер для записи результата.
        port (int): Порт для проверки.
        timeout (int): Таймаут подключения.

    Логика:
        - Пытается подключиться к домену по указанному порту.
        - Логирует результат (открыт или нет).
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
    Проверяет срок действия и валидность SSL-сертификата для домена.

    Args:
        domain (str): Домен, для которого проводится проверка.
        logger (Logger): Логгер для записи результатов.
        port (int): Порт для SSL (по умолчанию 443).

    Логика:
        - Устанавливает защищённое SSL-соединение с сервером (используя certifi для доверия корневым CA).
        - Получает SSL-сертификат сервера.
        - Извлекает дату окончания действия сертификата.
        - Вычисляет, сколько дней осталось до истечения срока действия.
        - Логирует результат (количество дней до окончания).
        - В случае ошибки логирует предупреждение.
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
    Измеряет сетевую задержку (latency) для указанного URL.

    Args:
        url (str): URL ресурса для измерения задержки.
        logger (Logger): Логгер для записи результатов.
        timeout (int): Таймаут HTTP-запроса.

    Логика:
        - Засекает время перед отправкой HTTP-запроса.
        - После получения ответа считает разницу времени в миллисекундах.
        - Логирует результат (latency).
        - В случае ошибки логирует предупреждение.
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
    Получает локальный IP-адрес текущего устройства.

    Args:
        logger (Logger): Логгер для фиксации результата или ошибок.

    Returns:
        str: Локальный IP-адрес (или None при ошибке).

    Логика:
        - Открывает UDP-сокет и "подключается" к внешнему адресу (например, Google DNS).
        - Получает свой локальный IP, используемый для выхода в интернет.
        - В случае успеха возвращает IP, иначе логирует ошибку.
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
    Получает публичный (внешний) IP-адрес текущего устройства через внешний сервис.

    Args:
        logger (Logger): Логгер для фиксации результата или ошибок.

    Returns:
        str: Публичный IP-адрес (или None при ошибке).

    Логика:
        - Выполняет HTTP-запрос к сервису https://api.ipify.org?format=json.
        - Извлекает публичный IP из ответа.
        - В случае успеха возвращает IP, иначе логирует ошибку.
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
    Получает и логирует локальный (private) и внешний (public) IP-адреса машины.

    Args:
        logger (Logger): Логгер для фиксации результата.

    Логика:
        - Использует get_local_ip(logger) для получения локального IP.
        - Использует get_public_ip(logger) для получения публичного IP через внешний сервис.
        - Логирует оба значения в едином сообщении, чтобы показать текущий адрес для локальной сети и для выхода в интернет.
    """
    private_ip = get_local_ip(logger)
    public_ip = get_public_ip(logger)
    logger.info("[GET_OWN_IP] - Here is your local IP %s and Public IP %s that looks at the Internet", private_ip, public_ip)

def icmp_ping(domain, logger, count=3):
    """
    Выполняет ICMP ping домена и логирует статистику потерь пакетов и времени отклика.

    Args:
        domain (str): Домен для пинга.
        logger (Logger): Логгер для записи результатов.
        count (int): Количество ICMP-эха запросов (по умолчанию 3).

    Логика:
        - Запускает системную утилиту ping с указанным числом пакетов.
        - Парсит вывод: количество отправленных/полученных пакетов, процент потерь, статистику времени (min/avg/max/stddev).
        - Логирует статистику передачи и времени.
        - В случае ошибки (например, запрет ICMP или сбой) логирует предупреждение.
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
    Анализирует основные тайминги HTTP-запроса: DNS, соединение, TTFB, передача данных.

    Args:
        url (str): URL для диагностики.
        logger (Logger): Логгер для записи результатов.
        timeout (int): Таймаут HTTP-запроса.

    Логика:
        - Парсит URL, определяет схему, хост, порт, путь.
        - Измеряет отдельные этапы: разрешение DNS, соединение, ожидание первого байта (TTFB), передачу всего содержимого.
        - Логирует метрики по каждому этапу в миллисекундах.
        - В случае ошибки логирует предупреждение.
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
    Проверяет наличие обязательных HTTP-заголовков безопасности и кеширования.

    Args:
        url (str): URL для проверки.
        logger (Logger): Логгер для записи результатов.
        timeout (int): Таймаут HTTP-запроса.

    Логика:
        - Выполняет GET-запрос к URL.
        - Проверяет наличие заголовков: Strict-Transport-Security, Content-Security-Policy, Cache-Control.
        - Если какие-то отсутствуют — пишет предупреждение с их списком.
        - Если все есть — пишет информационное сообщение.
        - В случае ошибки логирует предупреждение.
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
    Анализирует цепочку HTTP-редиректов для заданного URL и логирует их количество.

    Args:
        url (str): URL, для которого проводится анализ.
        logger (Logger): Логгер для записи результатов.
        timeout (int): Таймаут HTTP-запроса.
        max_redirects (int): Максимально допустимое число редиректов (по умолчанию 3).

    Логика:
        - Выполняет GET-запрос с разрешёнными редиректами.
        - Считает количество перенаправлений (redirects).
        - Если их больше max_redirects — логирует предупреждение.
        - Если в пределах нормы — логирует информационное сообщение с количеством.
        - В случае ошибки логирует предупреждение.
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


# --- Диагностические контроллеры ---


def run_basic_diagnostics(domain, url, logger, timeout=10):
    """
    Выполняет базовые диагностические проверки для сервиса.

    Args:
        domain (str): Домен для сетевых и SSL-проверок.
        url (str): URL для проверки задержки.
        logger (Logger): Логгер для записи результатов.
        timeout (int): Таймаут для сетевых операций.

    Логика:
        - Делает nslookup (проверка DNS).
        - Проверяет доступность порта 443.
        - Проверяет срок действия SSL-сертификата.
        - Измеряет сетевую задержку (latency).
    """
    nslookup(domain, logger)
    port_check(domain, logger)
    ssl_check(domain, logger)
    latency_measure(url, logger, timeout)


def run_full_diagnostics(domain, url, logger, timeout=10):
    """
    Выполняет полный набор диагностических проверок (базовые + расширенные).

    Args:
        domain (str): Домен для сетевых и SSL-проверок.
        url (str): URL для всех HTTP-диагностик.
        logger (Logger): Логгер для записи результатов.
        timeout (int): Таймаут для сетевых операций.

    Логика:
        - Запускает базовые проверки (run_basic_diagnostics).
        - Дополнительно:
            - Логирует локальный и внешний IP.
            - Выполняет ICMP ping.
            - Анализирует HTTP-тайминги (DNS, connect, TTFB, transfer).
            - Проверяет важные HTTP-заголовки.
            - Анализирует цепочку редиректов.
    """
    run_basic_diagnostics(domain, url, logger, timeout)
    get_own_ip(logger)
    icmp_ping(domain, logger)
    http_timing_metrics(url, logger, timeout)
    http_headers_check(url, logger, timeout)
    redirect_chain_analysis(url, logger, timeout)
