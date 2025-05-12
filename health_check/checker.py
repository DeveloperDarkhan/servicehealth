import requests
from bs4 import BeautifulSoup
import re
import dns.resolver
import ipaddress
import socket

from datetime import datetime


def verify_dns(domain, logger, ports=[80, 443]):
    """
    Комплексная проверка DNS и доступности IP-адресов домена по портам (по умолчанию 80 и 443).

    Args:
        domain (str): Доменное имя для проверки.
        logger (Logger): Объект логгера для записи событий.
        ports (list): Список портов для проверки (по умолчанию [80, 443]).

    Логика:
        1. Проверяет возможность разрешения домена в IP (стандартные DNS, затем публичные).
        2. Если не удалось разрешить, пишет ошибку в лог.
        3. Если IP-адреса найдены — проверяет доступность по портам.
        4. Если хотя бы для одного IP порт 443 доступен — возвращает True.
        5. Если порт 443 не открыт ни для одного IP — пишет ошибку в лог.
    """
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
    """
    Проверяет, можно ли разрешить домен в IP-адреса.

    Args:
        domain (str): Доменное имя.
        customnameservers (bool): Использовать публичные DNS (True) или стандартные (False).

    Returns:
        tuple: (resolvable (bool), спискок IP (list))

    Логика:
        1. Получает A-записи домена.
        2. При customnameservers=True использует публичные DNS.
        3. При успехе возвращает (True, список IP), иначе (False, []).
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
    Определяет, является ли IP-адрес публичным.

    Args:
        ip (str): IP-адрес.

    Returns:
        bool: True если IP публичный, иначе False.

    Логика:
        - Преобразует строку в объект ipaddress.
        - Проверяет, не является ли адрес приватным, loopback или зарезервированным.
    """
    ip_obj = ipaddress.ip_address(ip)
    return not (ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_reserved)


def check_ports(ip, ports, timeout=2):
    """
    Проверяет доступность указанных портов на данном IP-адресе.

    Args:
        ip (str): IP-адрес.
        ports (list): Список портов для проверки.
        timeout (int): Таймаут подключения в секундах (по умолчанию 2).

    Returns:
        dict: Словарь {порт: bool}, где True — порт доступен, False — порт недоступен.

    Логика:
        - Для каждого порта из списка пытается установить TCP-соединение.
        - Если соединение прошло успешно — порт считается доступным.
        - В случае ошибки или таймаута — порт считается недоступным.
        - Возвращает словарь с результатами проверки по каждому порту.
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
    Проверяет, доступен ли указанный URL и содержит ли ответ ключевое слово.

    Args:
        domain (str): Домен (не используется явно, но может быть полезен для логирования).
        url (str): URL для проверки.
        keyword (str): Ключевое слово для поиска в ответе.
        timeout (int): Таймаут запроса в секундах.
        logger (Logger): Объект логгера для записи событий.

    Returns:
        bool: True, если код ответа 200 и ключевое слово найдено в теле ответа. Иначе False.

    Логика:
        - Выполняет HTTP GET-запрос по заданному URL.
        - Если код ответа 200, извлекает текст из HTML, ищет ключевое слово (регистронезависимо).
        - Если найдено — пишет положительный результат в консоль, возвращает True.
        - Если не найдено — фиксирует ошибку в лог, возвращает False.
        - Если не 200 — пишет ошибку в лог, возвращает False.
        - В случае ошибки запроса — логирует её как ошибку.
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
