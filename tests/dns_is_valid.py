import dns.resolver
import ipaddress
import socket

def check_dns(hostname):
    try:
        answers = dns.resolver.resolve(hostname, 'A')
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

def check_port(ip, port, timeout=3):
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except (socket.timeout, socket.error):
        return False

# Основной блок
hostname = "git.payboxz.money"
resolvable, ips = check_dns(hostname)

if resolvable:
    print(f"{hostname} существует, IP-адреса: {ips}")
    for ip in ips:
        if is_public_ip(ip):
            print(f"{ip} — публичный IP")
        else:
            print(f"{ip} — приватный или зарезервированный IP")
        
        # Проверка доступности по порту 80 (HTTP)
        if check_port(ip, 80):
            print(f"Доступ к {ip}:80 (HTTP) есть")
        else:
            print(f"Доступ к {ip}:80 (HTTP) отсутствует")
        
        # Проверка доступности по порту 443 (HTTPS)
        if check_port(ip, 443):
            print(f"Доступ к {ip}:443 (HTTPS) есть")
        else:
            print(f"Доступ к {ip}:443 (HTTPS) отсутствует")
else:
    print(f"{hostname} не существует или не отвечает")
