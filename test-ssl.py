
import ssl
import socket
import certifi
from datetime import datetime

def get_ssl_expiry_date(hostname="sre-test-assignment.innervate.tech"):
    context = ssl.create_default_context(cafile=certifi.where())
    with socket.create_connection((hostname, 443)) as sock:
        with context.wrap_socket(sock, server_hostname=hostname) as ssock:
            cert = ssock.getpeercert()
            expiry_str = cert['notAfter']
            expiry_date = datetime.strptime(expiry_str, '%b %d %H:%M:%S %Y GMT')
            return expiry_date

domain = 'example.com'
expiry_date = get_ssl_expiry_date(domain)
print(f"SSL сертификат для {domain} истекает: {expiry_date}")
