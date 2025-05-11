import requests
from bs4 import BeautifulSoup  # добавь этот импорт
from datetime import datetime


def check_http(url, keyword, timeout, logger):
    try:
        resp = requests.get(url, timeout=timeout)
        if resp.status_code == 200:
            # Парсим HTML и ищем ключевое слово в видимом тексте
            soup = BeautifulSoup(resp.text, 'html.parser')
            text = soup.get_text(separator=' ', strip=True)
            if keyword.lower() in text.lower():
                now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                print(f'[{now}] [INFO] [HTTP_CHECK] - Status code is 200 and response body contains a keyword "{keyword}"')
                return True
            else:
                logger.error('[HTTP_CHECK] - Status code 200 but keyword "%s" not found in response text', keyword)
                return False
        else:
            logger.error('[HTTP_CHECK] - Status code %d received', resp.status_code)
            return False
    except Exception as e:
        logger.error('[HTTP_CHECK] - Exception: %s', str(e))
        return False
