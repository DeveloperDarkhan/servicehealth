import requests
from bs4 import BeautifulSoup
import re
from datetime import datetime

def check_http(url, keyword, timeout, logger):
    try:
        resp = requests.get(url, timeout=timeout)
        if resp.status_code == 200:
            soup = BeautifulSoup(resp.text, 'html.parser')
            text = soup.get_text(separator=' ', strip=True)
            pattern = r'\b' + re.escape(keyword) + r'\b'
            if re.search(pattern, text, re.IGNORECASE):
                now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                print(f'[{now}] [INFO] [HTTP_CHECK] - Status code is 200 and response body contains a keyword "{keyword}"')
                return True
            else:
                # if logger:
                logger.error('[HTTP_CHECK] - Status code 200 but keyword "%s" not found in response text', keyword)
                return False
        else:
            # if logger:
            logger.error('[HTTP_CHECK] - Status code %d received', resp.status_code)
            return False
    except Exception as e:
        # if logger:
        logger.error('[HTTP_CHECK] - Exception: %s', str(e))
        # return False
