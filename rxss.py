import requests
from qsreplace import qsreplace

class Rxss:

  def __init__(self, hosts="crawled.txt", payload="Rxss", ignore_base_url=False, follow_redirects=False, max_redirects=5):
    self.hosts = hosts
    self.payload = payload
    self.ignore_base_url = ignore_base_url
    self.session = requests.Session()
    
    if not follow_redirects:
      self.session.allow_redirects = False
    else:
      self.session.max_redirects = max_redirects
  
  def _gen_tampered_urls(self):
    with open(self.hosts, "r") as f:
      url_lst = f.read().splitlines()

    payload_lst = [self.payload]
    
    if self.ignore_base_url:
      tampered_urls = qsreplace(url_lst, payload_lst, edit_base_url=False)
    else:
      tampered_urls = qsreplace(url_lst, payload_lst, edit_base_url=True)

    return tampered_urls

  def check_reflection(self, url, userAgent="Mozilla/5.0 (Macintosh; Intel Mac OS X 14.5; rv:127.0) Gecko/20100101 Firefox/127.0"):
    header = {"Accept": "*/*", "User-Agent": userAgent}
    self.session.headers.update(header)
    try:
      response = self.session.get(url)
    except requests.exceptions.TooManyRedirects:
      message = f"[Vulnerable] [{url}] [Infinite Redirect Loop]"
    except Exception as err:
      error = f"[Error] [{url}] [{str(err)}]"

    print(response.text)
    if response:
      if self.payload in response.text:
        print(url)
