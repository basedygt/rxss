import requests
from qsreplace import qsreplace

class Rxss:

  def __init__(self, hosts, payload=["Rxss"], ignore_base_url=False, follow_redirects=False, max_redirects=5):
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

    if self.ignore_base_url:
      tampered_urls = qsreplace(url_lst, self.payload, edit_base_url=False)
    else:
      tampered_urls = qsreplace(url_lst, self.payload, edit_base_url=True)

    return tampered_urls

  def check_reflection(self, url, userAgent:
    header = {"Accept": "*/*", "User-Agent": userAgent}
    self.session.headers.update(header)
