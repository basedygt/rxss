import requests
from qsreplace import qsreplace

class Rxss:

  def __init__(self, hosts, payload, ignore_base_url):
    self.hosts = hosts
    self.payload = payload
    self.ignore_base_url = ignore_base_url
    
  def _gen_tampered_urls(self):
    with open(self.hosts, "r") as f:
      url_lst = f.read().splitlines()

    if self.ignore_base_url:
      tampered_urls = qsreplace(url_lst, self.payload, edit_base_url=False)
    else:
      tampered_urls = qsreplace(url_lst, self.payload, edit_base_url=True)
