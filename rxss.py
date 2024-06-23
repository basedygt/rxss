import requests
import urllib3
import concurrent.futures
from qsreplace import qsreplace

class Rxss:
    def __init__(self, hosts="hosts.txt", payload="rxss", output=False, ignore_base_url=False, follow_redirects=False, max_redirects=5):
        self.hosts = hosts
        self.output = output
        self.payload = payload
        self.ignore_base_url = ignore_base_url
        self.session = requests.Session()
        
        self.session.verify = False
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        
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
            vuln = f"[Vulnerable] [{url}] [Possible Infinite Redirect Loop]"
            print(vuln)
            return
        except requests.exceptions.RequestException as err:
            error = f"[Error] [{url}] [{str(err)}]"
            print(error)
            return

        if self.payload in response.text:
            print(url)
            if self.output:
                with open(self.output, "a") as f:
                    f.write(url + "\n")

    def check_reflections_threaded(self, max_threads=50):
        tampered_urls = self._gen_tampered_urls()
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_threads) as executor:
            futures = []
            for tampered_url in tampered_urls:
                futures.append(executor.submit(self.check_reflection, tampered_url))

            for future in concurrent.futures.as_completed(futures):
                try:
                    future.result()
                except Exception as e:
                    print(f"Error occurred: {str(e)}")

    def cli(self):
        import argparse
        parser = argparse.ArgumentParser(description="Check reflecting params and paths in a bunch of URLs")
        parser.add_argument("-i", "--hosts", metavar="", type=str, help="Path containing a list of URLs to scan")
        parser.add_argument("-p", "--payload", metavar="", type=str, default="rxss", help="Payload you want to send to check reflection (default rxss)")
        parser.add_argument("-o", "--output", metavar="", type=str, help="Path of file to write output to")
        parser.add_argument("-t", "--threads", metavar="", type=int, help="number of threads to use (default 50)")
        parser.add_argument("--timeout", metavar="", type=int, help="timeout in seconds (default 10)")
        parser.add_argument("--ignore-base-url", action="store_true", help="Disable appending payloads to paths in base URLs")
        parser.add_argument("-fr", "--follow-redirects", action="store_true", help="Follow http redirects")
        parser.add_argument("-maxr", "--max-redirects", metavar="", type=int, default=5, help="max number of redirects to follow per host (default 5)")
        args = parser.parse_args()

        return args

# Example usage:
if __name__ == "__main__":
    rxss = Rxss()
    rxss.check_reflections_threaded()
