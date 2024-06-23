# Rxss

RXSS is a Python tool designed for detecting reflecting params and paths in a bunch of URLs which can lead to reflected Cross-Site Scripting (XSS) vulnerabilities. It utilizes multithreading and customizable payload injection.

## Installation

Install RXSS from PyPI using pip:

```bash
pip install rxss
```

## Usage

### Command-Line Options

```
usage: rxss [-h] [-i] [-p] [-o] [-t] [-fr] [-maxr] [--timeout] [--ignore-base-url]

optional arguments:
  -h, --help            show this help message and exit
  -i , --urls           Path containing a list of URLs to scan
  -p , --payload        Payload you want to send to check reflection (default: rxss)
  -o , --output         Path of file to write output to (default: None)
  -t , --threads        Number of threads to use (default: 50)
  -fr, --follow-redirects
                        Follow HTTP redirects (default: False)
  -maxr , --max-redirects
                        Max number of redirects to follow per host (default: 5)
  --timeout             Timeout in seconds (default: 10)
  --ignore-base-url     Disable appending payloads to paths in base URLs (default: False)
```

### Examples

Scan URLs from a file `hosts.txt` with default settings:

```bash
rxss -i hosts.txt
```

Scan URLs with a custom payload and output results to `output.txt`:

```bash
rxss -i hosts.txt -p "<script>alert('XSS')</script>" -o output.txt
```

## Acknowledgments

- Built with [Python](https://www.python.org/)
- Utilizes [Requests](https://docs.python-requests.org/en/master/) for HTTP requests
- [qsreplace](https://github.com/basedygt/qsreplace) for query string manipulation
