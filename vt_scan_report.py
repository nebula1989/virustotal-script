from virustotal_python import Virustotal
from pprint import pprint
import time
import json
import urllib.request
import urllib.parse
import hashlib
import re
import os

with open("vt_api.txt", "r") as f:
    api_key = f.readlines()
vtotal = Virustotal(api_key)  # virustotal API key


def main():
    print("Welcome.  Input 1 or more urls: ")
    url = input()
    vt_scan(url)
    vt_report(url)


def vt_scan(url):
    result = vtotal.url_scan(
        [url]
    )
    pprint(result)


def vt_report(url):
    result = vtotal.url_report(
        [url]
    )

    pprint(result)


if __name__ == '__main__':
    main()
