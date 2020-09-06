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
    print("Welcome. Enter 1 or more URLS:")
    urls = get_urls()
    vt_scan_report(urls)


def get_urls():
    lines = []
    while True:
        line = input()
        if line:
            lines.append(line)
        else:
            break
    return lines


def vt_scan_report(urls_list):
    # THINK OF A WAY TO SCAN ONLY 4 URLS PER MINUTE IN A LIST OF X URLS.

    already_scanned_urls = []

    scan_limit_four_at_time = 0

    for i in range(0, len(urls_list)):
        if urls_list[i] not in already_scanned_urls:
            print("\nScanning: " + urls_list[i])
            vtotal.url_scan(
                [urls_list[i]]
            )

            countdown(3)
            print("\nPrinting Report:\n")
            result = vtotal.url_report(
                [urls_list[i]]
            )

            already_scanned_urls.append(urls_list[i])
            scan_limit_four_at_time += 1

            print("\n***********")
            pprint(result)
            print("*************\n")

            print("Already Scanned: " + str(already_scanned_urls))
            print("Scan Limit: " + str(scan_limit_four_at_time))

        if scan_limit_four_at_time > 0 and scan_limit_four_at_time % 4 == 0:
            print("Taking 1 minute break... using free VirusTotal Api, which limits to 4 per minute..")
            countdown(61)
            continue


def countdown(t):
    while t:
        mins, secs = divmod(t, 60)
        timer = '{:02d}:{:02d}'.format(mins, secs)
        print(timer, end="\r")
        time.sleep(1)
        t -= 1


if __name__ == '__main__':
    main()
