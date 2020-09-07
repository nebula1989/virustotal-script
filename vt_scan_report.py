from virustotal_python import Virustotal
from pprint import pprint
import time
import json

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
            result = ""
            print("\nScanning... \n" + urls_list[i] + " is...")

            vtotal.url_scan(
                [urls_list[i]]
            )

            countdown(16)

            result = vtotal.url_report(
                [urls_list[i]]
            )

            print("getting report...")
            countdown(16)

            # get JSON data from VT report
            try:
                data = json.dumps(result)
                json_result = json.loads(data)
                json_result = json_result['json_resp']
            except TypeError:
                print("JSON Error")
                continue

            for p in json_result:
                if p == 'positives' and json_result[p] > 0:
                    print("\nLikely a phish!\n" + p + ": " + str(json_result[p]))
                elif p == 'positives' and json_result[p] == 0:
                    print("\nUnlikely a phish!\n" + p + ": " + str(json_result[p]))
                    break

            already_scanned_urls.append(urls_list[i])
            scan_limit_four_at_time += 1
            print("\nYou have scanned " + str(scan_limit_four_at_time) + " URLs.")


def countdown(t):
    while t:
        mins, secs = divmod(t, 60)
        timer = '{:02d}:{:02d}'.format(mins, secs)
        print(timer, end="\r")
        time.sleep(1)
        t -= 1


if __name__ == '__main__':
    main()
