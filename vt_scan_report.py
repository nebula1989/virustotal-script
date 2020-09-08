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
    vt_get_report(urls)


def get_urls():
    lines = []
    while True:
        line = input()
        if line:
            lines.append(line)
        else:
            break
    return lines


def vt_get_report(urls):
    for url in urls:
        try:
            report = vtotal.url_report([url])
            data = json.dumps(report)
            json_report = json.loads(data)
            json_report = json_report['json_resp']
            #pprint(json_report)

            for item in json_report:
                if item == 'verbose_msg' and json_report[item] == 'Resource does not exist in the dataset':
                    vt_scan(url)

            for p in json_report:
                if p == 'positives' and json_report[p] > 0:
                    print("\nLikely a phish!\n" + p + ": " + str(json_report[p]))
                    break
                elif p == 'positives' and json_report[p] == 0:
                    print("\nUnlikely a phish!\n" + p + ": " + str(json_report[p]))
                    break

        except TypeError:
            print("You have exceeded the 4 calls per minute limit from VirusTotal... wait 1 minute")
            countdown(60)
            continue


def vt_scan(scan_this_url):
    print("This has never been scanned before... performing scan...")
    scan_status = vtotal.url_scan([scan_this_url])
    print("Scanning...")

    pprint(scan_status)
    countdown(10)

    report = vtotal.url_report([scan_this_url])
    data = json.dumps(report)
    json_report = json.loads(data)
    json_report = json_report['json_resp']
    #pprint(json_report)

    for p in json_report:
        if p == 'positives' and json_report[p] > 0:
            print("\nLikely a phish!\n" + p + ": " + str(json_report[p]))
            break
        elif p == 'positives' and json_report[p] == 0:
            print("\nUnlikely a phish!\n" + p + ": " + str(json_report[p]))
            break


def countdown(t):
    while t:
        mins, secs = divmod(t, 60)
        timer = '{:02d}:{:02d}'.format(mins, secs)
        print(timer, end="\r")
        time.sleep(1)
        t -= 1


if __name__ == '__main__':
    main()
