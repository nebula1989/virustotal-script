from virustotal_python import Virustotal
import time
import json
from pprint import pprint

# API_KEY = <ENTER YOUR VIRUSTOTAL API KEY>   get one here: https://developers.virustotal.com/reference

# save your api key in a text file and get the key
with open("vt_api.txt", "r") as f:
    api_key = f.readline()
vtotal = Virustotal(api_key)  # virustotal API key

LIKELY_PHISHES = []


def main():
    is_it_a_phish = False
    print("Welcome. Enter 1 or more URLS.  Press ENTER again after last entry:")
    urls = get_urls()
    scan_all_urls(urls)
    print(str(len(LIKELY_PHISHES)) + " out of " + str(len(urls)) + " are phishes.\nHere they are:")
    display_phishes()


def scan_all_urls(urls):
    #try: # This try except statement is a temporary fix for a bug, see except part
    for url in urls:
        #if url not in ALREADY_SCANNED_URLS:
        print("\nInvestigating " + url)
        json_report = vt_get_report(url)
        while json_report == "API_LIMIT":
            print("API LIMIT. WAIT 30 seconds.")
            countdown(30)
            json_report = vt_get_report(url)
            '''Turn this on if you want to see the JSON report in terminal'''
            #display_json(json_report)

        there_is_already_a_report = analyze_json_report(json_report)

        if there_is_already_a_report:
            determine_phish(json_report, url)
        else:
            fresh_json_report = vt_scan(url)

            '''Turn this on if you want to see the JSON report in terminal'''
            #display_json(fresh_json_report)

            determine_phish(fresh_json_report, url)

        print("********************** END ************************")
            #print(ALREADY_SCANNED_URLS)


    #except TypeError: # for some reason after the last url is scanned, is scans nothing and throws a type error.  Luckily, it all the urls are scanned fined and this happens on the end and only happens if the API limit is reached
        #print("Finished...")


def vt_get_report(url):
    try:
        report = vtotal.url_report([url])
        data = json.dumps(report)
        json_report = json.loads(data)
        json_report = json_report['json_resp']
        print("\nGetting Report")
        countdown(10)
        #ALREADY_SCANNED_URLS.append(url)

        return json_report

    # if the API request limit is exceed it returns a type error
    except TypeError:
        return "API_LIMIT"


def analyze_json_report(report):
    print("\nAnalyzing JSON to determine if a VT report already exists...")
    is_there_a_report = False

    for item in report:
        if item == 'verbose_msg' and report[item] == "Resource does not exist in the dataset":
            print("No report")
            is_there_a_report = False
            break

        elif item == 'verbose_msg' and report[item] == "Scan finished, scan information embedded in this object":
            print("Report Exists")
            is_there_a_report = True
            break

    return is_there_a_report


def determine_phish(json_report, url):
    print("\nDetermining if this URL is a phish...")

    for p in json_report:
        if p == 'positives' and json_report[p] > 0:
            print("LIKELY A PHISH!\n" + p + ": " + str(json_report[p]) + "\n")
            LIKELY_PHISHES.append(url)

        elif p == 'positives' and json_report[p] == 0:
            print("UNLIKELY A PHISH!\n" + p + ": " + str(json_report[p]) + "\n")


def vt_scan(url):
    print("\nThis has never been scanned before so let's go ahead and scan it for the first time.")
    vtotal.url_scan([url])
    print("Scanning...it takes a bit of time to get accurate report.")

    countdown(20)

    json_report = vt_get_report(url)

    return json_report


def get_urls():
    lines = []
    while True:
        line = input()
        if line:
            lines.append(line)
        else:
            break
    return lines


def countdown(t):
    while t:
        mins, secs = divmod(t, 60)
        timer = '{:02d}:{:02d}'.format(mins, secs)
        print("\r", end=timer)
        time.sleep(1)
        t -= 1


def display_json(json_data):
    print("\n**************\n")
    pprint(json_data)
    print("\n**************\n")


def display_phishes():
    for phish_url in LIKELY_PHISHES:
        print(phish_url)


if __name__ == '__main__':
    main()
