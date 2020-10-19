from virustotal_python import Virustotal
import time
import json
from pprint import pprint
import re

# api_key = <YOUR VIRUSTOTAL API KEY>   get one here: https://developers.virustotal.com/reference

# save your api key in a text file named "vt_api.txt".  This snippet of code will read the api key instead of hardcoding it, for security.
# or delete this and hard code it above
with open("vt_api.txt", "r") as f:
    api_key = f.readline()
vtotal = Virustotal(api_key)  # virustotal API key

# the urls flagged malicious are saved here
LIKELY_PHISHES = []

API_LIMIT_SECONDS = 15
GET_SCAN_REPORT_SECONDS = 5


def main():
    print("Welcome. Enter 1 or more URLS.  Press ENTER again after last entry:")
    urls = get_urls()
    decoded_urls = decode_url(urls)
    scan_all_urls(decoded_urls)
    print(str(len(LIKELY_PHISHES)) + " out of " + str(len(decoded_urls)) + " are phishes.\nHere they are:")
    display_phishes()


def scan_all_urls(urls):
    for url in urls:
        print("\nInvestigating " + url)
        json_report = vt_get_report(url)

        while json_report == "API_LIMIT":
            print("API LIMIT. WAIT 15 seconds.")
            countdown(API_LIMIT_SECONDS)
            json_report = vt_get_report(url)

        '''Turn this on if you want to see the JSON report in terminal'''
        #display_json(json_report)

        there_is_already_a_report = analyze_json_report(json_report) # checks VirusTotal if report already exists

        if there_is_already_a_report:
            determine_phish(json_report, url)
        else: # if no report exists, it will then scan, this saves API requests
            fresh_json_report = vt_scan(url)

            '''Turn this on if you want to see the JSON report in terminal'''
            #display_json(fresh_json_report)

            determine_phish(fresh_json_report, url)

        print("********************** END ************************")


def vt_get_report(url):  # Function to retrieve a VirusTotal report of urls[url]
    try:
        report = vtotal.url_report([url])
        data = json.dumps(report)
        json_report = json.loads(data)
        json_report = json_report['json_resp']
        print("\nGetting Report")
        countdown(GET_SCAN_REPORT_SECONDS)

        return json_report

    except TypeError:  # if the API request limit is exceed it returns a type error
        return "API_LIMIT"


def analyze_json_report(report):  # function to read JSON data to see if the url has already been scanned in VirusTotal
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


def determine_phish(json_report, url):  # Reads through JSON data to count malicious positives, prints PHISH if positives or found, prints NOT A PHISH if not
    print("\nDetermining if this URL is a phish...")

    for p in json_report:
        if p == 'positives' and json_report[p] > 0:
            print("LIKELY A PHISH!\n" + p + ": " + str(json_report[p]) + "\n")
            LIKELY_PHISHES.append(url)

        elif p == 'positives' and json_report[p] == 0:
            print("UNLIKELY A PHISH!\n" + p + ": " + str(json_report[p]) + "\n")


def vt_scan(url):  # if the ULR has never been scanned before, it is scanned here
    print("\nThis has never been scanned before so let's go ahead and scan it for the first time.")
    vtotal.url_scan([url])
    print("Scanning...it takes a bit of time to get accurate report.")

    countdown(GET_SCAN_REPORT_SECONDS)

    json_report = vt_get_report(url)

    return json_report


def decode_url(urls):
    decoded_urls = []
    for url in urls:
        if re.search('https://urldefense.com.+', url):
            pattern = "__(.*?)__"  # this only shows what is inside the double underscores
            result = re.search(pattern, url).group(1)
            decoded_urls.append(result)
        else:
            return urls
    return decoded_urls


def get_urls():  # function to input a list of URLS
    lines = []
    while True:
        line = input()
        if line:
            lines.append(line)
        else:
            break
    return lines


def countdown(t):  # a timer to display a countdown
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
