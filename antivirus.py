import requests
import os.path
from time import sleep
import json
import virustotal_python
print("\n\n\n\n\\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n***********************************************************")

api_key = "4ad643b592a8360390d3f30d3724eb3ddd1f0b140ba4df4f4f700e9adabeeb62"



def virus_check(file_path):
    url_report = post_and_get_report_url(file_path)
    if url_report:
        sleep(4)
        get_report(url_report, file_path)


def determine_content_type(resource_path):
    i = resource_path.rfind(".")
    if i == -1:
        return "application/octet-stream"
    resource_extension = resource_path[i + 1:]
    content_type = ""
    if resource_extension == "html":
        content_type = "text/html"
    elif resource_extension == "css":
        content_type = "text/css"
    elif resource_extension == "js":
        content_type = "application/javascript"
    elif resource_extension == "jpg":
        content_type = "image/jpeg"
    elif resource_extension == "gif":
        content_type = "image/gif"
    elif resource_extension == "png":
        content_type = "image/png"
    elif resource_extension == "ico":
        content_type = "image/x-icon"
    else:
        content_type = "application/octet-stream"
    return content_type


def post_and_get_report_url(file_path):
    url = "https://www.virustotal.com/api/v3/files"
    f1 = open(file_path, 'rb')
    con = f1.read()
    f1.close()
    files = { "file": (file_path, open(file_path, "rb"), determine_content_type(file_path)) }
    headers = {
        "accept": "application/json",
        "x-apikey": api_key
    }
    response = requests.post(url, files=files, headers=headers)
    j = response.json()
    report_url = j["data"]["links"]["self"]
    return report_url


def get_report(report_url, file_path):
    headers = {
        "accept": "application/json",
        "x-apikey": api_key
    }
    response = requests.get(report_url, headers=headers)
    sleep(2)

    j = response.json()
    stats = j["data"]["attributes"]["stats"]
    print(stats)
    mal = stats["malicious"]
    sus = stats["suspicious"]
    if mal > 0:
        print(f"the file {file_path} is a virus")
    elif sus > 0:
        print(f"the file {file_path} might be a virus")
    else:
        print(f"the file {file_path} is safe")



def main(root_dir):
    for root, dirs, files in os.walk(root_dir, topdown=False):
        for name in files:
            virus_check(os.path.join(root, name))


root_dir = r"C:\Users\shahar\Downloads\files"
main(root_dir)