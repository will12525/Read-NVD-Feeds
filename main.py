import requests
import psycopg2
import gzip
import json

#try:
#    conn = psycopg2.connect("dbname='maindb' user='main' host='localhost' password='myPass'")
#except:
#    print("I am unable to connect to the database")


def download_gz_file(url, file_name):
    request_url = '{0}{1}'.format(url, filename)
    r = requests.get(request_url, stream=True)
    with open(file_name, 'wb') as fd:
        for chunk in r.iter_content(chunk_size=128):
            fd.write(chunk)


base_url = 'https://nvd.nist.gov/feeds/json/cve/1.1/'
filename = "nvdcve-1.1-modified.json.gz"

download_gz_file(base_url, filename)

with gzip.open(filename, 'rt') as zipfile:
    my_object = json.load(zipfile)
    CVE_list = my_object["CVE_Items"]
    for cve_obj in CVE_list:
        cve = cve_obj["cve"]
        cve_data_meta = cve["CVE_data_meta"]
        ID = cve_data_meta["ID"]
        print(ID)
