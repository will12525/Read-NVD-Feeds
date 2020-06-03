import requests
import psycopg2
import gzip
import json
import pprint

#try:
#    conn = psycopg2.connect("dbname='maindb' user='main' host='localhost' password='myPass'")
#except:
#    print("I am unable to connect to the database")


def download_gz_file(url, file_name):
    request_url = '{0}{1}'.format(url, file_name)
    r = requests.get(request_url, stream=True)
    with open(file_name, 'wb') as fd:
        for chunk in r.iter_content(chunk_size=128):
            fd.write(chunk)


def handle_products(node, product_list, cve_id):
    if node.get("operator") == "AND":
        for inner_nodes in node.get("children"):
            handle_products(inner_nodes, product_list, cve_id)
    else:
        try:
            for cpe in node.get("cpe_match"):
                product_info = []

                cpe_uri = cpe.get("cpe23Uri").split(':')
                prod_v = (lambda x: x if x != '*' else None)(cpe_uri[5])
                prod_v2 = (lambda x: x if x != '*' else None)(cpe_uri[6])

                product_info.append(cpe_uri[4])
                product_info.append((lambda x: x if x != '*' else None)(cpe_uri[5]))
                product_info.append((lambda x: x if x != '*' else None)(cpe_uri[6]))
                product_info.append(cpe_uri[1])
                product_info.append(cpe.get("versionStartIncluding"))
                product_info.append(cpe.get("versionEndIncluding"))

                product_list.append(product_info)
        except TypeError:
            if verbose:
                print('{0}{1}'.format("No product exists for: ", cve_id))


def get_cvssv_score(version, impact):
    base = "{0}{1}".format("baseMetric", version)
    cvss = "{0}{1}".format("cvss", version)
    try:
        return impact.get(base).get(cvss).get("baseScore")
    except AttributeError:
        if verbose:
            print("cvssv3 score doesn't exist")
        return None


def add_file_to_db(filename):
    with gzip.open(filename, 'rt') as zipfile:
        my_object = json.load(zipfile)
        cve_list = my_object["CVE_Items"]
        for cve in cve_list:
            cve_obj = cve.get("cve")
            impact_obj = cve.get("impact")
            desc_obj = cve_obj.get("description")
            conf_obj = cve.get("configurations")

            cve_id = cve_obj.get("CVE_data_meta").get("ID")
            cvssv2 = get_cvssv_score("V2", impact_obj)
            cvssv3 = get_cvssv_score("V3", impact_obj)
            published_date = cve.get("publishedDate")
            last_modified_date = cve.get("lastModifiedDate")

            descriptions = []
            products = []

            try:
                for description in desc_obj.get("description_data"):
                    descriptions.append(description["value"])
            except TypeError:
                if verbose:
                    print("No descriptions found")
            try:
                for node_list in conf_obj.get("nodes"):
                    handle_products(node_list, products, cve_id)
            except TypeError:
                if verbose:
                    print("No nodes found")



verbose = False

base_url = 'https://nvd.nist.gov/feeds/json/cve/1.1/'
file_to_add = "nvdcve-1.1-modified.json.gz"

#download_gz_file(base_url, filename)
add_file_to_db(file_to_add)

print("Done")
