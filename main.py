import requests
import psycopg2
import gzip
import json
import pprint
import re


def download_gz_file(file_name):
    url = 'https://nvd.nist.gov/feeds/json/cve/1.1/'
    request_url = '{0}{1}'.format(url, file_name)
    r = requests.get(request_url, stream=True)
    with open(file_name, 'wb') as fd:
        for chunk in r.iter_content(chunk_size=128):
            fd.write(chunk)


def request_meta_data(file_name):
    url = 'https://nvd.nist.gov/feeds/json/cve/1.1/'
    request_url = '{0}{1}'.format(url, file_name)
    r = requests.get(request_url, stream=True)
    if r:
        return re.search('Date:(.*)\r\n', r.text).group(1)
    return False


def handle_products(node, product_list, cve_id):
    if node.get("operator") == "AND":
        for inner_nodes in node.get("children"):
            handle_products(inner_nodes, product_list, cve_id)
    else:
        try:
            for cpe in node.get("cpe_match"):
                product_info = []

                cpe_uri = cpe.get("cpe23Uri").split(':')

                product_info.append(cve_id)
                product_info.append(cpe_uri[4])
                product_info.append((lambda x: x if x != '*' else None)(cpe_uri[5]))
                product_info.append((lambda x: x if x != '*' else None)(cpe_uri[6]))
                product_info.append(float(cpe_uri[1]))
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


def add_file_to_db(filename, modify):
    # remove products related to this ID, update
    # DELETE FROM products WHERE cve_id = %s
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

            if modify:
                sql_query = "select cve_id from CVEs where cve_id = %s AND mod_date < %s"
                cur.execute(sql_query, (cve_id, last_modified_date))
                record = cur.fetchone()
                if record is None:
                    # The current record is older than the new record.
                    sql_query = "delete from products WHERE cve_id = %s"
                    cur.execute(sql_query, (cve_id, ))
                    sql_query = "delete from cve_id WHERE cve_id = %s"
                    cur.execute(sql_query, (cve_id,))
                else:
                    # The current record is up to date, carry on
                    continue

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


            sql = """ INSERT INTO CVEs 
            (cve_id, score_v2, score_v3, pub_date, mod_date, description) 
            VALUES (%s, %s, %s, %s, %s, %s) """
            params = (cve_id, cvssv2, cvssv3, published_date, last_modified_date, descriptions)
            try:
                cur.execute(sql, params)
                conn.commit()
            except Exception as err:
                print(err)

            sql = """ INSERT INTO products 
            (cve_id, prod_name, version1, version2, cpe_version, version_start, version_end) 
            VALUES (%s, %s, %s, %s, %s, %s, %s) """
            try:
                cur.executemany(sql, products)
                conn.commit()
            except Exception as err:
                print(err)


# Checks meta data dates of all data-feed files and compares the date to a stored value in the db.
# If the year doesn't exist then this downloads the new file and adds its data to the database.
def check_all_files():
    r = requests.get("https://nvd.nist.gov/vuln/data-feeds#JSON_FEED")

    for filename in re.findall(r'nvdcve-1.1-[0-9]*\.meta', r.text):
        file_last_modified = request_meta_data(filename)
        if file_last_modified:
            year = int(re.search('1.1-(.*).meta', filename).group(1))
            download_file = "{0}{1}".format(filename.rsplit('.', 1)[0], ".json.gz")

            sql_query = "select year from modified_files where year = %s"
            cur.execute(sql_query, (year,))
            record = cur.fetchone()
            if record is None:
                # This file is new
                print("NEW FILE")
                download_gz_file(download_file)
                sql = """ INSERT INTO modified_files(year, modified) VALUES (%s, %s) """
                params = (year, file_last_modified)
                try:
                    cur.execute(sql, params)
                    conn.commit()
                except Exception as err:
                    print(err)
                add_file_to_db(download_file, False)

            else:
                sql_query = "select * from modified_files where year = %s AND modified < %s"
                cur.execute(sql_query, (year, file_last_modified))
                record = cur.fetchone()
                if record:
                    # File has been modified since last check
                    print("UPDATING FILE")
                    download_gz_file(download_file)
                    sql_update_query = """Update modified_files set modified = %s where year = %s"""
                    cur.execute(sql_update_query, (file_last_modified, year))
                    conn.commit()
                    add_file_to_db(download_file, True)
    print("Done file check")


if __name__ == '__main__':
    verbose = False
    conn = None
    cur = None

    try:
        conn = psycopg2.connect("dbname='maindb' user='main' host='localhost' password='myPass'")
        cur = conn.cursor()
    except (Exception, psycopg2.DatabaseError) as error:
        print(error)
        if verbose:
            print("Unable to connect to database")
        exit(1)

    check_all_files()

    if conn is not None:
        cur.close()
        conn.close()
    print("Done")
