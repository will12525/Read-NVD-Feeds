This is a test program for reading and querying NVD Data feeds.

## Execution
When executed this program will download all CVE files and add the files contents to the database. When executed any 
time after the first time, this program will check all CVE files meta data and download any files that have been
modified.

## To Execute
Provide the necessary args to connect to the database.

`main.py [-hv] <DBName> <DBUser> <host> <password>`

This program requires the database name, connecting user, access point for the database, and connecting users password.


### Assumptions
This program assumes a PostgreSQL database exists and requires access it. 

## Requested queries

Query to show top 10 most vulnerable products based on the number of CVEs associated with them
- baseMetricV3
- `SELECT COUNT(prod_name) AS count, prod_name as Product_Name FROM products INNER JOIN cves ON cves.cve_id = products.cve_id WHERE score_v3 IS NOT NULL GROUP BY prod_name ORDER BY count DESC LIMIT 10;`
- baseMetricV2
- `SELECT COUNT(prod_name) AS count, prod_name as Product_Name FROM products INNER JOIN cves ON cves.cve_id = products.cve_id WHERE score_v2 IS NOT NULL GROUP BY prod_name ORDER BY count DESC LIMIT 10;`

Query to show the breakdown of the number of CVEs per whole-number score.
- baseMetricV3
- `SELECT COUNT(cve_id) AS count, CEIL(score_v3) as V3 FROM cves WHERE score_v3 IS NOT NULL GROUP BY CEIL(score_v3) ORDER BY CEIL(score_v3) DESC;`
- baseMetricV2
- `SELECT COUNT(cve_id) AS count, CEIL(score_v2) as V2 FROM cves WHERE score_v2 IS NOT NULL GROUP BY CEIL(score_v2) ORDER BY CEIL(score_v2) DESC;`