import os
import time

import requests
from pymongo import MongoClient

from utils import get_padded_version

CVE_API_URL = 'https://services.nvd.nist.gov/rest/json/cves/2.0'
CPE_API_URL = 'https://services.nvd.nist.gov/rest/json/cpes/2.0'
# MongoDB Configuration
MONGODB_URI = os.environ['MONGO_URI']
DATABASE_NAME = os.environ['MONGO_DB']


def get_version(stem):
    cpe_list = stem.split(":")
    version_stem = cpe_list[5]

    if cpe_list[6] != "*" and cpe_list[6] != "-":
        return f"{version_stem}.{cpe_list[6]}"
    else:
        return version_stem


def handle_cpes(base_url, params={}, delay=6):
    all_cpes = []

    # Connect to Mongo
    client = MongoClient(MONGODB_URI)
    db = client[DATABASE_NAME]

    while True:
        response = requests.get(base_url, params=params)
        if response.status_code == 200:
            data = response.json()
            cpes = data.get('products')

            for cpe in cpes:
                obj = cpe.get('cpe', {})
                cpe = obj.get('cpeName')
                items = cpe.split(':')
                vendor = items[3]
                product = items[4]
                version = get_version(cpe)
                details = {
                    'cpe': cpe,
                    'cpeNameId': obj.get("cpeNameId"),
                    'vendor': vendor,
                    'product': product,
                    'version': version,
                    'paddedVersion': get_padded_version(version),
                    'deprecated': obj.get('deprecated'),
                    'deprecatedBy': obj.get('deprecatedBy', ""),
                    'created': obj.get('created'),
                    'lastModified': obj.get('lastModified'),
                    'timestamp': data.get('timestamp'),  # timestamp of when record collection was fetched
                }

                all_cpes.append(details)

            print(f'RESULTS: {all_cpes}')
            break  # TODO: TESTING

            # check for remaining products according to total and pagination params
            total = data.get('totalResults')
            fetched_count = len(all_cpes)
            if fetched_count < total:
                params['startIndex'] += data['resultsPerPage']
                print(f'Fetched {fetched_count} of {total} CPEs...')
                time.sleep(delay)
            else:
                break
        else:
            print(f'Failed to fetch CPEs: ', response.status_code)

    db.cpes.insert_many(all_cpes)


def generate_cvss(metrics):
    cvss = []
    for version in metrics.items():
        for metric in version:
            cvss_data = metric.get('cvssData', {})
            details = {
                'version': cvss_data.get('version'),
                'score': cvss_data.get('baseScore'),
                'severity': metric.get('baseSeverity', cvss_data.get('baseSeverity')) # v2 and v3 store in different place
            }

            cvss.append(details)

    return cvss


def generate_cwe(weaknesses):
    value = 'Unknown'  # providing default
    for weakness in weaknesses:
        for cwe in weakness["description"]:
            if cwe["lang"] == "en":
                value = cwe["value"]

    return value

def handle_cves(base_url, params={}, delay=6):
    all_cves = []

    # Connect to Mongo
    client = MongoClient(MONGODB_URI)
    db = client[DATABASE_NAME]

    while True:
        response = requests.get(base_url, params=params)
        if response.status_code == 200:
            data = response.json()
            cves = data.get('vulnerabilities')

            for cve in cves:
                obj = cve.get('cve', {})
                id = obj.get('id')
                description = obj.get('descriptions')[0].get('value')
                nvd_status = obj.get('vulnStatus')
                references = [ref.get('url') for ref in obj.get('references')]
                cpe, vendors, products = determine_cve_cpes(obj.get('configurations'), db)
                cwe = generate_cwe(obj.get('weaknesses'))
                cvss = generate_cvss(obj.get('metrics'))
                published = obj.get('published')
                last_modified = obj.get('lastModified')
                timestamp = data.get('timestamp')
                details = {
                    'cve_id': id,
                    'description': description,
                    'nvdStatus': nvd_status,
                    'references': references,
                    'cvss': cvss,
                    'cwe': cwe,
                    'cpe': cpe,
                    'vendors': vendors,
                    'products': products,
                    'published': published,
                    'lastModified': last_modified,
                    'timestamp': timestamp,  # timestamp of when record collection was fetched
                }

                all_cves.append(details)

            print(f'RESULTS: {all_cves}')
            break  # TODO: TESTING

            # check for remaining products according to total and pagination params
            total = data.get('totalResults')
            fetched_count = len(all_cves)
            if fetched_count < total:
                params['startIndex'] += data['resultsPerPage']
                print(f'Fetched {fetched_count} of {total} CVEs...')
                time.sleep(delay)
            else:
                break
        else:
            print(f'Failed to fetch CVEs: ', response.status_code)

    # db.cpes.insert_many(all_cves)


params = {
    'startIndex': 0,
}
handle_cpes(CPE_API_URL, params=params)
# handle_cves(CVE_API_URL, params=params)
