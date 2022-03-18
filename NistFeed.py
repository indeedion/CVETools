#!/usr/bin/env python3

import argparse
import datetime
import os
import sys
import json
from io import BytesIO
from zipfile import ZipFile
from urllib.request import urlopen

#URL = "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-modified.json.zip"
URL = "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-recent.json.zip"
FILE_NAME = "nvdcve-1.1-recent.json"
#FILE_NAME = "nvdcve-1.1-modified.json"
CWD = os.getcwd()
CT = datetime.datetime.now().strftime("%Y%m%d-%H:%M:%S")
OUT_FILE = "nistfeed-recent-" + CT  + ".csv"

class CvssV3:
    def __init__(self, data=None):
        if data is None:
            self.data = []
            self.version = 'N/A'
            self.vectorString = 'N/A'           
            self.attackVector = 'N/A'
            self.privilegesRequired = 'N/A'
            self.userInteraction = 'N/A'
            self.scope = 'N/A'
            self.confidentialityImpact = 'N/A'
            self.availabilityImpact = 'N/A'
            self.baseScore = 'N/A'
            self.baseSeverity = 'N/A'
        else:
            self.data = data
            self.version = data['version']
            self.vectorString = data['vectorString']
            self.attackVector = data['attackVector']
            self.privilegesRequired = data['privilegesRequired']
            self.userInteraction = data['userInteraction']
            self.scope = data['scope']
            self.confidentialityImpact = data['confidentialityImpact']
            self.availabilityImpact = data['availabilityImpact']
            self.baseScore = str(data['baseScore'])
            self.baseSeverity = data['baseSeverity']

class Reference:
    def __init__(self, data):
        self.data = data
        self.url = self.data['url']
        self.name = self.data['name']
        self.refsource = self.data['refsource']
        self.tags = self.data['tags']

class CVEObject:
    def __init__(self, cve_data):
        #containers
        self.data = cve_data
        self.cve = self.data['cve']
        self.cve_meta = self.cve['CVE_data_meta']

        #cve
        self.ID = str(self.cve_meta['ID'])
        self.assigner = self.cve_meta['ASSIGNER']
        self.data_type = self.cve['data_type']
        self.data_format = self.cve['data_format']
        self.publishedDate = self.data['publishedDate']
        self.lastModifiedDate = self.data['lastModifiedDate']

        #referenses
        self.reference_data = self.cve['references']['reference_data']
        self.references = []
        for ref in self.reference_data:
            self.references.append(ref)         
        
        #description
        self.description_data = self.cve['description']['description_data']
        self.descriptions = []
        for des in self.description_data:
            self.descriptions.append(des['value'])

        #impact
        self.bm3Exist = False
        self.impact = self.data['impact']
        if 'baseMetricV3' in self.impact:
            self.CvssV3 = CvssV3(self.impact['baseMetricV3']['cvssV3'])
            self.exploitabilityScore = self.impact['baseMetricV3']['exploitabilityScore']
            self.impactScore = self.impact['baseMetricV3']['impactScore']
            self.bm3Exist = True
        else:
            self.CvssV3 = CvssV3(None)
            self.exploitabilityScore = 'N/A'
            self.impactScore = 'N/A'

def getFile():
    response = urlopen(URL)
    res = ""
    zipfile = ZipFile(BytesIO(response.read()))
    for line in zipfile.open(FILE_NAME).readlines():
        res += line.decode('utf-8')
    return res

FILE = getFile()

def makeCVS(objects):
    file = open(OUT_FILE, 'a') 
    file.write("CVE;BASE SCORE;DATE PUBLISHED;DESCRIPTION")
    for obj in objects:
        desc = ""
        for d in obj.descriptions:
            desc += d
        file.write(
            obj.ID + ";" + 
            obj.CvssV3.baseScore + ";" + 
            obj.publishedDate + ";" + 
            desc
            )
    
    file.close()

def intScore(score):
    spl = score.split('.')
    return spl[0]

def printByScore(score, objects):
    for obj in objects:
        if obj.CvssV3.baseScore != 'N/A':
            inScore = intScore(score)
            baseScore = intScore(obj.CvssV3.baseScore)
            if inScore == baseScore:
                print(obj.ID, obj.CvssV3.baseScore, obj.publishedDate)

def printDefault(objects):
    for obj in objects:
        print(obj.ID, obj.CvssV3.baseScore, obj.publishedDate)

def main():
    #for arg in sys.argv[1:]:

    #create object list
    CVEObjects = []

    #parse file into objects array
    data = json.loads(FILE)
    item_list = data['CVE_Items']
    for item in item_list:
        CVEObjects.append(CVEObject(item))
 
    if args.csv == True:
        makeCVS(CVEObjects)
    elif args.score is not None:
        printByScore(args.score, CVEObjects)
    else:
        printDefault(CVEObjects)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('-c', '--csv', action='store_true', help='create csv')
    parser.add_argument('-s', '--score', action='store', help='print only this base-score')
    args = parser.parse_args()
    #parser.print_help()
    main()
