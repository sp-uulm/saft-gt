import json
import pandas
import xml.etree.ElementTree as XMLParser
import os
from zipfile import ZipFile
import requests
from util.database_connector import Connector
from util.cwe_relations import calculateCweRelationships
import time
from datetime import datetime
import math


class DataGatherer:
    properties = None
    relevantFields = {'capec': ['\'ID', 'Name', 'Description', 'Alternate Terms', 'Likelihood Of Attack',
                                'Typical Severity', 'Related Attack Patterns',
                                'Prerequisites', 'Skills Required', 'Consequences', 'Mitigations'],
                      'cwe': ['CWE-ID', 'Name', 'Description', 'Related Weaknesses',
                              'Common Consequences', 'Potential Mitigations'],
                      'cweMap': ['CWE-ID', 'Related Attack Patterns'],
                      'epss': ['cve', 'epss']}
    database = Connector()

    def __init__(self):
        print("DG called!")
        propertiesFile = open('properties.json', 'r')
        self.properties = json.loads(propertiesFile.read())
        propertiesFile.close()
        apiKeyFile = open('api.json', 'r')
        apiKey = json.loads(apiKeyFile.read())
        apiKeyFile.close()
        self.properties['apiKey'] = apiKey['key']

    def downloadData(self, name, url):
        print(f'Downloading from {url}')
        getRequest = requests.get(url, allow_redirects=True)
        file = open('temp', 'wb')
        file.write(getRequest.content)
        file.close()
        if (getRequest.headers['Content-Type'] == 'application/zip'):
            currentZip = ZipFile('temp', 'r')
            currentZip.extractall()
            currentZip.close()
            if (os.path.exists(name+'.csv')):
                os.remove(name + '.csv')
            os.rename(currentZip.namelist()[0], name + '.csv')
        else:
            if (os.path.exists(name+'.csv')):
                os.remove(name + '.csv')
            os.rename('temp', name + '.csv')
        if os.path.exists('temp'):
            os.remove('temp')
        return name + '.csv'

    def updateCWE(self):
        print(' -- Updating CWE entries --')

        print('Updating CWE')
        for path in self.properties['sources']['cwe']:
            location = self.downloadData('cwe', path)
            cwe = pandas.read_csv(location, index_col=False,
                                  usecols=self.relevantFields['cwe']).fillna('na')

            self.database.deleteFromTable('CWE', 'ID', cwe['CWE-ID'].tolist())
            self.database.insertPandasInto('CWE', cwe)
            cwe = []
            if os.path.exists(location):
                os.remove(location)

        print('Updating Categories')
        location = self.downloadData(
            'cwe_categories', self.properties['sources']['cwe_categories'])
        tree = XMLParser.parse(location)
        root = tree.getroot()
        prefix = root.tag[0: root.tag.index('}') + 1]
        categories = []
        for category in tree.findall(".//" + prefix + "Category"):
            catid = category.attrib['ID']
            name = category.attrib['Name']
            for cwe in category.findall(".//" + prefix + "Has_Member"):
                if str(cwe.attrib['View_ID']) == '699':
                    categories.append((catid, cwe.attrib['CWE_ID'], name))
        self.database.deleteAllEntriesFromTable('CWE_Categories')
        self.database.insertPandasInto(
            'CWE_Categories', pandas.DataFrame(categories))
        tree = None
        root = None
        categories = []
        if os.path.exists(location):
            os.remove(location)
        print('Calculating CWE Relationships')
        self.database.cursor.execute('SELECT ID, RelatedWeaknesses FROM CWE')
        relatedWeaknesses = pandas.DataFrame(self.database.cursor)
        relations = calculateCweRelationships(relatedWeaknesses)
        relations['All_Predecessors'] = relations['All_Predecessors'].apply(
            lambda x: str(x).strip('[] ').replace('\'', ''))
        relations['All_Successors'] = relations['All_Successors'].apply(
            lambda x: str(x).strip('[] ').replace('\'', ''))
        self.database.deleteAllEntriesFromTable('CWE_Relations')
        self.database.insertPandasInto('CWE_Relations', relations)

    # Used to look up all of the cpe entries in a CVE response body

    def recursiveLookup(self, pointer, key):
        found = []
        if isinstance(pointer, dict):
            if key in pointer:
                found.append(pointer[key])
            for idict in pointer.values():
                for elem in self.recursiveLookup(idict, key):
                    found.append(elem)
        if isinstance(pointer, list):
            for ilist in pointer:
                for elem in self.recursiveLookup(ilist, key):
                    found.append(elem)
        return found

    def getEnglishField(self, data):
        data = pandas.DataFrame(data)
        return data[data['lang'] == 'en'].iloc[0, 1]

    # Processes the data in a list of CVE response bodies into the needed information

    def processCVEData(self, data):

        processedCVE = []
        processedCVECWEMAP = []
        for i, entry in data.iterrows():
            # CVE ENTRY
            cveID = entry['cve']['id']
            description = self.getEnglishField(entry['cve']['descriptions'])
            vector = None
            baseScore = None
            baseSeverity = None
            exploitabilityScore = None
            impactScore = None
            epss=None
            if 'metrics' in entry['cve'] and 'cvssMetricV31' in entry['cve']['metrics']:
                vector = entry['cve']['metrics']['cvssMetricV31'][0]['cvssData']['vectorString']
                baseScore = entry['cve']['metrics']['cvssMetricV31'][0]['cvssData']['baseScore']
                baseSeverity = entry['cve']['metrics']['cvssMetricV31'][0]['cvssData']['baseSeverity']
                exploitabilityScore = entry['cve']['metrics']['cvssMetricV31'][0]['exploitabilityScore']
                impactScore = entry['cve']['metrics']['cvssMetricV31'][0]['impactScore']
                epss=0
            # CVE CWE MAP
            associatedCWE = []
            if 'weaknesses' in entry['cve']:
                for weakness in entry['cve']['weaknesses']:
                    associatedCWE.append(
                        self.getEnglishField(weakness['description']))
            for cwe in associatedCWE:
                if cwe.startswith('CWE-'):
                    cwe = cwe.strip('CWE-')
                    try:
                        cwe = int(cwe)
                        processedCVECWEMAP.append((cveID, cwe))
                    except:
                        continue
            # CVECPE MAP
            cpeString = ''
            if 'configurations' in entry['cve']:
                cpes = self.recursiveLookup(
                    entry['cve']['configurations'], 'criteria')
                for cpe in cpes:
                    cpeString += cpe + ';'
                cpeString = cpeString.strip(';')
            processedCVE.append((cveID, description, vector, baseScore,
                                 baseSeverity, exploitabilityScore, impactScore, cpeString, epss))
        return processedCVE, processedCVECWEMAP

    # Reads all entries from the NVD CVE Database and processes them using the above data processor
    def getAllFromNistAPI(self, dataProcessor):
        timeOfLastUpdate = None
        if os.path.exists('local/last-update.json'):
            fileReader = open('local/last-update.json', 'r')
            try:
                timeOfLastUpdate = json.loads(fileReader.read())[
                    'last-cve-update']
            except Exception as e:
                print(e)
            finally:
                fileReader.close()
        lastModParam = ''
        if timeOfLastUpdate is not None:
            lastModParam = f'lastModStartDate={timeOfLastUpdate}&lastModEndDate={datetime.utcnow().isoformat()}&'
        url = self.properties['nistApi']['cves']['URI']
        apiKey = ''
        if self.properties['apiKey'] != '':
            apiKey = self.properties['apiKey']
        totalRecords = 1
        collectedRecords = 0
        while (totalRecords > collectedRecords):
            try:
                if len(apiKey) > 0:
                    results = requests.get(
                        url + '?' + lastModParam + '&startIndex=' + str(collectedRecords), headers={'apiKey': apiKey})
                else:
                    results = requests.get(
                        url + '?' + lastModParam + '&startIndex=' + str(collectedRecords))
                print(results)
                if results.status_code == 403:
                    print(
                        'Server refusing to reply. Waiting to reset the servers requests per minute..')
                    time.sleep(30)
                    continue
                time.sleep(self.properties['nistApi']['pauseBetweenRequests'])
                totalRecords = results.json()['totalResults']
                if totalRecords == 0:
                    continue
                collectedRecords += results.json()['resultsPerPage']
                cves, cvecwemap = dataProcessor(
                    pandas.DataFrame(results.json()['vulnerabilities']))
                self.database.deleteFromTable(
                    'CVE', 'ID', pandas.DataFrame(cves).iloc[:, 0].tolist())
                self.database.insertPandasInto('CVE', pandas.DataFrame(cves))
                self.database.deleteFromTable(
                    'CVE_CWE_MAP', '(CVE, CWE)', cvecwemap)
                self.database.insertPandasInto(
                    'CVE_CWE_MAP', pandas.DataFrame(cvecwemap))
                print(collectedRecords, '/', results.json()['totalResults'])
            except Exception as e:
                print(e)
                continue

        dates = datetime.utcnow().isoformat()
        self.verifyLastUpdate('local/last-update.json', 'last-cve-update', dates)
        return

    def getEpss(self):
        lastUpdate = None
        print(' -- Updating epss scores --')

        if os.path.exists('local/last-update.json'):
            fileReader = open('local/last-update.json', 'r')
            try:
                jsonData = json.loads(fileReader.read())
                if 'last-epss-update' in jsonData:
                    lastUpdate = jsonData['last-epss-update']
                else:
                    lastUpdate = '0001-01-01'
            except Exception as e:
                print(e)
            finally:
                fileReader.close()


        location = self.downloadData('epss', self.properties['sources']['epss'])

        date = pandas.read_csv(location, compression='gzip', nrows=1)
        dates = date.iloc[0, :].to_string()
        dates = dates[61:71]
        daten = datetime.strptime(dates, '%Y-%m-%d').date()

        if daten > datetime.strptime(lastUpdate, '%Y-%m-%d').date():
            epss = pandas.read_csv(location, compression='gzip', skiprows=[0],
                        header=0, sep=',', quotechar='"', usecols=self.relevantFields['epss']).fillna('na')
            epss['epss'] = epss['epss'].apply(lambda x: -(math.log(1-x)) / (60*60*24*30)) # number of seconds in a month (according to https://www.first.org/epss/articles/prob_percentile_bins)
            epss = epss.reindex(columns=['epss', 'cve'])
        else:
            epss = None

        if os.path.exists(location):
            os.remove(location)

        self.database.insertEpss(epss)

        self.verifyLastUpdate('local/last-update.json', 'last-epss-update', dates)

        # fileReader = open('local/last-update.json', 'w')
        # fileReader.write(json.dumps(
        #     {'last-epss-update': dates}))
        # fileReader.close()

        return epss

    def verifyLastUpdate(self, path, property, date):
        if not os.path.exists('local'):
            os.mkdir('local')

        if os.path.isfile(path):
            with open(path, "r") as f:
                data = json.load(f)
            if any(property in d for d in data):
                del data[next(i for i,d in enumerate(data) if property in d)]
            with open(path, "w") as f:
                json.dump(data, f, indent=2)

        a = []
        entry = {}
        entry[property] = date
        if not os.path.isfile(path):
            a.append(entry)
            with open(path, mode='w') as f:
                f.write(json.dumps(a))
        else:
            with open(path) as feedsjson:
                feeds = json.load(feedsjson)
                if property in feedsjson:
                    del feedsjson[property]
            feeds.append(entry)
            with open(path, mode='w') as f:
                f.write(json.dumps(feeds, indent=2))

    # Getting CVE Data
    def updateCVE(self):
        print('Storing CVE in DB')
        self.getAllFromNistAPI(self.processCVEData)

    def updateAll(self):
        self.updateCWE()
        self.updateCVE()
        self.getEpss()
