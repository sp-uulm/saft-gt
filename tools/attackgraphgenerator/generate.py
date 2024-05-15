#!/usr/bin/env python3

from datetime import datetime

from numpy import NaN
from util.attack_tree_model import *
import pandas
import os
import json
from util.database_connector import Connector
from util.cwe_relations import SandRelationsCalculator
import sys
import requests
import time

# Setup


class Generator:
    properties = None
    databaseProperties = None
    databaseConnector: Connector = Connector()

    def __init__(self, searchTerms, searchCPE=False, searchDescription=False, ):
        if not os.path.exists('properties.json'):
            print('Error: Properties File not found')
            exit()
        propertiesFile = open('properties.json', 'r')
        self.properties = json.loads(propertiesFile.read())
        propertiesFile.close()
        apiKeyFile = open('api.json', 'r')
        apiKey = json.loads(apiKeyFile.read())
        apiKeyFile.close()
        self.properties['apiKey'] = apiKey['key']
        # searchTerms is an array of json-Objects with the following fields:
        #   id:       Contains the cpe- or the fulltext-string to search for
        #   synonyms: Contains a list of synonyms used in the deployment model. 
        #             Should be copied in the "synonyms" parameter of the generated attack tree.
        saveLocation = datetime.now().isoformat().replace(
            '-', '_').replace('.', '_').replace(':', '_')
        for searchTerm in searchTerms:
            if searchCPE:
                self.generate(cveList=self.getByCPEMatchString(
                    searchTerm["id"]), type='cpe', searchString=searchTerm, saveLocation=saveLocation)
            if searchDescription:
                self.generate(cveList=self.getBySearchterm(searchTerm["id"]),
                              type='description', searchString=searchTerm, saveLocation=saveLocation)

    def getByCPEMatchString(self, cpe):
        nvdResults = self.nvdCPESearch(cpe)
        if len(nvdResults) < 1:
            print('NVD Search yielded no CWE for ' + cpe)
            return []
        self.databaseConnector.cursor.execute(
            "SELECT * FROM CVE WHERE ID IN " + str(nvdResults).replace('[', '(').replace(']', ')'))
        data = []
        for row in self.databaseConnector.cursor:
            data.append(row)
        data = pandas.DataFrame(data)
        return data

    def nvdCPESearch(self, cpe):
        url = self.properties['nistApi']['cves']['URI']
        apiKey = ''
        if self.properties['apiKey'] != '':
            apiKey = self.properties['apiKey']
        totalRecords = 1
        collectedRecords = []
        while (totalRecords > len(collectedRecords)):
            try:
                print("Searching CVEs for CPE: ")
                print(cpe)
                results = requests.get(
                    url + '?' + '&startIndex=' + str(len(collectedRecords)) + '&cpeName=' + cpe, headers={'apiKey': apiKey})
                print(results)
                if results.status_code == 403:
                    print(
                        'Server refusing to reply. Waiting to reset the servers requests per minute..')
                    time.sleep(30)
                    continue
                if results.status_code == 404:
                    print(
                        'Server replied with 404.\n\n', cpe + ' may not be a valid CPE.\nRetrying in 5seconds')
                    time.sleep(5)
                    continue
                time.sleep(self.properties['nistApi']['pauseBetweenRequests'])
                totalRecords = results.json()['totalResults']
                if totalRecords == 0:
                    continue
                collectedRecords += [item['cve']['id']
                                     for item in results.json()['vulnerabilities']]
            except Exception as e:
                print(e)
                continue
        return collectedRecords

    def getBySearchterm(self, searchterm):
        print("Searching CVEs for "+searchterm)
        #self.databaseConnector.cursor.execute("SELECT * FROM CVE WHERE LOWER(Description) LIKE LOWER('%" +
        #                                       searchterm + "%')")
        self.databaseConnector.cursor.execute("SELECT * FROM CVE WHERE match(description) against('\"" + searchterm + "\"' in boolean mode)")
        data = []
        for row in self.databaseConnector.cursor:
            data.append(row)
        data = pandas.DataFrame(data)
        return data

    def generateAttackStep(self, cve):
        return AttackTree(step=AttackStep(id=cve['CVE.ID'].replace('-', ''), cve=CVE(cve['CVE.ID']), description=cve['CVE.Description'],
                                          cvss=CVSS(cve['Vector']), baseScore=cve['BaseScore'], impactScore=cve['ImpactScore'],
                                          exploitabilityScore=cve['ExploitabilityScore'], epss=cve['Epss']))

    def generate(self, cveList, type, searchString, saveLocation=''):
        # searchString is a dictionary!
        fileName = ''.join([c for c in searchString["id"] if c.isalnum()])
        if len(fileName) <= 3:
            print(searchString["id"] + " is too short (<= 3 letters) for a useful search")
            return
        cpeString = None
        if type == 'cpe':
            cpeString = searchString["id"]
        attackStepReferences = {}
        if len(cveList) < 1:
            print(searchString)
            print('No related CVE entries found for "' + searchString["id"] + '"')
            return
        else:
            print(str(len(cveList)) + ' CVEs Found. Generating Attack Tree ...')
        generationNote = 'Generated for search by ' + \
            type + ' for keyword: ' + str(searchString["id"])
        fields = ['CVE.ID', 'CWE', 'CVE.Description', 'Vector', 'BaseScore', 'BaseSeverity',
                  'ExploitabilityScore', 'ImpactScore', 'Epss', 'CPEs', 'Name', 'RelatedWeaknesses']
        self.databaseConnector.cursor.execute(
            'SELECT ' + ''.join([field + ',' for field in fields]).strip(',') +
            ' FROM CVE LEFT OUTER JOIN CVE_CWE_MAP ON CVE_CWE_MAP.CVE = CVE.ID' +
            ' LEFT OUTER JOIN CWE ON CWE = CWE.ID  WHERE CVE.ID IN ' +
            str(cveList[0].tolist()).replace('[', '(').replace(']', ')'))
        dataFrame = pandas.DataFrame(self.databaseConnector.cursor)
        dataFrame.columns = fields
        dataFrame['CWE'] = dataFrame['CWE'].fillna(
            'Other').convert_dtypes(int)
        model = None
        subTree = None
        attackTree = None
        model = Model()
        model.attackTreeModels = []
        for key, data in dataFrame.groupby('CWE'):
            cweName = 'Name not available'
            if len(data[data['Name'] != None]) > 0:
                cweName = data[data['Name'] != None]['Name'].iloc[0]
            steps = []
            for i, cve in data.iterrows():
                if (cve['CVE.ID'] in attackStepReferences):
                    steps.append(AttackTree(
                        ref=attackStepReferences[cve['CVE.ID']]))
                else:
                    attackStepReferences[cve['CVE.ID']
                                         ] = cve['CVE.ID'].replace('-', '')
                    steps.append(self.generateAttackStep(cve))
            subTree = SubTree(gate=Gate(GateEnum.OR),
                              attackTrees=steps)
            attackTree = AttackTree(subTree=subTree)
            attackTreeModel = AttackTreeModel(AttackTarget(cpe=cpeString,
                                                           cwe=CWE(key, notes=cweName), note=generationNote, attackTree=attackTree))
            model.attackTreeModels.append(attackTreeModel)

        #cwes = dataFrame['CWE'].drop_duplicates()
        #self.databaseConnector.cursor.execute(
        #    'SELECT * FROM CWE_Relations WHERE CWE IN ' + str(cwes.tolist()).replace('[', '(').replace(']', ')'))
        #print (dataFrame)
        #relations = SandRelationsCalculator().calculate(dataFrame, pandas.DataFrame(self.databaseConnector.cursor), self.properties['maxRelationDepth'])
        #print('Calculating Relationships ...')
        #for relation in relations:
        #    subTree = SubTree(gate=Gate(GateEnum.SAND, id),
        #                      id=relations[relation], attackTrees=[])
        #    subTree.attackTrees.append(AttackTree(
        #        ref=str(relation[0].replace('-', ''))))
        #    subTree.attackTrees.append(AttackTree(
        #        ref=str(relation[1].replace('-', ''))))
        #    model.attackTreeModels.append(AttackTreeModel(
        #        AttackTarget(attackTree=AttackTree(subTree=subTree))))
        print('Writing to file: generated/' +
              saveLocation + '/' + fileName + '.txt ...')
        if not os.path.exists('generated'):
            os.mkdir('generated')
        if not os.path.exists('generated/' + saveLocation):
            os.mkdir('generated/' + saveLocation)
        file = open('generated/' + saveLocation + '/' + fileName + '.txt', 'w')
        file.write(model.build())
        file.close()
        print('Attack Tree generated sucessfully.')


params = sys.argv
if len(params) < 3:
    print('Insufficient number of parameters')
else:
    if params[1] == '-fp' or params[1] == '-fs':
        if os.path.exists(params[2]):
            fileReader = open(params[2], 'r')
            searchTerms = json.loads(fileReader.read())
            fileReader.close()
            Generator(searchTerms, searchCPE=params[1] == '-fp',
                      searchDescription=params[1] == '-fs')

    if params[1] == '-p' or params[1] == '-s':
        Generator(params[2:], searchCPE=params[1] == '-p',
                  searchDescription=params[1] == '-s')
