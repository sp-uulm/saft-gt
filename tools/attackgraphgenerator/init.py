#!/usr/bin/env python3

from util.database_connector import Connector
import sys
import os
import json
from util.data_gatherer import DataGatherer


def setupAPIKeyFile():
    freshlyCreated = False
    if not os.path.exists('api.json'):
        print('api.json not found. Creating File... \nAdd you api key here to profit from faster requests to the NVD or run init again to start updating')
        apiKeyFile = open('api.json', 'w')
        apiKeyFile.close()
        freshlyCreated = True
    apiKeyFile = open('api.json', 'r')
    content = {}
    if not freshlyCreated:
        try:
            content = json.loads(apiKeyFile.read())
        except:
            print(
                'Api key file is not configured correctly. Check the file and add your API key')
    if not 'key' in content:
        content['key'] = ''
        apiKeyFile.close()
        apiKeyFile = open('api.json', 'w')
        apiKeyFile.write(json.dumps(content))
    apiKeyFile.close()
    if freshlyCreated:
        exit()


# Execution starts here
# Parameters:
# '-r' completely deletes and re-initializes the tables
# any further arguments will specify the tables to drop

print('Starting Setup\nChecking Database')
arguments = sys.argv
resetTables = len(arguments) > 1 and arguments[1] == '-r'
tables = None
if len(arguments) > 2:
    tables = arguments[2:]
if resetTables and os.path.exists('local/last-update.json') and (tables is None or 'CVE' in tables):
    os.remove('local/last-update.json')
databaseConnector = Connector(
    checkTables=True, resetTables=resetTables, tablesToReset=tables)

print('Checking for api file')
setupAPIKeyFile()

DataGatherer().updateAll()
