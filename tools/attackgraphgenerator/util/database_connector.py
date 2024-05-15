import os
import json
import mariadb
import numpy
import pandas


class Connector:

    properties = None
    database = None
    cursor = None

    def __init__(self, checkTables=False, resetTables=False, tablesToReset=None):
        if not os.path.exists('properties.json'):
            print('Error: Properties File not found')
            exit()
        propertiesFile = open('properties.json', 'r')
        self.properties = json.loads(propertiesFile.read())['database']
        propertiesFile.close()
        self.establishConnection()
        if checkTables or resetTables:
            if resetTables:
                if tablesToReset is None:
                    print('Dropping all tables')
                else:
                    print('Dropping tables: ', tablesToReset)
                self.resetTables(tablesToReset)
            self.initDatabase()

    def establishConnection(self):
        print("Trying to connect to Database...")
        databaseProperties = self.properties
        try:
            self.database = mariadb.connect(user=databaseProperties['user'],
                                            password=databaseProperties['password'],
                                            host=databaseProperties['host'],
                                            database=databaseProperties['database'])
            self.cursor = self.database.cursor()
        except mariadb.Error as error:
            print('Failed to connect to database:\n' + str(error))
            exit()
        print('Connection Established')

    def initDatabase(self):
        # Database setup
        print('Setting up database tables')
        try:
            self.cursor.execute('CREATE TABLE CVE ('
                                + 'ID VARCHAR(255) PRIMARY KEY,'
                                + 'Description TEXT,'
                                + 'Vector VARCHAR(255),'
                                + 'BaseScore FLOAT,'
                                + 'BaseSeverity VARCHAR(255),'
                                + 'ExploitabilityScore FLOAT,'
                                + 'ImpactScore FLOAT,'
                                + 'CPEs MEDIUMTEXT,'
                                + 'Epss DOUBLE)'
                                )
        except mariadb.Error as e:
            print(e)
        try:
            self.cursor.execute('CREATE TABLE CVE_CWE_MAP ('
                                + 'CVE VARCHAR(255),'
                                + 'CWE INT)'
                                )
        except mariadb.Error as e:
            print(e)
        try:
            self.cursor.execute('CREATE TABLE CWE('
                                + 'ID INT PRIMARY KEY,'
                                + 'Name TEXT,'
                                + 'Description TEXT,'
                                + 'RelatedWeaknesses TEXT,'
                                + 'CommonConsequences TEXT,'
                                + 'PotentialMitigations TEXT)'
                                )
        except mariadb.Error as e:
            print(e)
        try:
            self.cursor.execute('CREATE TABLE CWE_Relations('
                                + 'CWE INT PRIMARY KEY,'
                                + 'predecessors TEXT,'
                                + 'successors TEXT)'
                                )
        except mariadb.Error as e:
            print(e)
        try:
            self.cursor.execute('CREATE TABLE CWE_Categories('
                                + 'ID INT,'
                                + 'CWE INT,'
                                + 'Name VARCHAR(255))'
                                )
        except mariadb.Error as e:
            print(e)

    def resetTables(self, tablesToReset):
        tables = ['CVE', 'CVE_CWE_MAP', 'CWE', 'CWE_Relations',
                  'CWE_Categories']
        if not tablesToReset is None:
            tables = tablesToReset
        for table in tables:
            try:
                self.cursor.execute('DROP TABLE ' + table)
            except mariadb.Error as e:
                print('Failed to reset table "' + table + '"')

    def insertPandasInto(self, table, data):
        valueString = ''
        data = data.replace({numpy.nan: None})
        data = data.where(pandas.notnull(data), None)
        for i in data.columns:
            valueString += '?,'
        try:
            query = 'INSERT INTO ' + table + \
                ' VALUES ( ' + valueString.strip(',') + ' );'
            self.cursor.executemany(query,
                                    data.values.tolist())
            self.database.commit()
        except mariadb.Error as e:
            print(table + ':' + str(e))

    def insertEpss(self, data):
        try:
            query = 'UPDATE CVE SET Epss = %s WHERE ID =  %s'
            self.cursor.executemany(query,
                                    data.values.tolist())
            self.database.commit()
        except mariadb.Error as e:
            print('CVE' + ':' + str(e))

    def deleteFromTable(self, table, table_id_column, ids):
        try:
            id_string = str(ids).replace('[', '(').replace(']', ')')
            self.cursor.execute(
                f'DELETE FROM {table} WHERE {table_id_column} IN {id_string}')
            self.database.commit()
        except mariadb.Error as e:
            print(e)

    def deleteAllEntriesFromTable(self, table):
        try:
            self.cursor.execute(f'DELETE FROM {table} WHERE TRUE')
        except mariadb.Error as e:
            print(e)
