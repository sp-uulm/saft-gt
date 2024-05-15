# Attack Tree Generator

# About
The application provides the ability to generate attack trees according to the syntax and form defined in xtext. In addition, attack chains can be generated to form complex attacks.

# Usage
The application contains a init.py and a generate.py file, which can be called with their respective parameters. The init file provides the ability to update and initialize a project. The generate file takes cmd arguments to generate attack trees.

## Init
```init.py``` -updates all data on the database, if nvd data was downloaded before it will only be updated.

```init.py -r``` -Deletes all of the database tables, then executes standard init.

```init.py -r <list of space seperated table names>``` -Deletes only the selected tables.


When first running init it will create an api file, which can then be used to add a nvd api v2 key. This is particularly helpful when downloading for the first time, since nvd limits the rates for people without an api key.

## Generate
```generate.py -p <list of searchterms>``` - Specifies a list of products (CPEs) to search by

```generate.py -fp <path to file>``` - Specifies the path to a file containing backspace separated CPEs


```generate.py -s <list of searchterms>``` - Specifies a list of search terms to search by

```generate.py -fs <path to file>``` - Specifies the path to a file containing backspace separated search terms


The generated files can be found under ```generated/\<timestamp>```
