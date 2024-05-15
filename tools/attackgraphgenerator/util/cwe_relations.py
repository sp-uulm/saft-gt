import pandas
import time


def getParents(x):
    nextIsParent = False
    parents = []
    for word in x:
        if word == 'ChildOf':
            nextIsParent = True
        if nextIsParent:
            if word.isnumeric():
                parents.append(word)
                nextIsParent = False
    return parents


def getSuccessors(x):
    nextIsSuccessor = False
    parents = []
    for word in x:
        if word == 'CanPrecede':
            nextIsSuccessor = True
        if nextIsSuccessor:
            if word.isnumeric():
                parents.append(word)
                nextIsSuccessor = False
    return parents


def getAllAncestors(cwe, relation_data):
    current = relation_data[relation_data['CWE']
                            == int(cwe)].reset_index().iloc[0]
    parents = current['Parents']
    for ancestor in current['Parents']:
        parents = parents + getAllAncestors(ancestor, relation_data)
    return parents


def getAll(cwes, selector, relation_data):
    allItems = []
    for cwe in cwes:
        allItems = allItems + \
            relation_data[relation_data['CWE'] == int(
                cwe)].reset_index().iloc[0][selector]
    return allItems


def calculateCweRelationships(rawData):
    relation_data = rawData
    relation_data.columns = ['CWE', 'Relations']
    relation_data['Parents'] = rawData['Relations'].apply(
        lambda x: x.split(':')).apply(lambda x: getParents(x))
    relation_data['Parents'] = relation_data['Parents'].apply(
        lambda x: list(dict.fromkeys(x)))
    relation_data['Successors'] = rawData['Relations'].apply(
        lambda x: x.split(':')).apply(lambda x: getSuccessors(x))
    relation_data['Successors'] = relation_data['Successors'].apply(
        lambda x: list(dict.fromkeys(x)))
    relation_data['Predecessors'] = relation_data['CWE'].apply(
        lambda x: relation_data[relation_data['Successors'].apply(lambda y: str(x) in y)]['CWE'].tolist())
    relation_data['Predecessors'] = relation_data['Predecessors'].apply(
        lambda x: list(dict.fromkeys(x)))
    relation_data['All_Parents'] = relation_data['CWE'].apply(
        lambda x: list(dict.fromkeys(getAllAncestors(x, relation_data) + [x])))
    relation_data['All_Successors'] = relation_data['All_Parents'].apply(
        lambda x: getAll(x, 'Successors', relation_data))
    relation_data['All_Successors'] = relation_data['All_Successors'].apply(
        lambda x: list(dict.fromkeys(x)))
    relation_data['All_Predecessors'] = relation_data['All_Parents'].apply(
        lambda x: getAll(x, 'Predecessors', relation_data))
    relation_data['All_Predecessors'] = relation_data['All_Predecessors'].apply(
        lambda x: list(dict.fromkeys(x)))
    return relation_data.loc[:, ['CWE', 'All_Predecessors', 'All_Successors']]


class SandRelationsCalculator:

    cweRelations = []
    knownRelations = dict()
    maxLevel = 2

    def calculate(self, cve_data: pandas.DataFrame, relations: pandas.DataFrame, maxLevel=2):
        self.maxLevel = maxLevel
        self.knownRelations = dict()
        relations.columns = ['CWE', 'pre', 'suc']
        relations.replace('', None)
        cwes = cve_data['CWE'].drop_duplicates().tolist()
        relations['pre'] = relations['pre'].apply(lambda x: x.split(','))\
            .apply(lambda x: [int(y) for y in x if len(y) > 0])\
            .apply(lambda x: [y for y in x if y in cwes])
        relations['suc'] = relations['suc'].apply(lambda x: x.split(','))\
            .apply(lambda x: [int(y) for y in x if len(y) > 0])\
            .apply(lambda x: [y for y in x if y in cwes])
        for key, data in relations.iterrows():
            self.createRelationsLists(
                data['CWE'], relations)
        [self.translateToCVEs(relation, cve_data)
                for relation in self.cweRelations]
        self.cweRelations = []
        return self.knownRelations

    def flattenTree(self, t):
        if type(t) != tuple:
            if t in self.knownRelations.values():
                t = [k for k, v in self.knownRelations.items() if v == t][0]
            else:
                return [t]
        return self.flattenTree(t[0]) + self.flattenTree(t[1])

    def addNewSand(self, elem1, elem2, iscwe=True):
        if iscwe:
            newTuple = (elem1, elem2)
            if newTuple not in self.cweRelations:
                self.cweRelations.append(newTuple)
            return newTuple
        if not iscwe:
            flattened_current = self.flattenTree((elem1, elem2))
            duplicates = [k for k in self.knownRelations if self.flattenTree(
                k) == flattened_current]
            if len(duplicates) > 0:
                return self.knownRelations[duplicates[0]]
            if elem1 in self.knownRelations:
                elem1 = self.knownRelations[elem1]
            if elem2 in self.knownRelations:
                elem2 = self.knownRelations[elem2]
            newTuple = (elem1, elem2)
            if newTuple not in self.knownRelations:
                self.knownRelations[newTuple] = 'S' + \
                    str(len(self.knownRelations))
            return self.knownRelations[newTuple]

    def zipLists(self, a, b):
        zippedList = []
        for x in a:
            zippedList += [self.addNewSand(x, y) for y in b]
        return zippedList

    def getAllUsedCWE(self, t):
        total = []
        if type(t) != tuple:
            return total
        if type(t[0]) == tuple:
            total += self.getAllUsedCWE(t[0])
        else:
            total.append(t[0])
        if type(t[1]) == tuple:
            total += self.getAllUsedCWE(t[1])
        else:
            total.append(t[1])
        return total

    def createRelationsLists(self, cwe, relations, level=0):
        if level >= self.maxLevel:
            return []
        alreadyVisited = self.getAllUsedCWE(cwe)
        combinations = []
        for i in range(2):
            if type(cwe) == tuple and type(cwe[i]) != tuple:
                cwe_id = cwe[i]
            else:
                cwe_id = cwe
            if cwe_id not in relations['CWE'].tolist():
                continue
            pred = relations[relations['CWE'] == cwe_id].iloc[0]['pre']
            succ = relations[relations['CWE'] == cwe_id].iloc[0]['suc']
            pred = [relation for relation in pred if relation not in alreadyVisited]
            succ = [relation for relation in succ if relation not in alreadyVisited]
            if i == 0 or type(cwe) != tuple:
                combinations += self.zipLists(pred, [cwe])
            if i == 1 or type(cwe) != tuple:
                combinations += self.zipLists([cwe], succ)
            nextLevel = [self.createRelationsLists(
                entry, relations, level=level + 1) for entry in combinations]
            for x in nextLevel:
                combinations += x
            if type(cwe) != tuple:
                break
        return combinations

    def translateToCVEs(self, elem, cveList):
        relations = []
        print(cveList)
        if type(elem[0]) != tuple and type(elem[1]) != tuple:
            for cve1 in cveList[cveList['CWE'] == elem[0]]['CVE.ID'].tolist():
                for cve2 in cveList[cveList['CWE'] == elem[1]]['CVE.ID'].tolist():
                    relations.append(
                        (cve1, cve2))                    
        elif type(elem[0]) == tuple and type(elem[1]) == tuple:
            for x in self.translateToCVEs(elem[0], cveList):
                for y in self.translateToCVEs(elem[1], cveList):
                    relations.append((x, y))
        elif type(elem[1]) == tuple:
            for x in cveList[cveList['CWE'] == elem[0]]['CVE.ID'].tolist():
                for y in self.translateToCVEs(elem[1], cveList):
                    relations.append((x, y))
        elif type(elem[0]) == tuple:
            for x in self.translateToCVEs(elem[0], cveList):
                for y in cveList[cveList['CWE'] == elem[1]]['CVE.ID'].tolist():
                    relations.append((x, y))
        return [self.addNewSand(relation[0], relation[1], iscwe=False)
                for relation in relations]
