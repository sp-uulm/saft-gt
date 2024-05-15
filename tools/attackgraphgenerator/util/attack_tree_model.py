from enum import Enum


class CVSS:
    cvss = None

    def __init__(self, cvss):
        self.cvss = cvss

    def build(self):
        return self.cvss


class CPE:
    cpe = None

    def __init__(self, cpe):
        self.cpe = cpe

    def build(self):
        return self.cpe


class CVE:
    cve = None
    description = None

    def __init__(self, cve, description=None):
        self.cve = cve
        self.description = description

    def build(self):
        descriptionString = ''
        if self.description is not None:
            descriptionString = ' description="' + self.description + '"'
        return self.cve + descriptionString


class CWE:
    cwe = None
    notes = None

    def __init__(self, cwe, notes=None):
        self.cwe = cwe
        self.notes = notes

    def build(self):
        notesString = ''
        if self.notes is not None:
            notesString = ' cweNotes="' + self.notes + '"'
        return 'CWE-' + str(self.cwe) + notesString


class AttackTree:
    step = None
    subTree = None
    ref = None

    def __init__(self, step=None, subTree=None, ref=None):
        self.step = step
        self.subTree = subTree
        self.ref = ref

    def build(self):
        if self.step is not None:
            return self.step.build()

        if self.subTree is not None:
            return self.subTree.build()

        if self.ref is not None:
            return str(self.ref)


class AttackTreeSubElements:
    value = None

    def __init__(self, attackStep=None, subTree=None):
        if attackStep is not None:
            self.value = attackStep
        elif subTree is not None:
            self.value = subTree

    def build(self):
        return self.value.build()


class AttackStep:
    id = None
    description = None
    cve = None
    cvss = None
    probability = None
    baseScore = None
    impactScore = None
    exploitabilityScore = None
    epss = None
    note = None
    attackTree = None

    def __init__(self, id=None, description=None, cve=None, cvss=None, probability=None, baseScore=None, impactScore=None, exploitabilityScore=None, epss= None, note=None, attackTree=None):
        self.id = id
        self.description = description
        self.cve = cve
        self.cvss = cvss
        self.probability = probability
        self.baseScore = baseScore
        self.impactScore = impactScore
        self.exploitabilityScore = exploitabilityScore
        self.epss = epss
        self.note = note
        self.attackTree = attackTree

    def build(self):
        result = 'AttackStep'

        if self.id is not None:
            result += ' '
            result += str(self.id)

        if self.description is not None:
            result += ' description="' + self.description + '"'

        if self.cve is not None and self.cve.build() is not None:
            result += ' CVE=' + self.cve.build()

        if self.cvss is not None and self.cvss.build() is not None:
            result += ' CVSS=' + self.cvss.build()

        if self.probability is not None and str(self.probability).replace('.', '', 1).isdigit():
            result += ' probability=' + str(self.probability)

        if self.baseScore is not None and str(self.baseScore).replace('.', '', 1).isdigit():
            result += ' BaseScore=' + str(self.baseScore)

        if self.impactScore is not None and str(self.impactScore).replace('.', '', 1).isdigit():
            result += ' ImpactScore=' + str(self.impactScore)

        if self.exploitabilityScore is not None and str(self.exploitabilityScore).replace('.', '', 1).isdigit():
            result += ' ExploitabilityScore=' + str(self.exploitabilityScore)

        if self.epss is not None:
            result += ' epss=' + str(self.epss)

        if self.note is not None:
            result += ' note="' + self.note + '"'

        #result += ' {' + self.attackTree.build() + '}'

        return result


class GateEnum(Enum):
    AND = 'AND'
    OR = 'OR'
    SAND = 'SAND'
    PAND = 'PAND'
    SOR = 'SOR'
    FDEP = 'FDEP'
    SPARE = 'SPARE'
    VOT = 'VOT'


class Gate:
    gate = None
    trigger = None
    primaryBasicEvent = None
    numberOfDisrubtions = None

    def __init__(self, gate=None, trigger=None, primaryBasicEvent=None, numberOfDistributions=None):
        self.gate = gate
        self.trigger = trigger
        self.primaryBasicEvent = primaryBasicEvent
        self.numberOfDisrubtions = numberOfDistributions

    def build(self):
        result = self.gate.value
        if self.gate == GateEnum.FDEP:
            result += ' trigger=' + self.trigger.build()
        if self.gate == GateEnum.SPARE:
            result += ' primaryBasicEvent=' + self.primaryBasicEvent.build()
        if self.gate == GateEnum.VOT:
            result += ' numberOfDisrubtions=' + str(self.numberOfDisrubtions)
        return result


class SubTree:
    gate = None
    id = None
    note = None
    attackTrees = []

    def __init__(self, gate=None, id=None, note=None, attackTrees=[]):
        self.gate = gate
        self.note = note
        self.attackTrees = attackTrees
        self.id = id

    def build(self):
        idString = ''
        if self.id is not None:
            idString = ' ' + str(self.id)

        noteString = ''
        if self.note is not None:
            noteString = ' note = "' + self.note + '"'

        attackTreesString = ''
        for entry in self.attackTrees:
            attackTreesString += entry.build() + ",\n"
        attackTreesString = " {\n" + attackTreesString.strip(',\n') + "\n}"

        return self.gate.build() + idString + noteString + attackTreesString


class AttackTarget:
    id = None
    cpe = None
    cwe = None
    cvss = None
    note = None
    attackTree = None

    def __init__(self, id=None, cpe=None, cwe=None, cvss=None, note=None, attackTree=None):
        self.id = id
        self.cpe = cpe
        self.cwe = cwe
        self.cvss = cvss
        self.note = note
        self.attackTree = attackTree

    def build(self):
        idString = ""
        if self.id is not None:
            idString = " id=" + str(self.id)

        cpeString = ""
        if self.cpe is not None:
            cpeString = " CPE=" + self.cpe

        cweString = ""
        if self.cwe is not None:
            cweString = " CWE=" + self.cwe.build()

        cvssString = ""
        if self.cvss is not None and self.cvss.build() is not None:
            cvssString = " CVSS=" + self.cvss.build()

        notesString = ""
        if self.note is not None:
            notesString = ' note="' + self.note + '"'

        return ("AttackTarget" + idString + cpeString + cweString + cvssString
                + notesString + ' {\n'
                + self.attackTree.build() + " \n}")


class AttackTreeElement:
    value = None

    def __init__(self, attackStep=None, subTree=None):
        if attackStep is not None:
            self.value = attackStep
        elif subTree is not None:
            self.value = subTree

    def build(self):
        return self.value.build()


class AttackTreeModel:
    value = None

    def __init__(self, attackTarget=None, attackTreeElement=None):
        if attackTarget is not None:
            self.value = attackTarget
        elif attackTreeElement is not None:
            self.value = attackTreeElement

    def build(self):
        return self.value.build()


class Model:
    attackTreeModels = []

    def __init__(self, attackTreeModels=[]):
        self.attackTreeModels = attackTreeModels

    def build(self):
        result = ''
        for models in self.attackTreeModels:
            result += models.build() + '\n'
        return result.strip('\n')
