#! /usr/bin/python

from ldif import LDIFParser, LDIFWriter

ALL_STRUCTURALS = ["TSIdevice","inetOrgPerson","device", "person","nisNetgroup"]

DEFAULT_STRUCTURAL = "DEFAULTOC"

STRUCTURAL_OBJECTCLASS_MAPPING = {
    ("device","inetOrgPerson") : ["TSIdevice","dummyPerson"],
    ("device","nisNetgroup") : ["TSIdevice", "dummyPerson"]
}

def sharedClasses(entry, classes):
    return compareClasses(entry,classes).count(True)

def compareClasses(entry, classes):
    '''
    Prüft für alle Elemente einer Liste von Klassen ob ein entry ein Objekt dieser Klasse ist (case-insensitive)
    '''
    try:
        return [(x.casefold() in [o.casefold() for o in entry["objectClass"]]) for x in classes]
    except KeyError:
        return []
def splitClasses(entry, classesToInspect):
    """
    Nimmt einen Record und gibt ein Tupel (a, b) mit
        a alle Klassen in classesToInspect
        b alle Klassen NICHT in classesToInspect
    """
    present = []
    absent = []
    for x in entry["objectClass"]:
        if x in classesToInspect: present.append(x)
        else: absent.append(x)
    present.sort()
    absent.sort()
    return (present, absent)


def modifyEntryValues(func, entry):
    '''
    Nimmt einen Entry entgegen und wendet die übergebende Funktion func auf alle Values im Entry an
    '''
    for k,v in entry.items():
        entry[k] = list(map(func,v))


class StructuralLDIFParser(LDIFParser):
    def __init__(self, inputFile, outputFile):
        LDIFParser.__init__(self,inputFile)

        self.count = 0
        self.missingStructurals = 0
        self.multipleStructurals = 0
        self.decodeError = 0
        self.unmapped = 0
        self.writer = LDIFWriter(outputFile)

    def handle(self, dn, entry):
        self.count+=1
        try:
            #Konvertiert alle Objektattributseinträge zu Strings damit Stringoperationen normal durchgeführt werden können
            #print(dn, entry)
            modifyEntryValues(lambda x: x.decode(), entry)
           # print(sharedClasses(entry,ALL_STRUCTURALS))
            if (sharedClasses(entry, ALL_STRUCTURALS) == 0):
                self.addMissingStructural(entry)
            if (sharedClasses(entry, ALL_STRUCTURALS) == 2):
                self.reduceMultipleStructural(entry)
        #Konvertiert alle Objektattributseinträge zurück zu Byte-Literalen damit das Unparsen durch LDIFWriter funktioniert
            #print(dn, entry, "\n")
            modifyEntryValues(lambda x: x.encode("utf-8"), entry)

            self.writer.unparse(dn, entry)
        except UnicodeDecodeError:
            self.decodeError +=1
        finally:
            print("Betrachtet: {} Missing Struct: {} Multiple Struct {} DecodeError {} Unmapped {} \r".format(self.count,self.missingStructurals, self.multipleStructurals, self.decodeError, self.unmapped),end="")

    def addMissingStructural(self, entry):
        '''
        Fehlerfall: Record hat kein Structural als Oberklasse
        Es wird ein vordefiniertes Default Structural ergänzt
        '''
        try:
            entry["objectClass"].append(DEFAULT_STRUCTURAL)
            self.missingStructurals += 1
        except KeyError:
            entry["objectClass"] = [DEFAULT_STRUCTURAL]

    def reduceMultipleStructural(self, entry):
        '''
        Fehlerfall: Record hat mehr als ein Structural als Oberklasse
        Die Nicht-Structural Oberklassen bleiben bestehen, nach einem vordefinierten Mapping werden die Objectclasses modifiziert
        '''
        structurals, nonstructurals = splitClasses(entry, ALL_STRUCTURALS)
        if tuple(structurals) in STRUCTURAL_OBJECTCLASS_MAPPING:
            self.multipleStructurals+=1
            entry["objectClass"] = nonstructurals + STRUCTURAL_OBJECTCLASS_MAPPING[tuple(structurals)]
        else:
            self.unmapped+=1
with open('app_dc_app.ldif','r') as inFile, open('app_dc_app_modified.ldif','w') as outFile:
    parser = StructuralLDIFParser(inFile, outFile)
    parser.parse()
    print("")
    print("")
    print("finished")

