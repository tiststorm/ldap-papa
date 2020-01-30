from ldif import LDIFParser, LDIFWriter

ALL_STRUCTURALS = ["TSIdevice","inetOrgPerson","device", "person"]

DEFAULT_STRUCTURAL = "DEFAULTOC"

STRUCTURAL_OBJECTCLASS_MAPPING = {
    ("device","inetOrgPerson") : ["TSIdevice","dummyPerson"]
}

def sharedClasses(entry, classes):
    return compareClasses(entry,classes).count(True)

def compareClasses(entry, classes):
    '''
    Prüft für alle Elemente einer Liste von Klassen ob ein entry ein Objekt dieser Klasse ist (case-insensitive)
    '''
    return [(x.casefold() in [o.casefold() for o in entry["objectclass"]]) for x in classes]

def splitClasses(entry, classesToInspect):
    """
    Nimmt einen Record und gibt ein Tupel (a, b) mit
        a alle Klassen in classesToInspect
        b alle Klassen NICHT in classesToInspect
    """
    present = []
    absent = []
    for x in entry["objectclass"]:
        if x in classesToInspect: present.append(x)
        else: absent.append(x)
    present.sort()
    absent.sort()
    return (present, absent)

def addMissingStructural(entry):
    '''
    Fehlerfall: Record hat kein Structural als Oberklasse
    Es wird ein vordefiniertes Default Structural ergänzt
    '''
    entry["objectclass"].append(DEFAULT_STRUCTURAL)

def reduceMultipleStructural(entry):
    '''
    Fehlerfall: Record hat mehr als ein Structural als Oberklasse
    Die Nicht-Structural Oberklassen bleiben bestehen, nach einem vordefinierten Mapping werden die Objectclasses modifiziert
    '''
    structurals, nonstructurals = splitClasses(entry, ALL_STRUCTURALS)
    if tuple(structurals) in STRUCTURAL_OBJECTCLASS_MAPPING:
        entry["objectclass"] = nonstructurals + STRUCTURAL_OBJECTCLASS_MAPPING[tuple(structurals)]
    else: pass

def modifyEntryValues(func, entry):
    '''
    Nimmt einen Entry entgegen und wendet die übergebende Funktion func auf alle Values im Entry an
    '''
    for k,v in entry.items():
        entry[k] = list(map(func,v))

class StructuralLDIFParser(LDIFParser):
    def __init__(self, inputFile, outputFile):
        LDIFParser.__init__(self,inputFile)
        self.writer = LDIFWriter(outputFile)

    def handle(self, dn, entry):

        #Konvertiert alle Objektattributseinträge zu Strings damit Stringoperationen normal durchgeführt werden können
        print(dn, entry)
        modifyEntryValues(lambda x: x.decode(), entry)

        if (sharedClasses(entry, ALL_STRUCTURALS) == 0):
            addMissingStructural(entry)
        if (sharedClasses(entry, ALL_STRUCTURALS) == 2):
            reduceMultipleStructural(entry)

        #Konvertiert alle Objektattributseinträge zurück zu Byte-Literalen damit das Unparsen durch LDIFWriter funktioniert
        print(dn, entry, "\n")
        modifyEntryValues(lambda x: x.encode("utf-8"), entry)

        self.writer.unparse(dn, entry)

with open('datensatz','r') as inFile, open('bereinigter_datensatz','w') as outFile:
    parser = StructuralLDIFParser(inFile, outFile)
    parser.parse()

