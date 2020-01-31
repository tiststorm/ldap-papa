#! /usr/bin/python

from ldif import LDIFParser, LDIFWriter
import sys,getopt

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
    def __init__(self, inputFile, outputFile, logFile):
        LDIFParser.__init__(self,inputFile)

        self.count = 0
        self.missingStructurals = 0
        self.multipleStructurals = 0
        self.decodeError = 0
        self.unmapped = 0
        self.writer = LDIFWriter(outputFile)
        self.logger = logFile

    def handle(self, dn, entry):
        self.count+=1
        try:
            #Konvertiert alle Objektattributseinträge zu Strings damit Stringoperationen normal durchgeführt werden können
            modifyEntryValues(lambda x: x.decode(), entry)

            if (sharedClasses(entry, ALL_STRUCTURALS) == 0):
                self.addMissingStructural(dn, entry)
            if (sharedClasses(entry, ALL_STRUCTURALS) == 2):
                self.reduceMultipleStructural(dn, entry)

            #Konvertiert alle Objektattributseinträge zurück zu Byte-Literalen damit das Unparsen durch LDIFWriter funktioniert
            modifyEntryValues(lambda x: x.encode("utf-8"), entry)



            self.writer.unparse(dn, entry)
        except UnicodeDecodeError:
            self.decodeError +=1
            self.logger.write("[DECODEERROR] UnicodeDecodeError bei dn={}\n".format(dn))
        finally:
            print("Betrachtet: {} Missing Struct: {} Multiple Struct {} DecodeError {} Unmapped {} \r".format(self.count,self.missingStructurals, self.multipleStructurals, self.decodeError, self.unmapped),end="")
            pass

    def addMissingStructural(self, dn, entry):
        '''
        Fehlerfall: Record hat kein Structural als Oberklasse
        Es wird ein vordefiniertes Default Structural ergänzt
        '''
        try:
            entry["objectClass"].append(DEFAULT_STRUCTURAL)
            self.missingStructurals += 1
            self.logger.write("[NEWOC] Es wurde ein Default-Structural bei dn={} ergänzt\n".format(dn))
        except KeyError:
            entry["objectClass"] = [DEFAULT_STRUCTURAL]
            self.logger.write("[NOOC] Es ist keine Objectclass bei dn={} vorhanden\n".format(dn))

    def reduceMultipleStructural(self, dn, entry):
        '''
        Fehlerfall: Record hat mehr als ein Structural als Oberklasse
        Die Nicht-Structural Oberklassen bleiben bestehen, nach einem vordefinierten Mapping werden die Objectclasses modifiziert
        '''
        structurals, nonstructurals = splitClasses(entry, ALL_STRUCTURALS)
        if tuple(structurals) in STRUCTURAL_OBJECTCLASS_MAPPING:
            self.multipleStructurals+=1
            newStructural = STRUCTURAL_OBJECTCLASS_MAPPING[tuple(structurals)]
            entry["objectClass"] = nonstructurals + newStructural
            self.logger.write("[NEWMAPPING] Bei dn={} wurde erfolgreich ein Mapping von {} auf {} durchgeführt\n".format(dn, structurals, newStructural))
        else:
            self.unmapped+=1
            self.logger.write("[UNMAPPED] Bei dn={} wurde kein Mapping für {} gefunden\n".format(dn, structurals))


inputfile = ''
outputfile = ''
try:
    opts, args = getopt.getopt(sys.argv[1:],"hi:o:l:",["ifile=","ofile=","lfile="])
except getopt.GetoptError:
    print('test.py -i <inputfile> -o <outputfile> -l <logfile>')
    sys.exit(2)
for opt, arg in opts:
    if opt == '-h':
       print('structural_fix.py -i <inputfile> -o <outputfile> -l <logfile>')
       sys.exit()
    elif opt in ("-i", "--ifile"):
       inputfile = arg
    elif opt in ("-o", "--ofile"):
       outputfile = arg
    elif opt in ("-l", "--lfile"):
       logfile  = arg
#print(inputfile,outputfile, logfile)

with open(inputfile,'r') as inFile, open(outputfile,'w') as outFile, open(logfile,'w') as logFile:
    parser = StructuralLDIFParser(inFile, outFile, logFile)
    parser.parse()
    print("\nfinished")

