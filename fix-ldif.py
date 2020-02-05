#! /usr/bin/python3

from ldif import LDIFParser, LDIFWriter
import sys,getopt,ldap


URI = "ldap://25.16.128.69:3389/"
BINDDN = "cn=Manager,dc=adm"
PASSWD_FILE = "/home/admin/mstorm/.p-test"
SCHEMA_DN = "cn=schema,cn=config"
SCHEMA_FILTER = "(objectclass=olcSchemaConfig)"
SCHEMA_ATTRS = ["olcObjectClasses"]

DEFAULT_STRUCTURAL = "dummySTRUCTURAL"

OPERATIONAL_ATTRS  = ["nsUniqueId","modifyTimestamp","modifiersName","creatorsName","createTimestamp","aci","entryID","entryUID"]
OPERATIONAL_ATTRS2 = ["memberOf","userPassword","entryID","entryUID"]


STRUCTURAL_OBJECTCLASS_MAPPING = {
    ("device","inetOrgPerson") : ["TSIdevice","dummyPerson"],
    ("device","nisNetgroup") : ["TSIdevice", "dummyPerson"],
    ("account","organizationalPerson") : ["TSIdevice", "dummyPerson"],
    ("applicationEntity","person") : ["TSIdevice", "dummyPerson"]
}



def usage():
    print('structural_fix.py -i <inputfile> -o <outputfile> -l <logfile>')
    sys.exit(2)


def getStructurals():
    '''
    Liest aus dem Schema eines LDAP-Servers alle STRUCTURAL objectClasses aus
    '''
    con = ldap.initialize(URI)
    with open(PASSWD_FILE,mode="r") as passfile:
        bindpw=passfile.readline()

    try:
        con.simple_bind(BINDDN,bindpw)
    except ldap.INVALID_CREDENTIALS:
        print ("Your username or password is incorrect.")
        sys.exit()
    except ldap.LDAPError:
        if type(e.message) == dict and e.message.has_key("desc"):
            print (e.message["desc"])
        else:
            print (e)
        sys.exit()

    schema = con.search_s(SCHEMA_DN, ldap.SCOPE_SUBTREE, SCHEMA_FILTER, SCHEMA_ATTRS)

    out = []
    struct = 0
    aux = 0
    abstract = 0
    count = 0

    for schemafile in schema:
        n = schemafile[0]
        for oc in schemafile[1]["olcObjectClasses"]:
            s = str(oc)
            if "STRUCTURAL" in s:
                struct+=1
                l = s.replace("'","").split(" ")
                for i in range(len(l)):
                    if l[i] == "NAME":
#                        print("{0}./{1}. Wort = {2}/{3}".format(i,i+1,l[i],l[i+1]))
                        if l[i+1] == "(":
                            out.append("{}".format(l[i+2]))
                            out.append("{}".format(l[i+3]))
                        else:
                            out.append("{}".format(l[i+1]))
            elif "AUXILIARY" in str(oc):
                aux+=1
            elif "ABSTRACT" in str(oc):
                abstract+=1
            else:
                print(oc)
            count+=1

    print("structural/abstract/auxiliary = {}/{}/{} of {} entries".format(struct,abstract,aux,count))
    return sorted(out,key=lambda x:x.lower())


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

def deleteCSN(value, separator):
    v = value.split(separator)[0]
#    print("splitte \"{}\" => \"{}\"".format(value,v))
    return v
 
def modifyEntryValues(func, entry):
    '''
    Nimmt einen Entry entgegen und wendet die übergebende Funktion func auf alle Values im Entry an
    '''
    for k,v in entry.items():
        entry[k] = list(map(func,v))

def modifyEntryIndexes(func, entry):
    '''
    Nimmt einen Entry entgegen und wendet die übergebende Funktion func auf alle Indexes im Entry an
    '''
    for k,v in entry.items():
        if ";" in k:
            l=func(k,";")
            print("Ersetze {}: {} durch {}: {}                    ".format(k,v,l,v))	# trailing " " um laufenden Output zu überschreiben
#            print("----------------------------------------------------------------------------------")
#            print(entry)
            del entry[k]
#            entry[l]=v	# Ersetzung des *Tupels*
            entry.update([(l,v)])	# alternativ
            print("Entry: ",entry)

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

        self.ALL_STRUCTURALS = getStructurals()

    def handle(self, dn, entry):
        '''
        parset alle Entries im inputFile
        '''
        self.count+=1
        try:
            #Konvertiert alle Objektattributseinträge zu Strings damit Stringoperationen normal durchgeführt werden können
            modifyEntryValues(lambda x: x.decode(), entry)

            # löscht operational Attribute
            # löscht CSN aus Attributen
            #modifyEntryIndexes(lambda x: x.deleteCSN(), entry)
            modifyEntryIndexes(deleteCSN, entry)

            # fügt allen Einträgen ohne STRUCTURAL objectClass eine solche hinzu
            if (sharedClasses(entry, self.ALL_STRUCTURALS) == 0):
                self.addMissingStructural(dn, entry)
            # ersetzt 2 STRUCTURAL objectClasses durch 2 andere (siehe Mapping in STRUCTURAL_OBJECTCLASS_MAPPING)
            if (sharedClasses(entry, self.ALL_STRUCTURALS) == 2):
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
        structurals, nonstructurals = splitClasses(entry, self.ALL_STRUCTURALS)
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
    usage
if len(opts) < 3:
    usage()
for opt, arg in opts:
    if opt == '-h':
       usage()
    elif opt in ("-i", "--ifile"):
       inputfile = arg
    elif opt in ("-o", "--ofile"):
       outputfile = arg
    elif opt in ("-l", "--lfile"):
       logfile  = arg
#print(inputfile,outputfile, logfile)

with open(inputfile,'r') as inFile, open(outputfile,'w') as outFile, open(logfile,'w') as logFile:
    parser = StructuralLDIFParser(inFile, outFile, logFile)
#    print("{}".format(parser.ALL_STRUCTURALS))
    print("----------------------------------------------------------------------------------")
    parser.parse()
    print("\nfinished")


