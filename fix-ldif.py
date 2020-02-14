#! /usr/bin/python3

from ldif import LDIFParser, LDIFWriter
from unidecode import unidecode
import sys,os,getopt,ldap,string,unicodedata


# bei Bedarf für entsprechende Ausgaben
DEBUG = False


URI = "ldap://25.16.128.69:3389/"
BINDDN = "cn=Manager,dc=adm"
PASSWD_FILE = "/home/admin/mstorm/.p-test"
SCHEMA_DN = "cn=schema,cn=config"
SCHEMA_FILTER = "(objectclass=olcSchemaConfig)"
SCHEMA_ATTRS = ["olcObjectClasses"]

DEFAULT_STRUCTURAL = "dummySTRUCTURAL"

# bekannt serverübergreifend operationale Parameter
OPERATIONAL_ATTRS  = ["aci","nsUniqueId","modifyTimestamp","modifiersName","creatorsName","createTimestamp","entryID","entryUID","memberOf","ldapSubEntry"]
# anscheinend DSEE-proprietäre operationale Parameter
OPERATIONAL_ATTRS2  = ["passwordPolicySubentry","passwordRetryCount","pwdLastAuthTime","passwordExpWarning","passwordExpWarned","pwdChangedTime","pwdFailureTime","passwordAllowChangeTime","pwdHistory","accountUnlockTime","passwordExpirationTime","retryCountResetTime"]

# anscheinend nicht mehr im Schema existente ehemals operational Attribute
DELETE_ATTRS = ["ds6ruv","nsds50ruv", "nsds5ReplConflict","nscpEntryDN","nsParentUniqueId","nsUniqueId","nsAccountLock"]
# anscheinend nicht mehr im Schema existente eigene Attribute
DELETE_ATTRS2  = ["dthostnamemode","dtsetshadowattributes"]
# unklar ob zu löschende Attribute
DELETE_ATTRS3 = []


# Fehlerfall: ein Eintrag hat eine oC, aber nicht die zugehörigen MUST-Attribute
# besonders schwierig bei operational Attributen wie z.B. groupOfUniqueNames
# Falls eine oC (Dict-Key) existiert, aber die zugehörigen musthave-Attribut(e) (1. Wert des Tupels) nicht, dann füge
# dieses Attribute letztere(s) mit einem Dummy-Value (2. Wert des Tupels, wenn nicht leer) hinzu
# oder lösche die oC (wenn 2. Wert des Tupels leer)
# Achtung, Prozessierung ist case sensitiv da er sich auf die Attributs*value*s bezieht; daher ggfs. mehrere Einträge verwenden

OC_ATTR_DEPENDENCY = { "groupOfUniqueNames" : [("uniqueMember", "dummyMember")],
                       "groupofuniquenames" : [("uniqueMember", "dummyMember")] }
#OC_ATTR_DEPENDENCY = { "groupOfUniqueNames" : [("uniqueMember", "")],
#                       "groupofuniquenames" : [("uniqueMember", "")] }

# dummyAUXILIARY muss alle Attribute als MAY enthalten, die nisNetgroup und person enthalten können
# (für inetOrPerson,organizationalPerson scheint es keine Einträge zu geben)
# person => MAY (sn $ cn )
# nisNetgroup => MAY ( nisNetgroupTriple $ memberNisNetgroup $ description )
STRUCTURAL_OBJECTCLASS_MAPPING = {
    ("device","nisNetgroup") : ["TSIdevice", "dummyAUXILIARY"],
    ("account","organizationalPerson") : ["TSIdevice", "dummyAUXILIARY"],
    ("device","inetOrgPerson") : ["TSIdevice","dummyAUXILIARY"],
    ("device","person") : ["TSIdevice", "dummyAUXILIARY"]
#    ("applicationEntity","person") : ["TSIdevice", "dummyAUXILIARY"],
#    ("applicationProcess","referral") : ["TSIdevice", "dummyAUXILIARY"]
}


def normalizeStringCaseless(text):
    return unicodedata.normalize("NFKD", text.casefold())


def usage():
    print("{} -i <inputfile> -o <outputfile> -l <logfile>'".format(os.path.basename(__file__)))
    sys.exit(2)


def getOperationals():
    return OPERATIONAL_ATTRS + OPERATIONAL_ATTRS2


def getAttributesToBeDeleted():
    return DELETE_ATTRS + DELETE_ATTRS2 + DELETE_ATTRS3


def getStructurals():
    """
    Liest aus dem Schema eines LDAP-Servers alle STRUCTURAL objectClasses aus
    """
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
                struct += 1
                l = s.replace("'","").split(" ")
                for i in range(len(l)):
                    if l[i] == "NAME":
                        if l[i+1] == "(":
                            out.append("{}".format(l[i+2]))
                            out.append("{}".format(l[i+3]))
                        else:
                            out.append("{}".format(l[i+1]))
            elif "AUXILIARY" in str(oc):
                aux += 1
            elif "ABSTRACT" in str(oc):
                abstract += 1
            count += 1

    print("structural/abstract/auxiliary = {}/{}/{} of {} entries".format(struct,abstract,aux,count))
    return sorted(out,key=lambda x:x.lower())


def sharedClasses(entry, classes):
    return compareClasses(entry,classes).count(True)


def compareClasses(entry, classes):
    """
    Prüft für alle Elemente einer Liste von Klassen ob ein entry ein Objekt dieser Klasse ist (case-insensitive)
    """
    try:
        return [(x.casefold() in [o.casefold() for o in entry["objectClass"]]) for x in classes]
    except KeyError:
        return []


def sanitizeObjectClasses(dn, entry, dependencies, self):
    """
    prüft ob zu bestimmten objectClasses gehörige (must-)Attribute vorhanden sind (Liste als "dependencies" übergeben)
    löscht ggfs. die oC (wenn die Liste zu ergänzender Attrs leer ist) und setzt ein dummy-Attribut
    """
    for oC in entry["objectClass"]:
        if oC in dependencies: # Wir wollen für diese Objectclass oC alle dependencies überprüfen
            l = [d[0] not in entry for d in dependencies[oC]]
            if all(l):
                entry["objectClass"].remove(oC)
                self.logger.write("[SANITIZE oC] Bei dn=\"{}\" wurde die oC {} gelöscht, weil die zugehörigen must-Attribute fehlen.\n".format(dn, oC))
                break
            for attribute, value in dependencies[oC]: 
                if attribute not in entry:
                    entry[attribute] = [value] # fügt dem dict neuen Eintrag mit key = Attributs-Name und value = dummy hinzu
                    self.logger.write("[SANITIZE oC] Bei dn=\"{}\" wurde dummy {}: {} ergänzt, weil es ein must-Attribut der objectClass {} ist, aber fehlte.\n".format(dn, attribute, value, oC))
    return entry


def sanitizeBooleanSyntax(dn,entry,attr,self):
    """
    korrigiert Wert eines Attributes vom Typ Boolean wie z.B. HPSAagent
    """	

    TRUE = "TRUE"; FALSE = "FALSE"
    ret = ""
    for k in entry[attr]:
        b = normalizeStringCaseless(k)
        if b == TRUE.casefold():
            ret += TRUE
        elif b == FALSE.casefold():
            ret += FALSE
        if b != k:
            self.logger.write("[SANITIZE BOOLEAN] Bei dn=\"{}\" wurde der Boolean-Wert des Attributes {} korrigiert: \"{}\" => \"{}\"\n".format(dn, attr, k, b))
    return ret


PrintableStringExtraChars = [ " ","'","(",")","+",",","-",".","/",":","=","?" ]	# laut ASN1
PrintableString = list(string.ascii_lowercase) + list(string.ascii_uppercase) + list(range(1,10)) + PrintableStringExtraChars

def sanitizePrintableStringSyntax(dn,entry,attr,self):
    """
    löscht Character aus dem Wert eines Attributes, die nicht der PrintableString Syntax entsprechen
    wie z.B. '%' aus destinationIndicator
    """	
    ret = ""
    for k in entry[attr]:
        a = ""
        for i in range(len(k)):
            if k[i] in PrintableString:
                a += k[i]
        ret += a
        if a != k:
            self.logger.write("[SANITIZE PrintableString] Bei dn=\"{}\" ergab das Matching von \"{}: {}\" gegen PrintableString \"{}\"\n".format(dn, attr, k, a))
    return ret


def sanitizeCharset(dn,entry,attr,self):
    """
    konvertiert non-UTF-8-Character im Wert eines Attributes
    unidecode Library übersetzt nach allen, nur nicht nach deutschen Regeln, weil z.B. Ä in anderen Sprachen ein eigener Buchstabe ist
    """	
#    international = { ord('é'):'e', ord('è'):'e', ord('ó'):'o', ord('ò'):'o', ord('á'):'a', ord('à'):'a', ord('â'):'a', ord('ä'):'ae', ord('ö'):'oe', ord('ü'):'ue', ord('ó'):'o', ord('ò'):'o', ord('á'):'a', ord('à'):'a', ord('â'):'a', ord('ß'):'ss' }
    diacritics = { ord('ä'):'ae', ord('ö'):'oe', ord('ü'):'ue', ord('Ä'):'Ae', ord('Ö'):'Oe', ord('Ü'):'Ue', ord('ß'):'ss' }
    
    ret = ""
    for k in entry[attr]:
        a = unidecode(k.translate(diacritics))
        if a != k:
            self.logger.write("[SANITIZE] Bei dn=\"{}\" wurden Zeichensatzfehler im Attribut \"{}\" von \"{}\" auf \"{}\" korrigiert\n".format(dn, attr, k, a))
        ret += a 
    return ret


sanitizeCases = { "destinationIndicator":sanitizePrintableStringSyntax, "gecos":sanitizeCharset, "HPSAagent":sanitizeBooleanSyntax, "HPOAactive":sanitizeBooleanSyntax, "NSShostsUseLDAP":sanitizeBooleanSyntax, "followReferrals":sanitizeBooleanSyntax }

def sanitizeEntry(dn, entry, self):
    """
    prüft ob alle Attribute eines Entrys in einer Liste von bekannten Fehlerfällen auftaucht und löscht/ersetzt ggfs. Character
    Kann man sicherlich (mit wesentlich mehr Aufwand) generalisieren, hier beschränkt sich die Behandlung auf eine
    hard-kodierte Logik abhängig vom Attribut, um "bekannte" Fehlerfälle zu korrigieren
    """
    for a in entry.keys():
        if a in sanitizeCases:
            sanitizer = sanitizeCases[a]
            entry[a] = [sanitizer(dn,entry,a,self)]
    return entry


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
    return v
 
def modifyEntryValues(func, entry):
    '''
    Nimmt einen Entry entgegen und wendet die übergebende Funktion func auf alle Values im Entry an
    '''
    for k,v in entry.items():
        try:
            entry[k] = list(map(func,v))
        except Exception:
            pass

def modifyAttributeNames(func, entry):
    '''
    Nimmt einen Entry entgegen und wendet die übergebende Funktion func auf alle Attributnamen im Entry an
    um z.B. serverspezifische Daten wie z.B. "objectClass;vucsn-5d5b850f000000cb0000: dtPasswordManagement"
    in allgemeingültige (ohne CSN etc) zu konvertieren.
    '''
    changed = dict(entry)
    for k in entry.keys():
        if ";" in k:
            new_attribute=func(k,";")
            if new_attribute not in changed: changed[new_attribute] = []
            changed[new_attribute] += entry[k]
            del changed[k]
    return changed 

def deleteOperationalAttributes(entry, operational_attributes):
    '''
    Nimmt einen Entry entgegen und löscht alle Attribute, die in OPERATIONAL_ATTRIBUTES gelistet sind
    '''
    changed = dict(entry)
    for k in entry.keys():
        if k in operational_attributes:
            del changed[k]
    return changed

def deleteEmptyAttributes(entry):
    '''
    Nimmt einen Entry entgegen und löscht alle Attribute, die kein value haben (bzw. z.B. von der Form "attribut;.....;deleted:" sind)
    '''
    changed = dict(entry)
    for k,v in entry.items():
        changed[k] = [x for x in v if x != ""]
    entry = dict(changed)
    for k,v in entry.items():
        if not v:
            del changed[k]
    return changed

def reencode(self, dn,entry,debug):
    '''
    encoded explizit alle verbliebenen str-values eines entry nach bytes
    wird nach einer exception in unparse() aufgerufen, 
    '''
    changed = dict(entry)
    if debug: print(dn,entry)
    for k,v in entry.items():
        for l in range(0, len(v)):
            if (isinstance(entry[k][l],str)):
                if debug:
                    print("problematisches Element",l,"ist",type(entry[k][l]),"  value=X",entry[k][l],"X")
                changed[k][l] = changed[k][l].encode()
                self.decodeError += 1
                if debug:
                    print("Korrigiertes    Element",l,"ist",type(changed[k][l]),"value=X",entry[k][l],"X")
                self.logger.write("[DECODEERROR] Es wurde Element {} = {} bei dn={} erneut encodiert\n".format(l,entry[k][l],dn))
    return changed

class StructuralLDIFParser(LDIFParser):
    def __init__(self, inputFile, outputFile, logFile):
        LDIFParser.__init__(self,inputFile)

        self.count = 0
        self.missingStructurals = 0
        self.countnonStructurals = 0
        self.multipleStructurals = 0
        self.decodeError = 0
        self.unmapped = 0
        self.writer = LDIFWriter(outputFile)
        self.logger = logFile
        self.nonStructuralCandidates = {"top"}

        self.ALL_STRUCTURALS = getStructurals()

    def handle(self, dn, entry):
        '''
        parset alle Entries im inputFile
        '''
        self.count+=1
        # Konvertiert alle Objektattributseinträge von byte arrays zu Strings damit Stringoperationen normal durchgeführt werden können
        if DEBUG: print("vor Decoding byte arrays nach Strings:", entry,"\n")
        modifyEntryValues(lambda x: x.decode(), entry)


        # bedient sich austauschbarer Funktion (hier: löscht CSN aus Attributensname)
        if DEBUG: print("vor modifyAttributeNames:",entry,"\n")
        entry = modifyAttributeNames(deleteCSN, entry)

        # löscht leere Attribute (können von der Form "attribut;.....;deleted:" sein)
        if DEBUG: print("vor deleteEmptyAttributes:",entry,"\n")
        entry = deleteEmptyAttributes(entry)

        # löscht operational Attribute des DSEE
        # wichtig: erst NACH Vereinheitlichung des Attributnamens aufrufen
        if DEBUG: print("vor delete operational:",entry,"\n")
        entry = deleteOperationalAttributes(entry, getOperationals())

        # löscht weitere (operational, aber nicht DSEE-spezifische) Attribute
        if DEBUG: print("nach delete operational:",entry,"\n")
        entry = deleteOperationalAttributes(entry, getAttributesToBeDeleted())

        # bereinigt Attributswerte gemäß hardkodierter Logik
        if DEBUG: print("vor sanitizeEntry:",entry,"\n")
        entry = sanitizeEntry(dn, entry, self)

        # ergänzt falls musthave Attribute fehlen das Attribut mit DummyValue 
        if DEBUG: print("vor sanitizeObjectClasses:", entry,"\n")
        entry = sanitizeObjectClasses(dn, entry, OC_ATTR_DEPENDENCY, self)

        # fügt allen Einträgen ohne STRUCTURAL objectClass eine solche hinzu
        # muss NACH sanitizeObjectClasses laufen, da dortdrin ggfs. die letzte STRUCTURAL Klasse gelöscht wird
        if DEBUG: print("vor addMissingStructural:", entry,"\n")
        if (sharedClasses(entry, self.ALL_STRUCTURALS) == 0):
            self.addMissingStructural(dn, entry)
        # ersetzt 2 STRUCTURAL objectClasses durch 2 andere (siehe Mapping in STRUCTURAL_OBJECTCLASS_MAPPING)
        if DEBUG: print("vor reduceMultipleStructural:", entry,"\n")
        if (sharedClasses(entry, self.ALL_STRUCTURALS) == 2):
            self.reduceMultipleStructural(dn, entry)

        # Konvertiert alle Objektattributseinträge zurück zu Byte-Literalen damit das Unparsen durch LDIFWriter funktioniert
        if DEBUG: print("vor Re-Encoding Strings nach bytes:", entry,"\n")
        modifyEntryValues(lambda x: x.encode("utf-8"), entry)

        try:
            self.writer.unparse(dn, entry)
        except Exception:
            # ist das Problem immer das Element[0]?? Haben wir einen off-by-one-Fehler?
            entry = reencode(self, dn, entry, False)
#            print("--------------------------------------------------------------------------------------------------------------")
#            entry = reencode(self, dn, entry, True)
#            print("--------------------------------------------------------------------------------------------------------------")
#            print("--------------------------------------------------------------------------------------------------------------")

#        except UnicodeDecodeError:
#            self.decodeError +=1
#            self.logger.write("[DECODEERROR] UnicodeDecodeError bei dn={}\n{}".format(dn,entry))

        finally:
            print("Analysiert: {} Missing Struct: {} Multiple Struct {} De/EncodeError {} Unmapped {} \r".format(self.count,self.missingStructurals, self.multipleStructurals, self.decodeError, self.unmapped),end="")
            pass

    def addMissingStructural(self, dn, entry):
        '''
        Fehlerfall: Record hat kein Structural als Oberklasse
        Es wird ein vordefiniertes Default Structural ergänzt
        '''
        try:
            before=set(self.nonStructuralCandidates)
            self.nonStructuralCandidates.update(entry["objectClass"])
            if (self.nonStructuralCandidates != before):
                self.countnonStructurals = len(self.nonStructuralCandidates)
#                print("{} objectClasses in entries ohne STRUCTRAL objectClass: {}".format(self.countnonStructurals,self.nonStructuralCandidates))
            self.logger.write("[NEWOC] Es wurde ein Default-Structural bei dn={} mit den objectClasses {} ergänzt\n".format(dn,entry["objectClass"]))
            entry["objectClass"].append(DEFAULT_STRUCTURAL)
            self.missingStructurals += 1
        except KeyError:
            entry["objectClass"] = [DEFAULT_STRUCTURAL]
            self.logger.write("[NOOC] Es ist gar keine Objectclass bei dn={} vorhanden\n".format(dn))

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
    print("------------------------------------------------------------------------------------------------------------------")
    parser.parse()
    print("\n")
#    print("------------------------------------------------------------------------------------------------------------------")
#    print("Alle STRUCTURAL objectClasses:\n{}".format(parser.ALL_STRUCTURALS))
#    print("------------------------------------------------------------------------------------------------------------------")
#    print("Alle objectClasses, die in Einträgen ohne STRUCTURAL objectClass vorkommen:\n{}".format(parser.nonStructuralCandidates))
#    print("------------------------------------------------------------------------------------------------------------------")



# Art und Anzahl Einträge, die keine STRUCTURAL objectClass haben:
# grep NEWOC /tmp/logfile | cut -d' ' -f11-|sort |uniq -c

