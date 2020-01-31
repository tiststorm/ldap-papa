# Imports:
```
python-ldap
sys
getopt
```

# Benutzung:
```
python structural-fix.py -i <input-Datei> -o <output-Datei> -l <log-Datei>
```
Log-Datei dokumentiert alle Änderungen, zum einfachen Suchen werden die Einträge folgendermaßen markiert:
1. [NEWMAPPING] mehrere Structurals erfolgreich umgemappt
2. [UNMAPPED] mehrere Structurals, aber kein zutreffendes Mapping gefunden
3. [DECODEERROR] Fehler beim Umwandeln des Objekts in Text
4. [NEWOC] kein Structural vorhanden, neues Structural ergänzt
5. [NOOC] keinerlei Objectclass vorhanden (sollte nicht vorkommen)
