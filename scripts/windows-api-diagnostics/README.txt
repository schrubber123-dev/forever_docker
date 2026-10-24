Forever 70450 - native Socket-Diagnose

1. Diesen ZIP-Inhalt vollstaendig entpacken. EXE und DLL muessen zusammen liegen.
2. WoW schliessen, den normalen Forever Launcher offen lassen.
3. Forever-API-Diagnose.exe doppelklicken; die Windows-Adminabfrage gilt nur fuer
   dieses Diagnoseprogramm. Das Spiel startet weiterhin aus dem normalen Launcher.
4. Bei "JETZT ... Play" im normalen Launcher auf Play klicken.
5. Bis "ZIP erstellt" warten (etwa 60 Sekunden ab erkannter Diagnosebereitschaft).
6. Die neu erzeugte Forever-API-....zip vom Desktop im Chat hochladen.

Diese Diagnose laedt voruebergehend ein eigenes Modul in WowB.exe und protokolliert
Windows-Socketaufrufe, numerische Adressen/Ports, Rueckgabewerte, Fehlercodes und
Aufrufstellen als Moduladressen/RVAs. Die API-Aufrufparameter und Rueckgabewerte
werden nicht absichtlich veraendert. Passwoerter, Tokens, Paket-/Anwendungsinhalte,
Prozessumgebungen oder Registrywerte werden nicht aufgezeichnet.

Dies ist KEIN Login-/Agent-Bypass. Es gibt keinen Versions- oder Produktstatus-Patch.
Der Agent wird nicht injiziert, gestartet oder beendet. Die Spiel-EXE wird nur
versionsgeprueft und gehasht; ihre Datei wird nicht beschrieben. Der Original-Hash
wird vor/nach der Aufzeichnung verglichen. Im lokalen Ausgabeordner liegt zudem
eine hashgepruefte Sicherung unter original-backup; sie wird NIE in die
Ergebnis-ZIP aufgenommen. Kein Blizzard-Programm wird mitgeliefert.

Nur der x64-Client mit FileVersion 1.60.1.70450 wird im normalen Modus akzeptiert.
Der Collector wartet auf einen neuen WowB-Prozess; bitte keine zweite Instanz starten.
Die Hooks werden am Ende deaktiviert, bei verlorenem Collector spaetestens nach
120 Sekunden ab Diagnosebereitschaft. Das Diagnosemodul bleibt aus Gruenden der
Speichersicherheit bis zum normalen Beenden des Spiels geladen. Vor dem naechsten
Versuch WoW schliessen. Die Originaldatei bleibt auf der Festplatte erhalten.

Die Logdateien sind auf 8 MiB begrenzt. Hook-Eintrittspunkte und ihre Bytefenster
vor/waehrend/nach der Diagnose werden auditierbar aufgezeichnet. Stack/RVA-Listen
ersetzen keine Funktionssymbole. ConnectEx-Abdeckung gilt fuer den ermittelten
Windows-Standardprovider; andere Provider oder direkt umgangene APIs koennen
unbeobachtet bleiben. Erfolgs-/Fehlercodes sind nur zusammen mit dem API-Ergebnis
zu interpretieren; nach erfolgreichen Windows-Aufrufen kann last-error veraltet sein.

Die ZIP enthaelt nur socket-<PID>.log und markers.txt. Die diagnostische DLL sowie
sonstige Dateien im lokalen Ausgabeordner werden nicht in die Ergebnis-ZIP gepackt.
Wenn "DIAGNOSEFEHLER" erscheint, dessen Text und eine gegebenenfalls erzeugte
Ergebnis-ZIP senden. Keine Speicherabbilder oder Clientdateien hochladen.

Quellcode: scripts/windows-api-diagnostics/ im Repository schrubber123-dev/forever_docker.
Abhaengigkeit: MinHook v1.3.4, exakt Commit c3fcafdc10146beb5919319d0683e44e3c30d537.
Lizenztexte werden mitgeliefert. diagnostic-build.txt nennt die genaue Quellrevision.
Der Windows-Selbsttest injiziert ausschliesslich einen eigenen Testprozess und
prueft echte Socketaufrufe, ConnectionRefused/InvalidSocket und Last-Error-Erhaltung.
Er beweist keine Fehlerursache oder Kompatibilitaet mit dem eigentlichen Spiel.
