Windows-Netzwerkdiagnose fuer Forever 70450

1. ZIP entpacken. WoW normal schliessen; den normalen Forever Launcher offen lassen.
2. Start-Network-Diagnostics.cmd doppelklicken. Die Windows-Adminabfrage gilt nur
   fuer den Collector, nicht fuer den Launcher oder das Spiel.
3. Wenn "JETZT ... Play" erscheint, im normalen Launcher Play klicken.
4. Das Diagnosefenster 90 Sekunden offen lassen. Danach die angezeigte
   Forever-Network-....zip vom Desktop im Chat hochladen.

Der Collector aendert weder Spieldateien noch Agent-, Server- oder Netzwerkeinstellungen.
Er startet zwei eigene, eindeutig benannte ETW-Sitzungen und stoppt nur diese.
Er sammelt systemweite Winsock-/DNS-Metadaten (auch anderer Programme), keine
Pakete, HTTP-Inhalte, Registrywerte, Passwoerter oder Prozessumgebungen.
Andere Programme moeglichst schliessen. Die erzeugte ZIP vor Weitergabe pruefen.
Die binaeren ETL-Dateien bleiben lokal; nur XML, Zusammenfassung, Kontroll- und
Zeit/PID-Marker werden in die ZIP aufgenommen. Jede ETL ist auf 8 MiB begrenzt
und kann alte Ereignisse ueberschreiben. Fehlende Ereignisse beweisen daher
allein keinen fehlenden Verbindungsversuch. summary.txt auf verlorene Events pruefen.

Technik: Windows PowerShell 5.1, logman, tracerpt und Get-WinEvent (Windows-Bordmittel).
AFD und DNS-Client werden auf Information-Level 4 aufgezeichnet.
SelfTest muss administrativ laufen, erzeugt eine erfolgreiche und eine abgelehnte
Loopback-Verbindung, loest localhost auf und verlangt tatsaechlich dekodierte
AFD-Socket-/Connect-/Completion-Ereignisse des Testprozesses. Kein WoW erforderlich.

Quellen:
https://learn.microsoft.com/en-us/windows/win32/winsock/control-of-winsock-tracing
https://learn.microsoft.com/en-us/windows/win32/winsock/winsock-tracing-levels
https://learn.microsoft.com/en-us/windows/win32/winsock/winsock-tracing-event-details
https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/logman-create-trace
https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/tracerpt
