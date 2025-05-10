# Connection - HackMyVM (Easy)

![Connection Icon](Connection.png)

## Übersicht

*   **VM:** Connection
*   **Plattform:** [HackMyVM](https://hackmyvm.eu/machines/machine.php?vm=Connection)
*   **Schwierigkeit:** Easy
*   **Autor der VM:** DarkSpirit
*   **Datum des Writeups:** 30. Oktober 2022
*   **Original-Writeup:** https://alientec1908.github.io/Connection_HackMyVM_Easy/
*   **Autor:** Ben C.

## Kurzbeschreibung

Die virtuelle Maschine "Connection" von HackMyVM (Schwierigkeitsgrad: Easy) wurde durch die Ausnutzung einer fehlkonfigurierten SMB-Freigabe kompromittiert. Anonymer Schreibzugriff auf eine SMB-Share, die mit dem Web-Root-Verzeichnis des Apache-Servers verknüpft war, ermöglichte das Hochladen einer PHP-Reverse-Shell. Nach Erlangung einer Shell als `www-data` wurde eine SUID-gesetzte `gdb`-Binärdatei identifiziert. Diese wurde ausgenutzt, um Root-Rechte auf dem System zu erlangen.

## Disclaimer / Wichtiger Hinweis

Die in diesem Writeup beschriebenen Techniken und Werkzeuge dienen ausschließlich zu Bildungszwecken im Rahmen von legalen Capture-The-Flag (CTF)-Wettbewerben und Penetrationstests auf Systemen, für die eine ausdrückliche Genehmigung vorliegt. Die Anwendung dieser Methoden auf Systeme ohne Erlaubnis ist illegal. Der Autor übernimmt keine Verantwortung für missbräuchliche Verwendung der hier geteilten Informationen. Handeln Sie stets ethisch und verantwortungsbewusst.

## Verwendete Tools

*   `arp-scan`
*   `nmap`
*   `gobuster`
*   `enum4linux`
*   `smbclient`
*   `curl`
*   `nc` (netcat)
*   `python3` (für Shell-Stabilisierung)
*   `stty`
*   Standard Linux-Befehle (`id`, `ls`, `find`, `cat`, `cd`, `sh`, `whoami`)
*   `gdb` (GNU Debugger - als Exploit-Vektor)

## Lösungsweg (Zusammenfassung)

Der Angriff auf die Maschine "Connection" erfolgte in diesen Schritten:

1.  **Reconnaissance:**
    *   Ziel-IP (`192.168.2.114`, Hostname `connection.hmv`) via `arp-scan` und `/etc/hosts` identifiziert.
    *   `nmap` zeigte offene Ports: 22 (SSH 7.9p1), 80 (Apache 2.4.38), 139 (SMB) und 445 (SMB - Samba 4.9.5).
    *   Nmap-Skripte deuteten auf anonymen Gastzugang für SMB und deaktiviertes Message Signing hin.
    *   `gobuster` auf Port 80 fand nur `/index.html`.

2.  **SMB Enumeration:**
    *   `enum4linux -a` bestätigte den anonymen SMB-Zugriff und identifizierte eine zugängliche Share namens `share`. Der lokale Benutzer `connection` wurde ebenfalls gefunden.
    *   Mittels `smbclient //192.168.2.114/share -U %` wurde anonym auf die Share zugegriffen.
    *   Innerhalb der Share wurde ein Verzeichnis `html` gefunden, das eine `index.html` enthielt. Wichtig war, dass **Schreibzugriff** auf dieses Verzeichnis bestand.

3.  **Initial Access (via SMB Upload & Web Shell):**
    *   Eine PHP-Reverse-Shell-Datei (`rev.php`) wurde vorbereitet.
    *   Mittels `smbclient` und dem `put rev.php`-Befehl wurde die Shell-Datei in das Verzeichnis `/share/html/` hochgeladen.
    *   Ein Netcat-Listener wurde auf dem Angreifer-System gestartet.
    *   Durch Aufruf von `http://192.168.2.114/rev.php` mit `curl` wurde die PHP-Shell auf dem Webserver ausgeführt.
    *   Eine Reverse Shell als Benutzer `www-data` wurde erfolgreich etabliert.
    *   Die Shell wurde für bessere Interaktivität stabilisiert.

4.  **Privilege Escalation (www-data zu root via SUID gdb):**
    *   `sudo -l` war für `www-data` nicht verfügbar.
    *   Die Suche nach SUID-Dateien (`find / -perm -4000 ...`) offenbarte, dass `/usr/bin/gdb` (GNU Debugger) SUID-Root gesetzt hatte.
    *   Die User-Flag wurde aus `/home/connection/local.txt` gelesen.
    *   Die SUID-Schwachstelle in `gdb` wurde ausgenutzt:
        `gdb -nx -ex 'python import os; os.execl("/bin/sh", "sh", "-p")' -ex quit`
    *   Dieser Befehl startete eine `/bin/sh`-Shell mit den effektiven Rechten von Root (`euid=0`).
    *   Die Root-Flag wurde aus `/root/proof.txt` gelesen.

## Wichtige Schwachstellen und Konzepte

*   **Anonymer SMB-Schreibzugriff:** Erlaubte das Hochladen einer Webshell in ein Web-Verzeichnis.
*   **Web Shell Execution:** Ausführung der hochgeladenen PHP-Datei über den Webserver.
*   **SUID-Exploitation (`gdb`):** Ausnutzung einer SUID-gesetzten `gdb`-Binärdatei zur Erlangung von Root-Rechten durch Ausführung von Shell-Befehlen innerhalb des Debuggers.
*   **Fehlkonfiguration von Diensten:** Unsichere SMB-Konfiguration war der Schlüssel zum initialen Zugriff.

## Flags

*   **User Flag (`/home/connection/local.txt`):** `3f491443a2a6aa82bc86a3cda8c39617`
*   **Root Flag (`/root/proof.txt`):** `a7c6ea4931ab86fb54c5400204474a39`

## Tags

`HackMyVM`, `Connection`, `Easy`, `SMB`, `Anonymous Write`, `Web Shell`, `PHP`, `SUID`, `gdb`, `Privilege Escalation`, `Linux`
