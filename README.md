# System Administrator
*Useful commands for a Windows Sysadmin*


### 🔹 **Informazioni di Sistema**

- `systeminfo` → Mostra dettagli sul sistema operativo, hardware e aggiornamenti.
- `winver` → Ottieni info sul sistema operativo.
- `hostname` → Mostra il nome del computer.
- `whoami` → Mostra l'utente corrente.
- `echo %username%` → Mostra il nome dell’utente loggato.
- `tasklist` → Elenca i processi in esecuzione.
- `taskkill /F /PID <PID>` → Termina un processo per ID.
- `taskkill /IM <nomeprocesso>.exe /F` → Termina un processo per nome.
- `msinfo32` → Apre le informazioni di sistema avanzate.
- `w32tm /query /source` → Mostra la sorgente dell'ora attuale del PC.
- `w32tm /config /syncfromflags:DOMHIER /update` → Configura la sincronizzazione con la gerarchia del dominio.
- `net stop w32time` → Arresta il servizio Ora di Windows.
- `net start w32time` → Avvia il servizio Ora di Windows.
- `w32tm /resync /nowait` → Forza la risincronizzazione immediata dell'orologio.
- `w32tm /query /status` → Verifica lo stato attuale della sincronizzazione dell'ora.

Con ***powershell***:

- `Rename-Computer -NewName "<Nome>" -Restart` → Rinomina il computer e riavvia il sistema per applicare le modifiche.

---

### 🔹 **Gestione Utenti e Gruppi**

- `net user` → Mostra tutti gli utenti locali.
- `net user <utente>` → Mostra dettagli su un utente.
- `net user <utente> <password> /add` → Crea un nuovo utente.
- `net user <utente> /delete` → Cancella un utente.
- `net localgroup Administrators` → Mostra gli utenti nel gruppo Administrators.
- `net localgroup Administrators <utente> /add` → Aggiunge un utente agli amministratori.
- `net localgroup Administrators <utente> /delete` → Rimuove un utente dagli amministratori.
- `net user <utente> NuovaPassword` → Cambia la password dell'account specificato.
- `net user <utente> /active:yes` → Attiva l'account se è disabilitato.
- `net user <utente> /active:no` → Disattiva l'account.
- `runas /user:<utente> cmd` → Esegue un prompt dei comandi come l'utente specificato.

---

### 🔹 **Gestione Rete**

- `ipconfig` → Mostra la configurazione di rete.
- `ipconfig /all` → Mostra dettagli avanzati sulla rete.
- `ipconfig /release` → Rilascia l’IP attuale.
- `ipconfig /renew` → Richiede un nuovo IP dal DHCP.
- `ipconfig /flushdns` → Svuota la cache DNS.
- `ipconfig /displaydns` → Mostra la cache DNS.
- `getmac` → Visualizza l'indirizzo MAC delle schede di rete del sistema.
- `ping <indirizzo>` → Verifica la connettività con un host.
- `tracert <indirizzo>` → Mostra il percorso dei pacchetti fino all’host.
- `pathping <indirizzo_IP>` → Combina le funzionalità di `ping` e `tracert` per analizzare il percorso e la qualità della connessione verso un host.
- `nslookup <dominio>` → Ottiene info DNS su un dominio.
- `netstat -ano` → Mostra connessioni di rete attive e processi associati.
- `netsh wlan show profiles` → Mostra le reti Wi-Fi salvate.
- `netsh wlan show profile <SSID> key=clear` → Mostra password di una rete Wi-Fi salvata.
- `netsh wlan export profile key=clear` → Esporta le info sulle reti Wi-FI salvate.
- `route print` → Mostra la tabella di routing locale.
- `arp -a` → Mostra la cache ARP della rete locale.
- `net use \\<server>\<share>` → Connette una cartella di rete.
- `net use \\<server>\<share> /delete` → Disconnette una cartella di rete.
- `route -p add <RETE_DESTINAZIONE> mask <MASCHERA> <GATEWAY> (metric <METRICA>)` → Aggiunge una route permanente (metrica opzionale) in locale.
- `route add 10.0.0.0 mask 255.0.0.0 192.168.2.1` → Esempio di route per connettersi a una rete diversa.
- `netsh interface ip set address name="<Nome Scheda>" static <IP> <Subnet Mask> <Gateway>` → Imposta un indirizzo IP statico su una scheda di rete specifica.

---

### 🔹 **Gestione Disco e File System**

- `diskpart` → Apre il tool per la gestione dei dischi.
- `chkdsk /f` → Controlla e corregge errori nel file system.
- `chkdsk /r` → Controlla e tenta di recuperare settori danneggiati.
- `sfc /scannow` → Controlla e ripara file di sistema corrotti.
- `format <lettera>: /FS:NTFS` → Formatta un disco in NTFS.
- `fsutil fsinfo drives` → Mostra le unità disponibili.
- `fsutil dirty query <unità>:` → Verifica se un volume ha errori.
- `cipher /w:<percorso>` → Cancella in modo sicuro i dati eliminati.
- `attrib +h +s +r <file>` → Nasconde e protegge un file.
- `attrib -h -s -r <file>` → Rende visibile un file nascosto.

---

### 🔹 **Gestione File e Cartelle**

- `mklink <Link> <Destinazione>` → Crea un collegamento simbolico a un file.
- `mklink /D <Link> <Destinazione>` → Crea un collegamento simbolico a una cartella.
- `mklink /H <Link> <Destinazione>` → Crea un hard link a un file.
- `mklink /J <Link> <Destinazione>` → Crea un collegamento simbolico di tipo "Junction" per le cartelle.
- `move <sorgente> <destinazione>` → Sposta un file o una cartella in un'altra posizione.
- `xcopy <sorgente> <destinazione> /E /I /Y` → Copia file e cartelle, inclusi i sottodirectory, e sovrascrive senza chiedere conferma.
- `robocopy <sorgente> <destinazione> /MIR /R:3 /W:5` → Copia file e cartelle, mantenendo la struttura e riprovando in caso di errore (R:3 = 3 tentativi, W:5 = attesa di 5 sec).
- `del <file>` → Cancella un file.
- `del /F <file>` → Forza l'eliminazione di un file.
- `del /S <file>` → Cancella un file in tutte le sottodirectory.
- `del /Q <file>` → Cancella un file senza chiedere conferma.
- `del /F /Q /A <file>` → Cancella un file nascosto o di sola lettura senza conferma.
- `rmdir <cartella>` → Cancella una cartella vuota.
- `rmdir /S <cartella>` → Cancella una cartella e tutti i suoi contenuti.
- `rmdir /S /Q <cartella>` → Cancella una cartella e tutti i suoi contenuti senza conferma.
- `erase <file>` → Alternativa a `del`, elimina un file.
- `erase /F /Q <file>` → Cancella un file nascosto o protetto senza conferma.
- `tree <directory>` → Visualizza graficamente la struttura delle cartelle di una directory.

---

### 🔹 **Gestione Servizi**

- `sc query` → Elenca tutti i servizi.
- `sc query <nomeservizio>` → Controlla lo stato di un servizio.
- `net start <nomeservizio>` → Avvia un servizio.
- `net stop <nomeservizio>` → Ferma un servizio.
- `sc config <nomeservizio> start= auto` → Imposta un servizio su avvio automatico.
- `sc config <nomeservizio> start= disabled` → Disabilita un servizio.

---

### 🔹 **Gestione Processi e Prestazioni**

- `tasklist` → Mostra i processi in esecuzione.
- `taskkill /F /PID <PID>` → Termina un processo.
- `wmic process where name="explorer.exe" call terminate` → Termina il processo Explorer.
- `resmon` → Apre il Resource Monitor.
- `perfmon` → Apre il Performance Monitor.

---

### 🔹 **Gestione Stampanti**

- `wmic printer list brief` → Elenca le stampanti installate.
- `wmic printer get name,default` → Mostra la stampante predefinita.
- `wmic printer where name="Stampante" call setdefaultprinter` → Imposta la stampante predefinita.
- `net start spooler` → Avvia il servizio di stampa.
- `net stop spooler` → Ferma il servizio di stampa.
- `del /Q /F /S "%systemroot%\System32\spool\PRINTERS\*.*"` → Cancella la coda di stampa.

Con ***powershell***:

- `Get-Printer` → Elenca tutte le stampanti installate sul sistema.
- `Get-Printer | Select-Object -Property Name` → Mostra i nomi completi delle stampanti senza troncature.
- `Get-Printer | Format-Table -Wrap -AutoSize` → Visualizza tutte le informazioni senza tagli di testo.
- `(Get-Printer -Name "Stampante") | Set-Printer -IsDefault $true` → Imposta la stampante predefinita.

---

### 🔹 **Backup e Ripristino**

- `wbadmin start backup -backupTarget:D: -include:C: -allCritical -quiet` → Avvia un backup di sistema.
- `wbadmin get versions` → Mostra le versioni dei backup disponibili.
- `wbadmin start recovery -version:<ID>` → Avvia il ripristino di un backup specifico.
- `rstrui` → Avvia il Ripristino Configurazione di Sistema.

---

### 🔹 **Gestione Boot e Riparazione Avvio**

- `bcdedit` → Visualizza e modifica il bootloader.
- `bcdedit /set {current} safeboot minimal` → Imposta l'avvio in modalità provvisoria.
- `bcdedit /deletevalue {current} safeboot` → Rimuove l'avvio in modalità provvisoria.
- `bootrec /fixmbr` → Ripara il Master Boot Record (MBR).
- `bootrec /fixboot` → Ripara il settore di avvio.
- `bootrec /rebuildbcd` → Ricostruisce la configurazione del bootloader.

---

### 🔹 **Registri di Windows**

- `reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Run` → Mostra programmi in avvio automatico.
- `reg add HKLM\Software\Microsoft\Windows\CurrentVersion\Run /v NomeApp /t REG_SZ /d "C:\Path\App.exe"` → Aggiunge un programma all'avvio.
- `reg delete HKLM\Software\Microsoft\Windows\CurrentVersion\Run /v NomeApp /f` → Rimuove un programma dall’avvio.

---

### 🔹 **Gestione Windows Update**

- `wuauclt /detectnow` → Forza la ricerca di aggiornamenti.
- `wuauclt /reportnow` → Forza l'invio del report degli aggiornamenti.
- `wuauclt /updatenow` → Forza l'installazione degli aggiornamenti.
- `sconfig` → Apre il menu di configurazione avanzata del server (Windows Server).
- `powershell Get-WindowsUpdateLog` → Mostra il log degli aggiornamenti.

---

### 🔹 **Gestione Permessi e Sicurezza**

- `icacls <file/cartella>` → Mostra i permessi di un file o cartella.
- `icacls <file/cartella> /grant <utente>:F` → Concede il controllo completo a un utente.
- `icacls <file/cartella> /remove <utente>` → Rimuove i permessi di un utente.
- `takeown /F <file/cartella>` → Prende la proprietà di un file o cartella.
- `gpupdate /force` → Forza l'aggiornamento dei criteri di gruppo.
- `gpresult /R` → Mostra i criteri di gruppo applicati.
- `secedit /analyze /cfg <config>` → Analizza la sicurezza del sistema.
- `secedit /configure /db c:\windows\security\local.sdb /cfg c:\windows\security\templates\defltbase.inf /areas SECURITYPOLICY` → Reimposta le policy di sicurezza predefinite.

---

### 🔹 **Gestione Eventi e Log di Sistema**

- `eventvwr` → Apre il Visualizzatore Eventi.
- `wevtutil qe System /c:5 /f:text` → Mostra gli ultimi 5 eventi del registro di sistema.
- `wevtutil cl Application` → Cancella il registro degli eventi dell'applicazione.
- `wevtutil el` → Elenca tutti i registri eventi disponibili.

---

### 🔹 **Gestione e Diagnosi Hardware**

- `dxdiag` → Apre lo strumento di diagnostica DirectX.
- `powercfg /batteryreport` → Genera un report dettagliato della batteria (su laptop).
- `powercfg /energy` → Analizza i consumi energetici e genera un report.
- `driverquery` → Mostra tutti i driver installati.
- `driverquery /v` → Mostra dettagli avanzati sui driver installati.
- `devmgmt.msc` → Apre Gestione Dispositivi.
- `set devmgr_show_nonpresent_devices=1 && devmgmt.msc` → Mostra dispositivi non più connessi.

---

### 🔹 **Gestione Processi e Debugging**

- `wmic process list brief` → Mostra i processi in esecuzione con dettagli minimi.
- `wmic process where "name='explorer.exe'" delete` → Termina Explorer.exe.
- `wmic process call create "notepad.exe"` → Avvia un processo.
- `wmic startup get caption,command` → Mostra i programmi in avvio automatico.
- `taskkill /T /F /PID <PID>` → Termina un processo e tutti i sottoprocessi.

Con ***powershell***:

- `Get-Process | Select-Object ProcessName, Id, CPU, Path` → Mostra i processi in esecuzione con dettagli minimi.
- `Stop-Process -Name "explorer" -Force` → Termina il processo `explorer.exe`.
- `Start-Process "notepad.exe"` → Avvia un nuovo processo (`notepad.exe`).
- `Get-CimInstance Win32_StartupCommand | Select-Object Name, Command` → Mostra i programmi in avvio automatico.

---

### 🔹 **Gestione Sessioni e Terminal Services**

- `query user` → Mostra gli utenti connessi al sistema.
- `logoff <sessionID>` → Disconnette un utente da una sessione.
- `query session` → Elenca le sessioni attive su un server.
- `qwinsta` → Mostra le sessioni attive in un terminal server.
- `rwinsta <sessionID>` → Disconnette una sessione RDP.

---

### 🔹 **Gestione Backup e Ripristino Avanzato**

- `robocopy <origine> <destinazione> /MIR /SEC /LOG:backup.log` → Esegue un backup con mirroring e mantiene i permessi.
- `vssadmin list shadows` → Elenca i punti di ripristino.
- `vssadmin delete shadows /all` → Cancella tutti i punti di ripristino.
- `reagentc /info` → Mostra lo stato dell'ambiente di ripristino.
- `reagentc /enable` → Abilita l'ambiente di ripristino di Windows.

---

### 🔹 **Gestione Server e Active Directory (AD)**

- `dsquery user` → Elenca tutti gli utenti di Active Directory.
- `dsquery group` → Elenca tutti i gruppi di Active Directory.
- `dsquery computer` → Elenca tutti i computer registrati in AD.
- `dsadd user "CN=utente,CN=Users,DC=dominio,DC=com" -pwd password123` → Aggiunge un utente in AD.
- `dsmod user "CN=utente,CN=Users,DC=dominio,DC=com" -pwd nuovoPassword` → Modifica la password di un utente.
- `dsrm "CN=utente,CN=Users,DC=dominio,DC=com"` → Rimuove un utente da AD.
- `Add-Computer -DomainName "<Domain>" -Credential "<Domain\User>" -Restart` → Aggiunge il computer al dominio e richiede credenziali di amministrazione.

---

### 🔹 **Diagnosi Avanzata e Modalità Provvisoria**

- `bcdedit /set {default} safeboot minimal` → Imposta l'avvio in modalità provvisoria.
- `bcdedit /deletevalue {default} safeboot` → Rimuove la modalità provvisoria.
- `recimg /createimage D:\RecoveryImage` → Crea un'immagine di ripristino personalizzata.
- `recimg /setcurrent D:\RecoveryImage` → Imposta un’immagine di ripristino personalizzata.

---

### 🔹 **Gestione Servizi Remoti**

- `sc \\remotecomputer query` → Controlla i servizi su un computer remoto.
- `sc \\remotecomputer stop <servizio>` → Ferma un servizio su un PC remoto.
- `sc \\remotecomputer start <servizio>` → Avvia un servizio su un PC remoto.

---

### 🔹 **Gestione DNS e Dominio**

- `ipconfig /registerdns` → Registra manualmente il DNS del computer.
- `nslookup -type=MX <dominio>` → Mostra i record MX di un dominio.
- `nltest /dsgetdc:<dominio>` → Trova un domain controller.
- `nltest /dclist:<dominio>` → Elenca tutti i domain controller disponibili.

---

### 🔹 **Gestione Condivisioni di Rete**

- `net share` → Mostra le cartelle condivise.
- `net share <nomeshare>=C:\cartella /grant:Everyone,FULL` → Condivide una cartella con accesso completo a tutti.
- `net share <nomeshare> /delete` → Elimina una condivisione di rete.

---

### 🔹 **Diagnosi e Ripristino di File di Sistema**

- `DISM /Online /Cleanup-Image /CheckHealth` → Controlla l'integrità dei file di sistema.
- `DISM /Online /Cleanup-Image /ScanHealth` → Controlla in modo più approfondito l'integrità dei file di sistema.
- `DISM /Online /Cleanup-Image /RestoreHealth` → Ripara file di sistema corrotti usando i file di Windows Update.
- `sfc /scannow` → Controlla e ripara i file di sistema danneggiati.

---

### 🔹 **Gestione del Firewall di Windows**

- `netsh advfirewall show allprofiles` → Mostra lo stato del firewall.
- `netsh advfirewall set allprofiles state off` → Disattiva il firewall.
- `netsh advfirewall set allprofiles state on` → Attiva il firewall.
- `netsh advfirewall firewall add rule name="Apertura porta 3389" dir=in action=allow protocol=TCP localport=3389` → Apre la porta 3389 (RDP).

---

### 🔹 **Connessione Desktop Remoto (RDP)**

- `mstsc /v:<IP_o_Nome_PC>` → Avvia una sessione di Desktop Remoto (RDP) con il PC remoto.
- `mstsc /admin /v:<IP_o_Nome_PC>` → Connessione alla sessione amministrativa del PC remoto.
- `mstsc /f /v:<IP_o_Nome_PC>` → Avvia la sessione in modalità schermo intero.
- `mstsc /multimon /v:<IP_o_Nome_PC>` → Abilita l'uso di più monitor nella sessione remota.
- `mstsc /save:connessione.rdp` → Salva le impostazioni di connessione in un file `.rdp`.

---

### 🔹 **PowerShell Remoto (WinRM)**

- `powershell Enter-PSSession -ComputerName <NomePC>` → Avvia una sessione PowerShell sul PC remoto.
- `powershell Invoke-Command -ComputerName <NomePC> -ScriptBlock {Get-Process}` → Esegue un comando su un PC remoto.
- `winrm quickconfig` → Abilita e configura il servizio WinRM (necessario per il remote management).

---

### 🔹 **Esecuzione di Comandi Remoti con PsExec**

- `psexec \\<NomePC> -u <Utente> -p <Password> cmd` → Apre un prompt dei comandi remoto.
- `psexec \\<NomePC> -u <Utente> -p <Password> ipconfig` → Esegue un comando specifico sul PC remoto.
- `psexec \\<NomePC> -u <Utente> -p <Password> shutdown -r -t 0` → Riavvia il PC remoto immediatamente.

---

### 🔹 **Connessione SSH a un PC Remoto**

- `ssh <utente>@<IP_o_NomePC>` → Connessione SSH al PC remoto.
- `ssh -p <porta> <utente>@<IP>` → Connessione SSH specificando una porta diversa da 22.

 Il PC remoto deve avere un **server SSH attivo**. Su Windows si può installare con:

```powershell
Get-WindowsFeature -Name OpenSSH-Server | Install-WindowsFeature
```

---

### 🔹 **Accesso a Cartelle Condivise con `net use`**

- `net use Z: \\<IP_PC_Remoto>\Cartella /user:<utente> <password>` → Mappa una cartella di rete su un'unità locale.
- `net use Z: /delete` → Disconnette l'unità di rete mappata.
- `net view \\<IP_PC_Remoto>` → Mostra le cartelle condivise su un PC remoto.

---

### 🔹 **Gestione del Firewall per Connessioni Remote**

- `netsh advfirewall firewall add rule name="Apertura porta 3389" dir=in action=allow protocol=TCP localport=3389` → Apre la porta **3389** per Desktop Remoto.
- `netsh advfirewall firewall add rule name="Abilita WinRM" dir=in action=allow protocol=TCP localport=5985` → Apre la porta per WinRM (PowerShell Remoto).
- `netsh advfirewall set allprofiles state off` → Disattiva il firewall (⚠ pericoloso!).
- `netsh advfirewall set allprofiles state on` → Riattiva il firewall.

---

### 🔹 **Controllo di PC Remoti in Rete**

- `ping <IP_PC_Remoto>` → Verifica se il PC remoto è raggiungibile.
- `tracert <IP_PC_Remoto>` → Mostra il percorso della rete verso il PC remoto.
- `nslookup <NomePC>` → Risolve il nome del PC in un indirizzo IP.
- `tasklist /s <IP_PC_Remoto> /u <Utente> /p <Password>` → Elenca i processi in esecuzione su un PC remoto.
- `shutdown /s /m \\<IP_PC_Remoto> /t 0` → Spegne un PC remoto.
- `shutdown /r /m \\<IP_PC_Remoto> /t 0` → Riavvia un PC remoto.

---

### 🔹 Utilities

- `dir /s /a:-d /b | find /c /v ""` → Conta il numero di file in una cartella e nelle sottocartelle.
- `certutil -hashfile "C:\percorso\file.txt" SHA256` → Genera l'hash SHA256 di un file.
- `fc hash1.txt hash2.txt` → Confronta il contenuto di due file di testo (txt, csv, log).
- `fc /B hash1.txt hash2.txt` → Confronta due file in modalità binaria (per qualsiasi tipo di file).
- `schtasks /create /tn "<Nome_Task>" /tr "<Percorso_Script>" /sc daily /st 09:00` → Crea un'attività pianificata che esegue uno script ogni giorno alle 9:00.
- `control` → Apre il **Pannello di Controllo**.
- `netplwiz` → Gestisce gli **Account Utente** e l'accesso automatico.
- `msconfig` → Apre la **Configurazione di sistema** per gestire l'avvio e i servizi.
- `mstsc` → Avvia la **Connessione Desktop Remoto**.
- `control netconnections` → Apre le **Connessioni di rete**.
- `secpol.msc` → Apre i **Criteri di sicurezza locali** (Local Security Policy).
- `control printers` → Apre il menu **Dispositivi e Stampanti**.
- `regedit` → Avvia l’**Editor del Registro di Sistema**.
- `osk` → Avvia la **Tastiera su schermo**.
- `eventvwr` → Apre il **Visualizzatore eventi** per consultare i log di sistema.
- `lusrmgr.msc` → Apre **Utenti e gruppi locali** (solo su edizioni Pro/Enterprise di Windows).
- `findstr /i "errore" C:\path\to\file.log` → Cerca la parola **"errore"** ignorando la differenza tra maiuscole e minuscole.
- `findstr /b "errore" C:\path\to\file.log` → Cerca la parola **"errore"** solo all'inizio di ogni riga.
- `findstr /v "errore" C:\path\to\file.log` → Mostra le righe che **non contengono** la parola **"errore"**.
- `findstr /n "errore" C:\logs\*.log` → Cerca la parola **"errore"** e mostra il **numero di riga** per ogni risultato trovato.
- `shutdown /r /t 0` → Riavvia il sistema immediatamente (”-t” = time).
- `shutdown /s /t 0` → Arresta il sistema immediatamente (”-t” = time).
