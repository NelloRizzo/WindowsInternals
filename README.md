# WindowsInternals

Un analizzatore di processi Windows scritto in **C puro**, senza dipendenze esterne. Usa direttamente le Windows API per enumerare processi, ispezionare servizi e scansionare la memoria RAM di qualsiasi processo in esecuzione.

## Funzionalità

- **Lista processi** — enumera tutti i processi attivi con PID, PPID, thread, RAM usata (working set, peak, memoria privata)
- **Filtro per nome** — filtra i processi per prefisso del nome dell'eseguibile
- **Servizi per PID** — mostra tutti i servizi Windows ospitati da un dato processo (utile per analizzare le istanze di `svchost.exe`)
- **Scan della memoria** — scansiona tutto lo spazio di indirizzi di un processo e produce un hex dump delle regioni leggibili
- **Architettura estendibile** — callback personalizzabili per dump, ricerca di pattern, o analisi custom

## Struttura del progetto

```
WindowsInternals/
├── wininternals.h       # Tipi, strutture, macro, prototipi
├── wininternals.c       # Implementazione delle API
├── main.c               # Programma principale e callback
└── Makefile
```

## Requisiti

- Windows 10 o superiore
- MinGW-W64 / GCC oppure MSVC
- `make` (GnuWin32 o equivalente)

## Compilazione

```batch
make
```

Con MSVC:

```batch
cl main.c wininternals.c /Fe:process_analyzer.exe /link psapi.lib advapi32.lib kernel32.lib
```

> Per accedere alla memoria di processi di sistema eseguire come **Amministratore**.

## Utilizzo

```batch
# Lista tutti i processi
process_analyzer.exe

# Filtra per nome (prefisso)
process_analyzer.exe svchost

# Mostra i servizi ospitati da un PID
process_analyzer.exe 1234

# Hex dump della memoria di un PID
process_analyzer.exe @1234
# Hex dump della memoria su un file di testo
process_analyzer.exe @1234 > output.txt

```
> Il programma non termina immediatamente, ma solo dopo l'inserimento di un nuemro e la pressione del tasto `INVIO` al fine di consentire l'esecuzione di un primo test:

```batch
# In una finestra lanciare il comando:
process_analyzer.exe process_analyzer
# quindi leggere il `pid` ed eseguire, in un'altra finestra:
process_analyzer.exe @pid_trovato > output.txt
# per ottenere il dump della memoria nel file `output.txt`
```

## API Windows utilizzate

| API | Scopo |
|-----|-------|
| `CreateToolhelp32Snapshot` | Snapshot dei processi attivi |
| `Process32First/Next` | Enumerazione processi |
| `GetProcessMemoryInfo` | Statistiche memoria per processo |
| `OpenSCManager` | Connessione al Service Control Manager |
| `EnumServicesStatusEx` | Enumerazione servizi attivi |
| `VirtualQueryEx` | Mappa delle regioni di memoria |
| `ReadProcessMemory` | Lettura della RAM di un processo |
| `AdjustTokenPrivileges` | Attivazione `SeDebugPrivilege` |

## Librerie collegate

- `kernel32.lib` — API di base Windows
- `psapi.lib` — informazioni sui processi
- `advapi32.lib` — Service Control Manager e privilegi

## Licenza

MIT
