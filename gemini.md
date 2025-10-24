# Checkpoint Toolbox - Dokumentacja Projektu

## 1. Cel Projektu

Repozytorium zawiera zestaw skryptów PowerShell służących do zdalnej administracji firewallem Checkpoint za pomocą jego API. Struktura katalogów w projekcie symuluje rzeczywistą strukturę produkcyjną, aby ułatwić rozwój i testowanie.

## 2. Architektura Środowiska

Środowisko produkcyjne składa się z dwóch głównych hostów, które biorą udział w procesie.

### 2.1. Hosty

*   **Komputer lokalny**: Główna stacja robocza użytkownika.
*   **Serwer zdalny (`remote_server`)**: Wyznaczony serwer ze statycznym adresem IP.

Taka architektura jest wymuszona przez listę kontroli dostępu (ACL) na firewallu Checkpoint, która ogranicza dostęp do API tylko do zaufanych adresów IP. Adres IP serwera `remote_server` jest dodany do ACL. Aby zapewnić spójny i bezpieczny dostęp, wszystkie kluczowe operacje są wykonywane z serwera zdalnego za pomocą polecenia `Invoke-Command` w PowerShell.

### 2.2. Struktura Plików i Workflow

Praca użytkownika na komputerze lokalnym opiera się na dwóch kluczowych plikach:

1.  **`.\checkpoint_toolbox.ps1`**: Główny skrypt zawierający fragmenty kodu, które są uruchamiane na żądanie w edytorze PowerShell ISE (poprzez zaznaczenie i wciśnięcie `F8`).
2.  **`O:\Scripts\Powershell\Modules\checkpoint_remote.psm1`**: Moduł PowerShell, ładowany automatycznie przy starcie sesji ISE. Zawiera funkcje pomocnicze, które realizują zdalne operacje na serwerze `remote_server` przy użyciu `Invoke-Command`.

## 3. Konwencja Nazewnictwa Katalogów

Aby zasymulować rozproszony system plików środowiska produkcyjnego w ramach jednego repozytorium, zastosowano specyficzną konwencję nazewnictwa folderów:

`<nazwa_serwera>-<litera_dysku>-<ścieżka_katalogu>`

*   Prefiks `<nazwa_serwera>` jest używany dla katalogów znajdujących się na serwerze zdalnym. Jest pomijany dla zasobów lokalnych.
*   Segmenty ścieżki są oddzielone myślnikami.

**Przykłady:**

*   Folder w repozytorium: `remote_server-D-Powershell-Checkpoint-AddHosts`
    *   Oznacza ścieżkę produkcyjną: `D:\Powershell\Checkpoint\AddHosts` na serwerze `remote_server`.
*   Folder w repozytorium: `O-Scripts-Powershell-Modules`
    *   Oznacza ścieżkę produkcyjną: `O:\Scripts\Powershell\Modules` na komputerze lokalnym.

