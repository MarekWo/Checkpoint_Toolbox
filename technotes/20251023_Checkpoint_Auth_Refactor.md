# Notatka Techniczna: Refaktoryzacja Uwierzytelniania i Logiki Skryptów Checkpoint

**Data:** 2025-10-23

## Podsumowanie

Wprowadzono fundamentalne zmiany w architekturze uwierzytelniania dla skryptów tylko do odczytu oraz poprawiono logikę wyszukiwania obiektów w celu zwiększenia bezpieczeństwa, niezawodności i dokładności.

## Zmiany

### 1. Bezpieczne, Nieinteraktywne Uwierzytelnianie Read-Only

**Problem:**
Operacje tylko do odczytu (np. `Get-CPWhereUsed`) wymagały uciążliwego, interaktywnego logowania z użyciem tokena RSA. Próby automatyzacji przy użyciu zdalnego Menedżera poświadczeń nie powiodły się z powodu problemu "drugiego skoku" (double-hop) w zdalnych sesjach PowerShell, a przechowywanie hasła w pliku `.ini` na serwerze stanowiło ryzyko bezpieczeństwa.

**Rozwiązanie: Przekazywanie Poświadczeń w Pamięci**
Zaimplementowano bezpieczny, trójetapowy mechanizm, który omija wszystkie powyższe problemy:

1.  **Odczyt Lokalny:** Funkcja `Get-CPWhereUsed` w lokalnym module (`checkpoint_remote.psm1`) otrzymała przełącznik `-ReadOnly`. Po jego użyciu, funkcja odczytuje poświadczenia dla konta API z **lokalnego Menedżera poświadczeń na komputerze użytkownika**.
2.  **Bezpieczne Przekazanie:** Odczytane hasło jest następnie przekazywane jako parametr w pamięci do zdalnego polecenia `Invoke-Command`. Hasło nigdy nie jest zapisywane na dysku serwera docelowego.
3.  **Użycie Zdalne:** Zdalny skrypt `whereused.ps1` i moduł `Get-Sessionid.psm1` zostały zmodyfikowane tak, aby mogły przyjąć to hasło i użyć go do zalogowania się do Checkpoint API.

**Korzyści:**
- **Bezpieczeństwo:** Hasło jest bezpiecznie przechowywane w lokalnym Menedżerze poświadczeń i nigdy nie jest zapisywane w pliku tekstowym na serwerze.
- **Niezawodność:** Rozwiązanie omija problem "drugiego skoku", ponieważ odczyt poświadczeń odbywa się lokalnie.
- **Wygoda:** Umożliwia w pełni zautomatyzowane, nieinteraktywne uruchamianie skryptów tylko do odczytu.

### 2. Poprawa Dokładności Wyszukiwania Obiektów (`whereused.ps1`)

**Problem:**
Skrypt `whereused.ps1` przy wyszukiwaniu obiektu po adresie IP (np. `172.30.2.21`) mógł zwrócić obiekt pasujący częściowo (np. `172.30.2.218`), co prowadziło do błędnych wyników.

**Rozwiązanie:**
- Zmodyfikowano logikę wyszukiwania w funkcji `Get-CheckpointIPInfo`. Skrypt najpierw pobiera listę potencjalnych dopasowań, a następnie iteruje przez nie, aby znaleźć obiekt z **dokładnie pasującym adresem IP**. Jeśli taki obiekt nie istnieje, zwracany jest komunikat "object not found".

**Korzyść:**
Zapewnienie dokładności i wiarygodności wyników zwracanych przez skrypt.

---

## Instrukcja Konfiguracji Środowiska

Aby nowy mechanizm uwierzytelniania działał poprawnie, należy wykonać następującą konfigurację:

### A. Na Twoim LOKALNYM Komputerze (Workstation)

Musisz jednorazowo zapisać hasło dla konta API w swoim lokalnym Menedżerze poświadczeń.

1.  Otwórz terminal PowerShell na swoim komputerze.
2.  Wklej i wykonaj poniższą komendę. Zostaniesz poproszony o podanie hasła.
    ```powershell
    cmdkey /generic:LegacyGeneric:target=fwmgr /user:fwapi /pass
    ```
    *   **Uwaga:** Upewnij się, że `user` to poprawna nazwa konta API (np. `fwapi`).

### B. Na ZDALNYM Serwerze (`csnetsec`)

Musisz upewnić się, że w pliku konfiguracyjnym `.ini` zdefiniowana jest nazwa użytkownika dla konta API.

1.  Połącz się z serwerem `csnetsec`.
2.  Otwórz do edycji plik `cp_tools.ini` znajdujący się w Twoim folderze domowym (`$env:USERPROFILE\cp_tools.ini`).
3.  W sekcji `[USER]` dodaj lub upewnij się, że istnieje następujący wpis:
    ```ini
    [USER]
    api_user=fwapi
    ```
    *   **Ważne:** Skrypt użyje tej nazwy użytkownika podczas logowania przy użyciu hasła, które przekażesz ze swojego komputera. Hasło **nie jest** tutaj zapisywane.

### C. Sposób Użycia

Po wykonaniu powyższej konfiguracji, możesz używać nowego mechanizmu w następujący sposób:

-   **Dla operacji Read-Only (np. `whereused`):**
    Dodaj przełącznik `-ReadOnly` na końcu polecenia.
    ```powershell
    Get-CPWhereUsed @fwmgr -ip 172.30.2.21 -ReadOnly
    ```

-   **Dla operacji zapisu (np. `Add-CPHosts`, `Push-CPPolicy`):**
    Wywołuj polecenia tak jak dotychczas, **bez** przełącznika `-ReadOnly`. Skrypt poprosi Cię wtedy o hasło z tokena RSA.

## Zmodyfikowane Pliki

-   `O-Scripts-Powershell-Modules\checkpoint_remote.psm1` (logika lokalna)
-   `csnetsec-D-Powershell-Checkpoint-AddHosts-Modules\Get-Sessionid.psm1` (logika zdalna)
-   `csnetsec-D-Powershell-Checkpoint-AddHosts\whereused.ps1` (logika zdalna)
