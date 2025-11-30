# Formatowanie Kodu - Dokumentacja

## Konfiguracja Flake8

Plik `.flake8` zawiera restrykcyjną konfigurację wymuszającą:

### Wymagania stylistyczne:
- **Maksymalna długość linii**: 79 znaków (PEP8)
- **Maksymalna długość pliku**: 2000 linii
- **Wcięcia**: 4 spacje (bez tabulatorów)
- **Spójne wcięcia**: Wszystkie reguły E111-E133 (indentation)
- **Whitespace**: Wszystkie reguły E201-E275, W291-W293, W391
- **Złożoność**: max-complexity = 10

### Rozszerzenia:
- **flake8-bugbear (Bxxx)**: Wykrywa potencjalne błędy
- **flake8-comprehensions (Cxxx)**: Sprawdza list comprehensions
- **flake8-annotations (Ixxx)**: Wymaga typowania funkcji

## Automatyczne formatowanie

### Narzędzia:
- **autopep8**: Automatyczne formatowanie zgodne z PEP8
- **isort**: Sortowanie importów

### Użycie:

```bash
# Formatuj pojedynczy plik
python -m autopep8 --in-place --aggressive --max-line-length=79 plik.py
python -m isort --profile=black --line-length=79 plik.py

# Formatuj katalog
python -m autopep8 --in-place --aggressive --max-line-length=79 --recursive katalog/
python -m isort --profile=black --line-length=79 --recursive katalog/

# Użyj skryptu
python scripts/format_code_batch.py
```

## Sprawdzanie kodu

```bash
# Sprawdź wszystkie błędy
flake8 collectors/ processors/ core/ utils/

# Sprawdź tylko błędy stylistyczne
flake8 --select=E,W collectors/ processors/ core/ utils/

# Statystyki
flake8 --statistics collectors/ processors/ core/ utils/
```

## Najczęstsze błędy i naprawy

### W293: blank line contains whitespace
**Naprawa**: Usuń spacje z pustych linii
```python
# ❌ Błędne
def func():
    
    pass

# ✅ Poprawne
def func():

    pass
```

### E302: expected 2 blank lines
**Naprawa**: Dodaj 2 puste linie przed definicją funkcji/klasy
```python
# ❌ Błędne
import os
def func():
    pass

# ✅ Poprawne
import os


def func():
    pass
```

### E501: line too long
**Naprawa**: Podziel długie linie
```python
# ❌ Błędne (80+ znaków)
result = very_long_function_name(param1, param2, param3, param4, param5)

# ✅ Poprawne
result = very_long_function_name(
    param1, param2, param3, param4, param5
)
```

### W291: trailing whitespace
**Naprawa**: Usuń spacje na końcu linii
```python
# ❌ Błędne (spacja na końcu)
def func(): 

# ✅ Poprawne
def func():
```

## CI/CD

Formatowanie jest sprawdzane w GitHub Actions:
- Flake8 uruchamia się automatycznie przy każdym push/PR
- Błędy nie przerywają CI (używa `|| true`)
- Wszystkie błędy są logowane do review

