"""
Moduł sprawdzający czy wszystkie wymagane pakiety z requirements.txt są zainstalowane.
"""
import sys
import subprocess
import pkg_resources
from pathlib import Path
from utils.logger import get_logger

logger = get_logger()


def parse_requirements_file(requirements_path="requirements.txt"):
    """
    Parsuje plik requirements.txt i zwraca listę pakietów.

    Args:
        requirements_path (str): Ścieżka do pliku requirements.txt

    Returns:
        list: Lista krotek (package_name, version_spec) lub None jeśli plik nie istnieje
    """
    req_file = Path(requirements_path)

    if not req_file.exists():
        logger.warning(
            f"[REQUIREMENTS] Requirements file not found: {requirements_path}")
        return None

    requirements = []

    try:
        with open(req_file, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()

                # Pomiń komentarze i puste linie
                if not line or line.startswith('#'):
                    continue

                # Usuń komentarze z końca linii
                if '#' in line:
                    line = line.split('#')[0].strip()

                # Parsuj linię (może zawierać wersję, np. "package==1.0.0" lub
                # "package>=1.0.0")
                if line:
                    # Usuń białe znaki i sprawdź czy to nie jest opcja
                    # instalacji (np. --index-url)
                    if line.startswith('-'):
                        continue

                    # Usuń warunki platformowe (np. "; sys_platform ==
                    # 'win32'")
                    if ';' in line:
                        line = line.split(';')[0].strip()

                    # Podziel na nazwę pakietu i specyfikację wersji
                    parts = line.split('==', 1)
                    if len(parts) == 2:
                        package_name = parts[0].strip()
                        version = parts[1].strip()
                        requirements.append((package_name, f"=={version}"))
                    else:
                        # Sprawdź inne specyfikatory wersji (>=, <=, >, <, ~=)
                        found_op = False
                        for op in ['>=', '<=', '>', '<', '~=', '!=']:
                            if op in line:
                                parts = line.split(op, 1)
                                package_name = parts[0].strip()
                                version = parts[1].strip()
                                # Usuń warunki platformowe z wersji jeśli są
                                if ';' in version:
                                    version = version.split(';')[0].strip()
                                requirements.append(
                                    (package_name, f"{op}{version}"))
                                found_op = True
                                break
                        if not found_op:
                            # Brak specyfikacji wersji - tylko nazwa pakietu
                            requirements.append((line, None))

        logger.debug(
            f"[REQUIREMENTS] Parsed {len(requirements)} packages from {requirements_path}")
        return requirements

    except Exception as e:
        logger.error(f"[REQUIREMENTS] Error parsing requirements file: {e}")
        return None


def check_package_installed(package_name, version_spec=None):
    """
    Sprawdza czy pakiet jest zainstalowany i czy spełnia wymagania wersji.

    Args:
        package_name (str): Nazwa pakietu
        version_spec (str, optional): Specyfikacja wersji (np. "==1.0.0", ">=1.0.0")

    Returns:
        tuple: (is_installed: bool, installed_version: str or None, error: str or None)
    """
    try:
        # Pobierz zainstalowaną wersję
        installed = pkg_resources.get_distribution(package_name)
        installed_version = installed.version

        # Jeśli nie ma wymagania wersji, pakiet jest OK
        if version_spec is None:
            return True, installed_version, None

        # Sprawdź czy wersja spełnia wymagania
        try:
            # Użyj pkg_resources do porównania wersji
            requirement = pkg_resources.Requirement.parse(
                f"{package_name}{version_spec}")
            if installed_version in requirement:
                return True, installed_version, None
            else:
                return False, installed_version, f"Version mismatch: installed {installed_version}, required {version_spec}"
        except Exception as e:
            # Jeśli nie można porównać wersji, zaakceptuj zainstalowaną wersję
            logger.debug(
                f"[REQUIREMENTS] Could not compare version for {package_name}: {e}")
            return True, installed_version, None

    except pkg_resources.DistributionNotFound:
        return False, None, "Package not installed"
    except Exception as e:
        return False, None, f"Error checking package: {e}"


def check_all_requirements(
        requirements_path="requirements.txt", show_missing=True):
    """
    Sprawdza czy wszystkie pakiety z requirements.txt są zainstalowane.

    Args:
        requirements_path (str): Ścieżka do pliku requirements.txt
        show_missing (bool): Czy wyświetlać informacje o brakujących pakietach

    Returns:
        dict: {
            'all_installed': bool,
            'total_packages': int,
            'installed_packages': int,
            'missing_packages': list,
            'version_mismatches': list,
            'details': list of dicts
        }
    """
    requirements = parse_requirements_file(requirements_path)

    if requirements is None:
        return {
            'all_installed': False,
            'total_packages': 0,
            'installed_packages': 0,
            'missing_packages': [],
            'version_mismatches': [],
            'details': [],
            'error': 'Requirements file not found'
        }

    results = {
        'all_installed': True,
        'total_packages': len(requirements),
        'installed_packages': 0,
        'missing_packages': [],
        'version_mismatches': [],
        'details': []
    }

    logger.info(f"[REQUIREMENTS] Checking {len(requirements)} packages...")

    for package_name, version_spec in requirements:
        is_installed, installed_version, error = check_package_installed(
            package_name, version_spec)

        detail = {
            'package': package_name,
            'required_version': version_spec,
            'installed': is_installed,
            'installed_version': installed_version,
            'error': error
        }
        results['details'].append(detail)

        if is_installed:
            results['installed_packages'] += 1
            if show_missing:
                logger.debug(
                    f"[REQUIREMENTS] ✓ {package_name} {installed_version or ''} installed")
        else:
            results['all_installed'] = False
            if error == "Package not installed":
                results['missing_packages'].append(package_name)
                if show_missing:
                    logger.warning(
                        f"[REQUIREMENTS] ✗ {package_name} NOT INSTALLED")
            else:
                results['version_mismatches'].append({
                    'package': package_name,
                    'installed': installed_version,
                    'required': version_spec,
                    'error': error
                })
                if show_missing:
                    logger.warning(
                        f"[REQUIREMENTS] ✗ {package_name} version mismatch: {error}")

    if results['all_installed']:
        logger.info(
            f"[REQUIREMENTS] All {results['total_packages']} packages are installed")
    else:
        logger.warning(f"[REQUIREMENTS] Missing {len(results['missing_packages'])} packages, "
                       f"{len(results['version_mismatches'])} version mismatches")

    return results


def get_install_command(missing_packages):
    """
    Generuje komendę do instalacji brakujących pakietów.

    Args:
        missing_packages (list): Lista nazw pakietów do zainstalowania

    Returns:
        str: Komenda pip install
    """
    if not missing_packages:
        return None

    return f"pip install {' '.join(missing_packages)}"


def install_missing_packages(
        requirements_path="requirements.txt", auto_install=True):
    """
    Sprawdza i automatycznie instaluje brakujące pakiety z requirements.txt.

    Args:
        requirements_path (str): Ścieżka do pliku requirements.txt
        auto_install (bool): Czy automatycznie instalować brakujące pakiety

    Returns:
        dict: Wyniki instalacji z check_all_requirements() + informacje o instalacji
    """
    # Sprawdź wymagania
    results = check_all_requirements(requirements_path, show_missing=True)

    if results['all_installed']:
        logger.info("[REQUIREMENTS] All packages are already installed")
        return results

    # Jeśli są brakujące pakiety i auto_install jest włączone
    if results['missing_packages'] and auto_install:
        logger.info(
            f"[REQUIREMENTS] Attempting to install {len(results['missing_packages'])} missing packages...")

        try:
            # Pobierz pełne specyfikacje pakietów z requirements.txt
            requirements = parse_requirements_file(requirements_path)
            if requirements is None:
                logger.error(
                    "[REQUIREMENTS] Cannot parse requirements file for installation")
                return results

            # Znajdź pełne specyfikacje dla brakujących pakietów
            packages_to_install = []
            for package_name, version_spec in requirements:
                if package_name in results['missing_packages']:
                    if version_spec:
                        packages_to_install.append(
                            f"{package_name}{version_spec}")
                    else:
                        packages_to_install.append(package_name)

            if packages_to_install:
                # Uruchom pip install
                logger.info(
                    f"[REQUIREMENTS] Installing: {', '.join(packages_to_install)}")
                print(
                    f"\n📦 Installing missing packages: {', '.join(results['missing_packages'])}")

                # Użyj subprocess do instalacji
                install_cmd = [
                    sys.executable, "-m", "pip", "install", "--upgrade"
                ] + packages_to_install

                try:
                    result = subprocess.run(
                        install_cmd,
                        check=True,
                        capture_output=True,
                        text=True,
                        timeout=300  # 5 minut timeout
                    )

                    logger.info(f"[REQUIREMENTS] Installation successful")
                    print("✅ Packages installed successfully!")

                    # Sprawdź ponownie po instalacji
                    results = check_all_requirements(
                        requirements_path, show_missing=False)

                    if results['all_installed']:
                        logger.info(
                            "[REQUIREMENTS] All packages are now installed")
                        print("✅ All requirements are now satisfied!")
                    else:
                        logger.warning(
                            "[REQUIREMENTS] Some packages still missing after installation")
                        print(
                            "⚠️  Some packages may still be missing. Please check manually.")

                except subprocess.TimeoutExpired:
                    logger.error(
                        "[REQUIREMENTS] Installation timeout (exceeded 5 minutes)")
                    print("❌ Installation timeout. Please install packages manually.")
                except subprocess.CalledProcessError as e:
                    logger.error(f"[REQUIREMENTS] Installation failed: {e}")
                    logger.error(f"[REQUIREMENTS] Error output: {e.stderr}")
                    print(f"❌ Installation failed: {e.stderr}")
                    print(
                        f"\nPlease install manually: {get_install_command(results['missing_packages'])}")
                except Exception as e:
                    logger.exception(
                        f"[REQUIREMENTS] Unexpected error during installation: {e}")
                    print(f"❌ Unexpected error during installation: {e}")

        except Exception as e:
            logger.exception(
                f"[REQUIREMENTS] Error preparing installation: {e}")
            print(f"❌ Error preparing installation: {e}")

    return results


def print_requirements_status(results):
    """
    Wyświetla czytelny status wymagań.

    Args:
        results (dict): Wyniki z check_all_requirements()
    """
    print("\n" + "=" * 70)
    print("REQUIREMENTS CHECK")
    print("=" * 70)

    if results.get('error'):
        print(f"❌ Error: {results['error']}")
        return

    total = results['total_packages']
    installed = results['installed_packages']
    missing = len(results['missing_packages'])
    mismatches = len(results['version_mismatches'])

    print(f"Total packages: {total}")
    print(f"Installed: {installed}")

    if missing > 0:
        print(f"Missing: {missing}")
        print("\nMissing packages:")
        for pkg in results['missing_packages']:
            print(f"  - {pkg}")

    if mismatches > 0:
        print(f"Version mismatches: {mismatches}")
        print("\nVersion mismatches:")
        for mismatch in results['version_mismatches']:
            print(
                f"  - {mismatch['package']}: installed {mismatch['installed']}, required {mismatch['required']}")

    if results['all_installed']:
        print("\n✓ All requirements are satisfied!")
    else:
        install_cmd = get_install_command(results['missing_packages'])
        if install_cmd:
            print(f"\nTo install missing packages, run:")
            print(f"  {install_cmd}")

    print("=" * 70 + "\n")


if __name__ == "__main__":
    # Test funkcji
    results = check_all_requirements()
    print_requirements_status(results)
