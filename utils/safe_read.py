"""
Safe file reading utility with multiple encoding support and binary detection.
"""
import os
from utils.logger import get_logger

logger = get_logger()

# Lista kodowań do próby (w kolejności priorytetu)
# Zgodnie z wymaganiami: UTF-8 → UTF-16 LE → CP1250 → fallback
ENCODINGS = ['utf-8', 'utf-8-sig', 'utf-16-le', 'utf-16', 'cp1250', 'cp1252', 'cp850', 'latin1', 'cp437', 'utf-16-be']

def is_binary_file(file_path, sample_size=8192):
    """
    Sprawdza czy plik jest binarny.
    
    Args:
        file_path (str): Ścieżka do pliku
        sample_size (int): Rozmiar próbki do sprawdzenia
    
    Returns:
        bool: True jeśli plik jest binarny, False jeśli tekstowy
    """
    try:
        with open(file_path, 'rb') as f:
            sample = f.read(sample_size)
            # Sprawdź czy zawiera null bytes (typowe dla plików binarnych)
            if b'\x00' in sample:
                return True
            # Sprawdź czy zawiera tylko drukowalne znaki ASCII lub znaki UTF-8
            try:
                sample.decode('utf-8')
            except UnicodeDecodeError:
                return True
            return False
    except Exception as e:
        logger.warning(f"[SAFE_READ] Error checking if file is binary: {e}")
        return True  # W razie wątpliwości, traktuj jako binarny

def safe_read(file_path, encodings=None, fallback_encoding=None):
    """
    Bezpieczne wczytywanie pliku z obsługą wielu kodowań.
    
    Args:
        file_path (str): Ścieżka do pliku
        encodings (list, optional): Lista kodowań do próby. Jeśli None, używa domyślnej listy.
        fallback_encoding (str, optional): Kodowanie fallback. Jeśli None, używa 'utf-8' z errors='replace'
    
    Returns:
        tuple: (content: str, encoding: str, error: str or None)
               Jeśli sukces: (content, encoding, None)
               Jeśli błąd: (None, None, error_message)
    """
    if encodings is None:
        encodings = ENCODINGS
    
    if fallback_encoding is None:
        fallback_encoding = 'utf-8'
    
    # Sprawdź czy plik istnieje
    if not os.path.exists(file_path):
        error_msg = f"File does not exist: {file_path}"
        logger.error(f"[SAFE_READ] {error_msg}")
        return None, None, error_msg
    
    # Sprawdź czy plik jest binarny
    if is_binary_file(file_path):
        error_msg = f"File appears to be binary: {file_path}"
        logger.warning(f"[SAFE_READ] {error_msg}")
        return None, None, error_msg
    
    # Próbuj różne kodowania zgodnie z sekwencją fallback
    # UTF-8 → UTF-16 LE → CP1250 → inne
    for encoding in encodings:
        try:   
            with open(file_path, 'r', encoding=encoding, errors='strict') as f:
                content = f.read()
                logger.debug(f"[SAFE_READ] Successfully read {file_path} with encoding: {encoding}")
                return content, encoding, None
        except UnicodeDecodeError as e:
            logger.debug(f"[SAFE_READ] UnicodeDecodeError with {encoding}: {e}")
            continue
        except Exception as e:
            logger.debug(f"[SAFE_READ] Error reading {file_path} with encoding {encoding}: {type(e).__name__}: {e}")
            continue
    
    # Jeśli wszystkie kodowania zawiodły, spróbuj z fallback (z zamianą znaków)
    try:
        with open(file_path, 'r', encoding=fallback_encoding, errors='replace') as f:
            content = f.read()
            logger.warning(f"[SAFE_READ] Read {file_path} with fallback encoding {fallback_encoding} (some characters may be replaced)")
            return content, fallback_encoding, None
    except Exception as e:
        error_msg = f"Failed to read file with all encodings: {type(e).__name__}: {e}"
        logger.error(f"[SAFE_READ] {error_msg}")
        return None, None, error_msg

def detect_encoding(file_path, sample_size=8192):
    """
    Wykrywa kodowanie pliku używając chardet (jeśli dostępny).
    
    Args:
        file_path (str): Ścieżka do pliku
        sample_size (int): Rozmiar próbki do analizy
    
    Returns:
        str or None: Wykryte kodowanie lub None
    """
    try:
        import chardet
        with open(file_path, 'rb') as f:
            sample = f.read(sample_size)
            result = chardet.detect(sample)
            encoding = result.get('encoding')
            confidence = result.get('confidence', 0)
            
            if encoding and confidence > 0.7:
                logger.debug(f"[SAFE_READ] Detected encoding: {encoding} (confidence: {confidence:.2f})")
                return encoding
            else:
                logger.debug(f"[SAFE_READ] Low confidence encoding detection: {encoding} (confidence: {confidence:.2f})")
                return None
    except ImportError:
        logger.debug("[SAFE_READ] chardet not available, skipping auto-detection")
        return None
    except Exception as e:
        logger.debug(f"[SAFE_READ] Error detecting encoding: {type(e).__name__}: {e}")
        return None

