"""
Logger dla aplikacji diagnostycznej - zapisuje wszystkie informacje potrzebne do debugowania.
"""
import logging
import sys
from pathlib import Path
from datetime import datetime
import traceback

# Katalog na logi
LOG_DIR = Path("logs")
LOG_DIR.mkdir(exist_ok=True)

# Nazwa pliku loga z timestampem
LOG_FILE = LOG_DIR / f"diagnostic_tool_{datetime.now().strftime('%Y%m%d')}.log"
# Plik logowania diagnostycznego (każdy krok diagnostyczny)
DIAGNOSTIC_LOG_FILE = LOG_DIR / \
    f"diagnostic_log_{datetime.now().strftime('%Y%m%d')}.txt"

# Konfiguracja loggera


def setup_logger(name="DiagnosticTool", level=logging.DEBUG):
    """
    Konfiguruje i zwraca logger.

    Args:
        name (str): Nazwa loggera
        level: Poziom logowania (DEBUG, INFO, WARNING, ERROR, CRITICAL)

    Returns:
        logging.Logger: Skonfigurowany logger
    """
    logger = logging.getLogger(name)

    # Jeśli logger już ma handlery, nie konfiguruj ponownie
    if logger.handlers:
        return logger

    logger.setLevel(level)

    # Format logów
    detailed_format = logging.Formatter(
        '%(asctime)s | %(levelname)-8s | %(name)s | %(funcName)s:%(lineno)d | %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )

    simple_format = logging.Formatter(
        '%(asctime)s | %(levelname)-8s | %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )

    # Handler do pliku (szczegółowy)
    file_handler = logging.FileHandler(LOG_FILE, encoding='utf-8', mode='a')
    file_handler.setLevel(logging.DEBUG)  # Wszystkie poziomy do pliku
    file_handler.setFormatter(detailed_format)

    # Handler do konsoli (uproszczony)
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(logging.INFO)  # Tylko INFO i wyżej do konsoli
    console_handler.setFormatter(simple_format)

    # Handler do pliku diagnostycznego (każdy krok diagnostyczny)
    diagnostic_file_handler = logging.FileHandler(
        DIAGNOSTIC_LOG_FILE, encoding='utf-8', mode='a')
    # INFO i wyżej do pliku diagnostycznego
    diagnostic_file_handler.setLevel(logging.INFO)
    diagnostic_format = logging.Formatter(
        '%(asctime)s | %(levelname)-8s | %(name)s | %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    diagnostic_file_handler.setFormatter(diagnostic_format)

    # Dodaj handlery
    logger.addHandler(file_handler)
    logger.addHandler(console_handler)
    logger.addHandler(diagnostic_file_handler)

    return logger


# Globalny logger
_logger = None


def get_logger():
    """Zwraca globalny logger (tworzy jeśli nie istnieje)."""
    global _logger
    if _logger is None:
        _logger = setup_logger()
    return _logger


def log_function_call(func):
    """Decorator do logowania wywołań funkcji."""
    def wrapper(*args, **kwargs):
        logger = get_logger()
        func_name = func.__name__
        logger.debug(f"Calling {func_name} with args={args}, kwargs={kwargs}")
        try:
            result = func(*args, **kwargs)
            logger.debug(f"{func_name} completed successfully")
            return result
        except Exception as e:
            logger.error(f"{func_name} failed: {type(e).__name__}: {e}")
            logger.debug(f"Traceback:\n{traceback.format_exc()}")
            raise
    return wrapper


def log_exception(logger, message="Exception occurred", exc_info=True):
    """
    Loguje wyjątek z pełnym tracebackiem.

    Args:
        logger: Logger instance
        message (str): Wiadomość do logowania
        exc_info (bool): Czy dołączyć informacje o wyjątku
    """
    if exc_info:
        logger.error(f"{message}\n{traceback.format_exc()}")
    else:
        logger.error(message)


def log_collector_start(collector_name):
    """Loguje start collectora."""
    logger = get_logger()
    logger.info(f"[COLLECTOR] Starting: {collector_name}")


def log_collector_end(collector_name, success=True, error=None, data_count=0):
    """Loguje zakończenie collectora."""
    logger = get_logger()
    if success:
        logger.info(
            f"[COLLECTOR] Completed: {collector_name} (collected {data_count} items)")
    else:
        logger.error(f"[COLLECTOR] Failed: {collector_name} - {error}")


def log_processor_start(processor_name):
    """Loguje start procesora."""
    logger = get_logger()
    logger.info(f"[PROCESSOR] Starting: {processor_name}")


def log_processor_end(processor_name, success=True,
                      error=None, issues_found=0):
    """Loguje zakończenie procesora."""
    logger = get_logger()
    if success:
        logger.info(
            f"[PROCESSOR] Completed: {processor_name} (found {issues_found} issues)")
    else:
        logger.error(f"[PROCESSOR] Failed: {processor_name} - {error}")


def log_bsod_analysis(bsod_found, related_events_count, top_causes_count):
    """Loguje wyniki analizy BSOD."""
    logger = get_logger()
    if bsod_found:
        logger.info(
            f"[BSOD] Analysis completed: BSOD found, {related_events_count} related events, {top_causes_count} top causes")
    else:
        logger.info(f"[BSOD] Analysis completed: No BSOD found")


def log_performance(operation, duration_seconds, details=None):
    """Loguje metryki wydajności."""
    logger = get_logger()
    msg = f"[PERFORMANCE] {operation} took {duration_seconds:.2f}s"
    if details:
        msg += f" | {details}"
    logger.debug(msg)


def log_data_sample(data_name, sample_data, max_length=200):
    """Loguje próbkę danych (dla debugowania)."""
    logger = get_logger()
    data_str = str(sample_data)
    if len(data_str) > max_length:
        data_str = data_str[:max_length] + "..."
    logger.debug(f"[DATA] {data_name}: {data_str}")
