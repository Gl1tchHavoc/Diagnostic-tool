"""
Warning classification utility - filtruje fałszywe DISK_WARNING.
"""
from utils.logger import get_logger

logger = get_logger()

# Słowa kluczowe, które NIE powinny być klasyfikowane jako DISK_WARNING
NON_DISK_KEYWORDS = [
    "url",
    "http://",
    "https://",
    "upnp",
    "ssdpsrv",
    "wmpnetworksvc",
    "eventing",
    "winhttp",
    "web services",
    "cannot find description",
    "audit success",
    "network",
    "tcp",
    "udp",
    "dns",
    "dhcp"
]


def is_false_disk_warning(message):
    """
    Sprawdza czy wiadomość NIE dotyczy dysku (fałszywy DISK_WARNING).

    Args:
        message (str): Wiadomość do sprawdzenia

    Returns:
        bool: True jeśli to FAŁSZYWY DISK_WARNING (nie dotyczy dysku)
    """
    if not message:
        return False

    message_lower = message.lower()

    for keyword in NON_DISK_KEYWORDS:
        if keyword in message_lower:
            logger.debug(
                f"[WARNING_CLASSIFIER] False DISK_WARNING detected (keyword: {keyword}): {message[:100]}")
            return True

    return False


def classify_warning(message, event_id=None):
    """
    Klasyfikuje warning na podstawie wiadomości.

    Args:
        message (str): Wiadomość warninga
        event_id (str, optional): ID eventu

    Returns:
        str: Typ warninga (NETWORK_WARNING, DISK_WARNING, SYSTEM_WARNING, IGNORE)
    """
    if not message:
        return "SYSTEM_WARNING"

    message_lower = message.lower()

    # Sprawdź czy to fałszywy DISK_WARNING
    if is_false_disk_warning(message):
        # Sprawdź czy to network-related
        network_keywords = [
            "url",
            "http",
            "upnp",
            "ssdpsrv",
            "wmpnetworksvc",
            "winhttp",
            "web services",
            "network",
            "tcp",
            "udp",
            "dns",
            "dhcp"]
        if any(kw in message_lower for kw in network_keywords):
            return "NETWORK_WARNING"
        # Inne fałszywe - ignoruj
        return "IGNORE"

    # Sprawdź czy to rzeczywiście dotyczy dysku
    disk_keywords = [
        "disk",
        "volume",
        "ntfs",
        "file system",
        "i/o error",
        "read error",
        "write error",
        "bad block",
        "bad sector"]
    if any(kw in message_lower for kw in disk_keywords):
        return "DISK_WARNING"

    return "SYSTEM_WARNING"
