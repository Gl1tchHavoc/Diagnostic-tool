"""
Confidence normalization and scoring utilities.
"""
from utils.logger import get_logger

logger = get_logger()


def normalize_confidence(confidence_score, min_score=0,
                         max_score=100, target_min=0, target_max=100):
    """
    Normalizuje confidence score do zakresu 0-100.

    Args:
        confidence_score (float): Oryginalny confidence score
        min_score (float): Minimalna wartość w oryginalnym zakresie
        max_score (float): Maksymalna wartość w oryginalnym zakresie
        target_min (float): Docelowa minimalna wartość (domyślnie 0)
        target_max (float): Docelowa maksymalna wartość (domyślnie 100)

    Returns:
        float: Znormalizowany confidence score (0-100)
    """
    if confidence_score is None:
        return 0.0

    try:
        # Jeśli score jest już w zakresie 0-100, zwróć bez zmian
        if 0 <= confidence_score <= 100:
            return float(confidence_score)

        # Normalizuj do zakresu 0-100
        if max_score == min_score:
            return float(target_min)

        normalized = ((confidence_score - min_score) / (max_score
                      - min_score)) * (target_max - target_min) + target_min

        # Ogranicz do zakresu docelowego
        normalized = max(target_min, min(target_max, normalized))

        logger.debug(
            f"[CONFIDENCE_NORMALIZER] Normalized {confidence_score} to {normalized}")
        return round(normalized, 2)

    except (TypeError, ValueError) as e:
        logger.warning(
            f"[CONFIDENCE_NORMALIZER] Error normalizing confidence {confidence_score}: {e}")
        return 0.0


def calculate_weighted_confidence(scores, weights=None):
    """
    Oblicza ważoną średnią confidence z wielu score'ów.

    Args:
        scores (list): Lista confidence scores
        weights (list, optional): Lista wag dla każdego score'a

    Returns:
        float: Ważona średnia confidence (0-100)
    """
    if not scores:
        return 0.0

    if weights is None:
        weights = [1.0] * len(scores)

    if len(weights) != len(scores):
        logger.warning(
            f"[CONFIDENCE_NORMALIZER] Weights length mismatch, using equal weights")
        weights = [1.0] * len(scores)

    try:
        # Normalizuj wszystkie scores do 0-100
        normalized_scores = [normalize_confidence(score) for score in scores]

        # Oblicz ważoną średnią
        total_weight = sum(weights)
        if total_weight == 0:
            return 0.0

        weighted_sum = sum(
            score * weight for score,
            weight in zip(
                normalized_scores,
                weights))
        weighted_avg = weighted_sum / total_weight

        logger.debug(
            f"[CONFIDENCE_NORMALIZER] Calculated weighted confidence: {weighted_avg} from {len(scores)} scores")
        return round(weighted_avg, 2)

    except Exception as e:
        logger.warning(
            f"[CONFIDENCE_NORMALIZER] Error calculating weighted confidence: {e}")
        return 0.0


def apply_confidence_decay(base_confidence, age_hours, decay_rate=0.1):
    """
    Zastosowuje decay do confidence score na podstawie wieku zdarzenia.

    Args:
        base_confidence (float): Bazowy confidence score
        age_hours (float): Wiek zdarzenia w godzinach
        decay_rate (float): Współczynnik zaniku na godzinę (domyślnie 0.1 = 10%)

    Returns:
        float: Confidence score po zastosowaniu decay
    """
    if base_confidence is None or base_confidence <= 0:
        return 0.0

    try:
        # Normalizuj do 0-100
        normalized = normalize_confidence(base_confidence)

        # Zastosuj decay
        decay_factor = max(0, 1 - (age_hours * decay_rate))
        decayed_confidence = normalized * decay_factor

        logger.debug(
            f"[CONFIDENCE_NORMALIZER] Applied decay: {normalized} -> {decayed_confidence} (age: {age_hours}h, rate: {decay_rate})")
        return round(decayed_confidence, 2)

    except Exception as e:
        logger.warning(
            f"[CONFIDENCE_NORMALIZER] Error applying confidence decay: {e}")
        return normalize_confidence(base_confidence)
