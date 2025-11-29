"""
Tests for event scoring system.
"""
import pytest
from datetime import datetime, timedelta, timezone
from correlation.bsod_correlation import BSODCorrelator

class TestScoring:
    """Testy dla systemu scoringu."""
    
    def test_time_based_scoring(self):
        """Test scoringu opartego na czasie."""
        correlator = BSODCorrelator()
        bsod_time = datetime.now(timezone.utc)
        
        # Event 15 sekund przed BSOD
        event1 = {
            'timestamp': bsod_time - timedelta(seconds=15),
            'level': 'Error',
            'category': 'OTHER',
            'message': 'Test event'
        }
        score1 = correlator.calculate_event_score(event1, bsod_time)
        assert score1 >= 3.0  # +3 za czas 0-30s
        
        # Event 60 sekund przed BSOD
        event2 = {
            'timestamp': bsod_time - timedelta(seconds=60),
            'level': 'Error',
            'category': 'OTHER',
            'message': 'Test event'
        }
        score2 = correlator.calculate_event_score(event2, bsod_time)
        assert score2 >= 2.0  # +2 za czas 31-120s
        assert score2 < score1  # Powinien mieć niższy score niż event1
    
    def test_level_based_scoring(self):
        """Test scoringu opartego na poziomie."""
        correlator = BSODCorrelator()
        bsod_time = datetime.now(timezone.utc)
        
        # Critical event
        event_critical = {
            'timestamp': bsod_time - timedelta(seconds=20),
            'level': 'Critical',
            'category': 'OTHER',
            'message': 'Critical event'
        }
        score_critical = correlator.calculate_event_score(event_critical, bsod_time)
        
        # Warning event
        event_warning = {
            'timestamp': bsod_time - timedelta(seconds=20),
            'level': 'Warning',
            'category': 'OTHER',
            'message': 'Warning event'
        }
        score_warning = correlator.calculate_event_score(event_warning, bsod_time)
        
        assert score_critical > score_warning  # Critical powinien mieć wyższy score
    
    def test_category_based_scoring(self):
        """Test scoringu opartego na kategorii."""
        correlator = BSODCorrelator()
        bsod_time = datetime.now(timezone.utc)
        
        # Hardware event
        event_hardware = {
            'timestamp': bsod_time - timedelta(seconds=20),
            'level': 'Error',
            'category': 'DISK_ERROR',
            'message': 'Disk error'
        }
        score_hardware = correlator.calculate_event_score(event_hardware, bsod_time)
        
        # Other event
        event_other = {
            'timestamp': bsod_time - timedelta(seconds=20),
            'level': 'Error',
            'category': 'OTHER',
            'message': 'Other event'
        }
        score_other = correlator.calculate_event_score(event_other, bsod_time)
        
        assert score_hardware > score_other  # Hardware powinien mieć wyższy score
    
    def test_negative_score_filtering(self):
        """Test filtrowania eventów z ujemnym score."""
        correlator = BSODCorrelator()
        bsod_time = datetime.now(timezone.utc)
        
        # Noise event (powinien mieć ujemny score)
        noise_event = {
            'timestamp': bsod_time - timedelta(seconds=20),
            'level': 'Information',
            'category': 'OTHER',
            'message': 'Service started successfully'
        }
        score = correlator.calculate_event_score(noise_event, bsod_time)
        
        # Noise event powinien być odfiltrowany (score < 0 lub is_noise = True)
        assert correlator.is_noise(noise_event) == True


