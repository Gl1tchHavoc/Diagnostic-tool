"""
Tests for BSOD correlation.
"""
import pytest
from datetime import datetime, timedelta, timezone
from correlation.bsod_correlation import BSODCorrelator

class TestBSODCorrelator:
    """Testy dla BSODCorrelator."""
    
    def test_correlator_initialization(self):
        """Test inicjalizacji korelatora."""
        correlator = BSODCorrelator(time_window_minutes=5)
        assert correlator.time_window_minutes == 5
        assert correlator.bsod_timestamp is None
        assert correlator.correlated_events == []
    
    def test_is_noise(self):
        """Test wykrywania noise."""
        correlator = BSODCorrelator()
        
        # Test noise events
        noise_events = [
            {'message': 'Service Windows Update running', 'level': 'Information'},
            {'message': 'DNS request completed', 'level': 'Information'},
            {'message': 'User logged on', 'level': 'Information'},
        ]
        
        for event in noise_events:
            assert correlator.is_noise(event) == True
        
        # Test non-noise events
        non_noise_events = [
            {'message': 'Disk error detected', 'level': 'Error'},
            {'message': 'Driver failed to load', 'level': 'Critical'},
        ]
        
        for event in non_noise_events:
            assert correlator.is_noise(event) == False
    
    def test_calculate_event_score(self):
        """Test obliczania score eventu."""
        correlator = BSODCorrelator()
        bsod_time = datetime.now(timezone.utc)
        
        # Event 25 sekund przed BSOD, Error level, DISK_ERROR category
        event = {
            'timestamp': bsod_time - timedelta(seconds=25),
            'level': 'Error',
            'category': 'DISK_ERROR',
            'message': 'Disk error'
        }
        
        score = correlator.calculate_event_score(event, bsod_time)
        # Powinien mieć: +3 (czas 0-30s) + +3 (Error) + +5 (Hardware) = 11
        assert score >= 10.0
    
    def test_filter_events_by_time(self):
        """Test filtrowania eventów po czasie."""
        correlator = BSODCorrelator(time_window_minutes=5)
        bsod_time = datetime.now(timezone.utc)
        
        events = [
            {'timestamp': bsod_time - timedelta(minutes=3), 'message': 'Event 1'},
            {'timestamp': bsod_time - timedelta(minutes=6), 'message': 'Event 2'},  # Poza oknem
            {'timestamp': bsod_time + timedelta(seconds=30), 'message': 'Event 3'},
            {'timestamp': bsod_time + timedelta(minutes=2), 'message': 'Event 4'},  # Poza oknem
        ]
        
        filtered = correlator.filter_events_by_time(events, bsod_time)
        # Powinny być tylko Event 1 i Event 3
        assert len(filtered) == 2


