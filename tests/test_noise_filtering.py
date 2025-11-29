"""
Tests for noise filtering.
"""
import pytest
from correlation.bsod_correlation import BSODCorrelator

class TestNoiseFiltering:
    """Testy dla filtracji noise."""
    
    def test_regex_patterns(self):
        """Test regex patterns dla noise."""
        correlator = BSODCorrelator()
        
        noise_messages = [
            "The description for Event ID 12345 cannot be found",
            "Audit Success",
            "Service Windows Update running",
            "Service Spooler started successfully",
        ]
        
        for message in noise_messages:
            event = {'message': message, 'level': 'Information'}
            assert correlator.is_noise(event) == True
    
    def test_common_noise_keywords(self):
        """Test słów kluczowych dla noise."""
        correlator = BSODCorrelator()
        
        noise_messages = [
            "DNS request completed",
            "User logged on",
            "Windows Update installed",
            "Backup completed successfully",
            "Scheduled task completed",
        ]
        
        for message in noise_messages:
            event = {'message': message, 'level': 'Information'}
            assert correlator.is_noise(event) == True
    
    def test_information_level_filtering(self):
        """Test filtrowania poziomu Information."""
        correlator = BSODCorrelator()
        
        information_events = [
            {'message': 'Any message', 'level': 'Information'},
            {'message': 'Another message', 'level': 'informational'},
            {'message': 'Yet another', 'level': 'Info'},
        ]
        
        for event in information_events:
            assert correlator.is_noise(event) == True
    
    def test_non_noise_events(self):
        """Test że ważne eventy nie są traktowane jako noise."""
        correlator = BSODCorrelator()
        
        important_events = [
            {'message': 'Disk error detected', 'level': 'Error'},
            {'message': 'Driver failed to load', 'level': 'Critical'},
            {'message': 'Memory management error', 'level': 'Warning'},
            {'message': 'GPU driver crash', 'level': 'Error'},
        ]
        
        for event in important_events:
            assert correlator.is_noise(event) == False


