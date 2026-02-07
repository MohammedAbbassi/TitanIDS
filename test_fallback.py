from capture import start_capture
from config import load_config
from logger import setup_logger
import unittest
from unittest.mock import MagicMock, patch

# This test forces the fallback by simulating a sniff failure
class TestMockFallback(unittest.TestCase):
    
    @patch('capture.sniff')
    @patch('capture.start_mock_capture')
    def test_fallback(self, mock_start_mock, mock_sniff):
        # Configure sniffing to fail
        mock_sniff.side_effect = RuntimeError("No Npcap")
        
        config = load_config()
        setup_logger("test.log", console_output=True)
        
        print("Testing fallback mechanism...")
        start_capture(config)
        
        # Verify sniff was called
        mock_sniff.assert_called_once()
        
        # Verify fallback was triggered
        mock_start_mock.assert_called_once()
        print("PASS: Fallback to mock mode verified.")

if __name__ == "__main__":
    unittest.main()
