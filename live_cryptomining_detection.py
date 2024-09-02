import pyshark
import re
import sys
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# List of known cryptomining pool domains
KNOWN_MINING_POOLS = [
    'minexmr.com',
    'supportxmr.com',
    'nanopool.org',
    'cryptonight-hub.miningpoolhub.com',
    'monerohash.com'
]

# Define suspicious patterns in URLs that might indicate mining
SUSPICIOUS_PATTERNS = [
    re.compile(r'/miner\.php'),  # Common script file name
    re.compile(r'/mining\.js'),  # Common mining JS file
    re.compile(r'/coinhive\.js')  # Specific to CoinHive
]

# Function to analyze packet and check for cryptomining indicators
def analyze_packet(packet):
    try:
        if 'http' in packet:
            http_layer = packet['http']
            
            # Check for known mining pool domains
            host = http_layer.get('host', '')
            if any(pool in host for pool in KNOWN_MINING_POOLS):
                logging.warning(f"Mining pool domain detected: {host}")
            
            # Check for suspicious URLs
            url = http_layer.get('request_full_uri', '')
            if any(pattern.search(url) for pattern in SUSPICIOUS_PATTERNS):
                logging.warning(f"Suspicious mining-related URL detected: {url}")
    
    except KeyError as e:
        logging.error(f"KeyError while analyzing packet: {e}")
    except Exception as e:
        logging.error(f"Unexpected error while analyzing packet: {e}")

# Function to start live traffic analysis
def start_live_analysis(interface):
    logging.info(f"Starting live capture on interface: {interface}")
    capture = pyshark.LiveCapture(interface=interface)

    try:
        for packet in capture.sniff_continuously():
            analyze_packet(packet)
    except KeyboardInterrupt:
        logging.info("Stopping live capture")
    except Exception as e:
        logging.error(f"Error during packet capture: {e}")

# Main function
if __name__ == '__main__':
    if len(sys.argv) != 2:
        print("Usage: python script_name.py <network_interface>")
        sys.exit(1)
    
    network_interface = sys.argv[1]  # Replace with your network interface name (e.g., 'eth0', 'wlan0', 'en0', etc.)
    logging.info(f"Monitoring interface: {network_interface}")  # Debugging: Check if the interface is correctly defined
    start_live_analysis(network_interface)
