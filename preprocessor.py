from datetime import datetime
import math
import sys

def int_to_hex_bytes(num):
    """
    Given a 32-bit integer, returns a list of four hexadecimal strings,
    each representing one byte of the integer.
    """
    # Mask to extract 8 bits
    mask = 0xFF
    
    # Extract each byte and convert to hex
    byte1 = (num >> 24) & mask  # Shift right 24 bits and mask to get the first byte
    byte2 = (num >> 16) & mask  # Shift right 16 bits and mask to get the second byte
    byte3 = (num >> 8) & mask   # Shift right 8 bits and mask to get the third byte
    byte4 = num & mask          # Mask to get the fourth byte
    
    # Format each byte as hex and return the list
    return [f"{byte1:02X}", f"{byte2:02X}", f"{byte3:02X}", f"{byte4:02X}"]


def tcount():
    # Get the current date and time
    now = datetime.utcnow()

    # Optionally, if you need the timestamp as an integer (e.g., for Unix timestamp)
    timestamp = int(math.floor(now.timestamp()/30))
    hex_bytes = int_to_hex_bytes(timestamp)

    return f"TCOUNT    db   ${hex_bytes[3]},${hex_bytes[2]},${hex_bytes[1]},${hex_bytes[0]}"


SYMBOLS = {
    "%TCOUNT%": tcount,
}


def main():
    for line in sys.stdin:
        line = line.strip()
        if line in SYMBOLS:
            line = SYMBOLS[line]()
        print(line)


if __name__ == '__main__':
    main()
