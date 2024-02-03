from datetime import datetime

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


# Get the current date and time
now = datetime.now()

# Create a datetime object for the first day of the current year at midnight
start_of_year = datetime(now.year, 1, 1, 0, 0, 0)

# Optionally, if you need the timestamp as an integer (e.g., for Unix timestamp)
timestamp = int(start_of_year.timestamp())

hex_bytes = int_to_hex_bytes(timestamp)
print(f"CURRENT_YEAR        EQU    {str(now.year)[-2:]}")
print("START_OF_YEAR:")
print(f"        db    ${hex_bytes[3]}")
print(f"        db    ${hex_bytes[2]}")
print(f"        db    ${hex_bytes[1]}")
print(f"        db    ${hex_bytes[0]}")
