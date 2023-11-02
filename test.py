hex_string = "06 67 6f 6f 67 6c 65 03 63 6f 6d 00"
hex_values = hex_string.split()  # Split the hex string into individual values

# Convert each hex value to its corresponding ASCII character and join them
translated_string = ''.join([chr(int(value, 16)) for value in hex_values])

print(translated_string)