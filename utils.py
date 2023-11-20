def ascii_to_binary_list(input_string):
    binary_list = []

    for char in input_string:
        # Convert each character to its ASCII representation and then to binary
        binary_representation = bin(ord(char))[2:]
        
        # Ensure each binary representation is 8 bits long by padding with leading zeros
        binary_representation = '0' * (8 - len(binary_representation)) + binary_representation
        
        # Append the binary representation to the list
        binary_digits = [int(bit) for bit in binary_representation]
        binary_list.extend(binary_digits)

    return binary_list


def binary_list_to_ascii(binary_list):
    ascii_string = ""

    # Group the binary digits into chunks of 8
    chunks = [binary_list[i:i+8] for i in range(0, len(binary_list), 8)]

    for binary_digits in chunks:
        # Convert each integer to a string and join them together
        binary_representation = ''.join(map(str, binary_digits))

        # Convert binary representation to decimal and then to ASCII character
        ascii_character = chr(int(binary_representation, 2))
        
        # Append the ASCII character to the string
        ascii_string += ascii_character

    return ascii_string