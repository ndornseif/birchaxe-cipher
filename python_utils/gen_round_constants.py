import hashlib
import math
import sys

# File with digits from "A Million Random Digits with 100,000 Normal Deviates"
RAND_DIGITS_FILE = "rand_digits.txt"
DIGTS_TO_READ = 2688


def digit_pair_to_bcd_byte(digit0, digit1):
    # Convert each digit to four bit BCD
    bcd0 = int(str(digit0), base=16) & 0b1111
    bcd1 = int(str(digit1), base=16) & 0b1111
    # Concatenate nibbles to byte
    return bcd0 + (bcd1 << 4)


def read_digits_file(filepath, lines):
    digits = []
    with open(filepath, "r", encoding="UTF-8") as file:
        # Read in first n lines
        for i in range(lines):
            if line := file.readline():
                # Lines are formatted as "index digt"
                # Extract only the digit
                split = line.split(" ")
                if len(split) > 1:
                    digits.append(int(split[1].rstrip()))
            else:
                raise ValueError(
                    f"Unable to read more than {i} lines. Expected to read {lines} lines."
                )
    return digits


def digit_list_to_bytearay(digits):
    return_bytes = bytearray()
    half_length = math.floor(len(digits) / 2)
    for i in range(half_length):
        # Convert pairs of digits to BCD
        digit0 = digits[2 * i]
        digit1 = digits[(2 * i) + 1]
        return_bytes.append(digit_pair_to_bcd_byte(digit0, digit1))
    return return_bytes


def hash_bytearray(input_array):
    result_hash = bytearray()
    for i in range(0, len(input_array), 32):
        if i + 32 > len(input_array):
            raise ValueError(
                f"Bytes not supplied in 32 byte blocks for hashing. Bytearray ends at {len(input_array)} expected end at {i+32}."
            )
        # Hash 32 bytes (256bits) of RAND BCD
        chunk = input_array[i : i + 32]
        h = hashlib.new("sha3_256")
        h.update(chunk)
        # Save as bytes.
        for byte in h.digest():
            result_hash.append(byte)
    return result_hash


def gen_round_constants(input_bytearray):
    """
    Takes in 1024 bytes and formats them for inclusion as a [[[u8; 16]; 2]; 32] in rust code.
    """
    return_array = []
    for roundc in range(32):
        half_array = []
        for half in range(2):
            inner_bytes = []
            for byte in range(16):
                read_byte = input_bytearray.pop()
                # Convert to hex with min with of four so 0x4 turns to 0x04
                inner_bytes.append(f"{read_byte:#04x}")
            half_array.append(inner_bytes)
        return_array.append(half_array)

    # Format for easy copying to rust
    return_str = ""
    for roundc in return_array:
        roundc_str = str(roundc)
        # Remove string delimeter from bytes: '0xff' to 0xff
        roundc_str = roundc_str.replace("'", "")
        return_str += roundc_str + ",\n"

    return return_str


def gen_shift_table(input_bytearray):
    """
    Takes in 256 bytes and generates 256 values between 0 and 63.
    Formats them for inclusion in rust code as [u32; 256].
    """
    shift_array = []
    for i in range(256):
        shift_value = int(input_bytearray.pop()) % 64
        shift_array.append(shift_value)

    return_str = str(shift_array)
    return return_str


def gen_key_iv(input_bytearray):
    """
    Takes in 64 bytes and formats them for easy inclusion in rust as [u8; 64].
    """
    return_array = []
    for i in range(64):
        read_byte = input_bytearray.pop()
        return_array.append(f"{read_byte:#04x}")

    # Remove string delimeter from bytes '0xff' to 0xff
    return_str = str(return_array)
    return_str = return_str.replace("'", "")
    return return_str


def main():
    rand_digits = read_digits_file(RAND_DIGITS_FILE, DIGTS_TO_READ)
    rand_bytes = digit_list_to_bytearay(rand_digits)
    rand_hash = hash_bytearray(rand_bytes)
    # Take first 1024 bytes
    print("Round constants:")
    print(gen_round_constants(rand_hash[:1024]))
    # Take next 256 bytes
    print("Shift table:")
    print(gen_shift_table(rand_hash[1024:1280]))
    # Take next 64 bytes
    print("Key IV:")
    print(gen_key_iv(rand_hash[1280:1344]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
