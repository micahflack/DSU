import sys

# Source: http://www.falatic.com/index.php/108/python-and-bitwise-rotation
rol = lambda val, r_bits, max_bits: \
    (val << r_bits%max_bits) & (2**max_bits-1) | \
    ((val & (2**max_bits-1)) >> (max_bits-(r_bits%max_bits)))

# Creates the hash based off of dll name
def create_module_hash(dll_name):
    result = 0x00000000

    for i in range(0,len(dll_name)):

        tmp = ord(dll_name[i])

        if tmp >= 0x41 or tmp < 0x5a:
            tmp = tmp | 0x20

        result = rol(result,7,32)
        result = result ^ tmp

    return result

#creates hash based off of WinAPI name (from Export directory->AddressOfNames)
def create_api_hash(export_name):
    api_hash = 0x00000000

    for i in range(0, len(export_name)):
        api_hash = rol(api_hash, 7, 32)
        api_hash = api_hash ^ ord(export_name[i])

    return api_hash


def main(argv):

	print "MODULE HASH ["+argv[0]+"]: " + hex(create_module_hash(argv[0])) + " - " + hex(create_api_hash(argv[1]))


if __name__ == '__main__':
	main(sys.argv[1:])