h1 = input("Enter first hash value in hex: ").strip()
h2 = input("Enter second hash value in hex: ").strip()

# Check if inputs are valid
if not h1 or not h2 or len(h1) != len(h2):
    print("Please ensure both hashes are provided and have the same length.")
    # Exit if inputs invalid
    import sys
    sys.exit(1)

differentBits = 0

for i in range(len(h1)):

    h1Ascii = ord(h1[i])
    h2Ascii = ord(h2[i])
    
    # xor the two ascii values to find the different bits.
    xorResult = h1Ascii ^ h2Ascii
    
    temp_xor = xorResult
    while temp_xor > 0:
        if temp_xor % 2 == 1:
            differentBits += 1
        temp_xor //= 2

totalBits = len(h1) * 8

print("Total bits compared (based on character ASCII): " + str(totalBits))
print("Number of different bits: " + str(differentBits))

sameBits = totalBits - differentBits
print("Number of same bits: " + str(sameBits))