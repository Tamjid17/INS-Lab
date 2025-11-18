h1 = input("Enter first hash value in hex: ").strip()
h2 = input("Enter second hash value in hex: ").strip()

# Check if inputs are valid
if not h1 or not h2 or len(h1) != len(h2):
    print("Please ensure both hashes are provided and have the same length.")
    # Exit if inputs invalid
    import sys
    sys.exit(1)

# Convert hex string to integer to binary
b1 = bin(int(h1, 16))[2:].zfill(len(h1) * 4)
b2 = bin(int(h2, 16))[2:].zfill(len(h2) * 4)

# Count bit matches
same_bits = sum(1 for x, y in zip(b1, b2) if x == y)
diff_bits = len(b1) - same_bits

print(f"Total bits compared: {len(b1)}")
print(f"Number of same bits: {same_bits}")
print(f"Number of different bits: {diff_bits}")

percentage = (same_bits / len(b1)) * 100
print(f"Percentage of matching bits: {percentage:.2f}%")