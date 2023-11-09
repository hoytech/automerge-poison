import math

## From: https://github.com/ept/byzantine-eventual/blob/master/evaluation/false_pos.py

def classic_bloom(bits, items, hashes):
  numerator = (bits ** (hashes * items) - (bits - 1) ** (hashes * items)) ** hashes
  denominator = bits ** (hashes * hashes * items)
  return numerator / denominator

bits_per_item = 10
hashes = 7

items = 400

print("False positive probability, normal: ", classic_bloom(bits_per_item * items, items, hashes))
print("False positive probability, poisoned: ", classic_bloom(int(bits_per_item * items / 8), items, hashes))
