def convertUleb128BytesToInt(bs):
  # Calculates the end position (the highest bit is 0)
  for last in range(5):
    if bs[last] & 0x80 == 0:
      break

  value = 0
  for i in range(last + 1):
    value |= (bs[i] & 0x7f) << i * 7

  return value, last + 1


def convertIntToUleb128Bytes(value):
  bs = []

  for i in range(5):
    bs.append((value >> 7 * i) & 0x7f)

  for last in range(len(bs), 0, -1):
    if bs[last - 1] != 0:
      break

  for i in range(last - 1):
    bs[i] |= 0x80

  return bytes(bs[0x00:last]), last


def convertSleb128BytesToInt(bs):
  # Calculates the end position (the highest bit is 0)
  for last in range(5):
    if bs[last] & 0x80 == 0:
      break

  value = 0
  for i in range(last + 1):
    value = value + ((bs[i] & 0x7f) << (i * 7))
  if bs[i] & 0x40 != 0:
    value |= - (1 << (i * 7) + 7)
  return value, last + 1


def convertIntToSleb128Bytes(i):
  bs = []

  while True:
    byte = i & 0x7f
    i = i >> 7
    if (i == 0 and byte & 0x40 == 0) or (i == -1 and byte & 0x40 != 0):
      bs.append(byte)
      return bytes(bs), len(bs)
    bs.append(0x80 | byte)


if __name__ == '__main__':
  tes_value = 10417513783
  v, _ = convertIntToUleb128Bytes(tes_value)
  v2, _ = convertUleb128BytesToInt(v)
  print(tes_value, v, v2)

  tes_value = -123456
  v, _ = convertIntToSleb128Bytes(tes_value)
  v2, _ = convertSleb128BytesToInt(v)
  print(tes_value, v, v2)
