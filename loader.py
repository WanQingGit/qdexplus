from qdexplus import dex_struct
from qstruct.backends.file_backend import *
from qstruct.base import QType
from qstruct.qarray import QArray


def main():
  QType.q_cached = {}
  QArray.q_const = True
  region = file_region.create('/home/wanqing/data/workspace/python/Code_Management/scripts/dexfactory/data/classes.dex')
  assert backend.memblock_add_range(region)

  dex_haader = dex_struct.DexHeader(region.base)
  assert dex_haader is dex_struct.DexHeader(region.base)
  dex_haader.fetch_once()
  if not dex_haader.verify():
    raise Exception
  print('end parser section header')


if __name__ == '__main__':
  backend = FileBackend.install(wordsize=4)
  main()
  FileBackend.uninstall()
