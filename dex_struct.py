from typing import Dict, Union, List

from qdexplus.dex_insns_item import DexInsnsItem
from qdexplus.utils import convertUleb128BytesToInt, convertIntToUleb128Bytes, convertSleb128BytesToInt, \
  convertIntToSleb128Bytes
from qstruct.base import QType, QStructField
from qstruct.contrib import android_dexfile
from qstruct.contrib.android_dexfile import QDexStruct, DexTypeId, DexMethodId, DexFieldId, DexClassDef, DexTypeItem, \
  DexMapItem, kDexTypeCodeItem
from qstruct.primary import QUInt8, QTChar, QUInt32
from qstruct.qarray import QArray32
from qstruct.qpointer import QPointer32

QDexStruct.q_def_pointer_cls = QPointer32
QDexStruct.array_wrapper = QArray32


class DexDynamicArray(object):
  q_size_attr = ['size']
  q_list_attr = ['list']
  q_objsize: int

  @classmethod
  def class_on_create(cls):
    if type(cls.q_size_attr) != list:
      size_attr = [cls.q_size_attr]
      cls.q_size_attr = size_attr
    if type(cls.q_list_attr) != list:
      list_attr = [cls.q_list_attr]
      cls.q_list_attr = list_attr
    size_attr = cls.q_size_attr
    list_attr = cls.q_list_attr
    num = len(size_attr)
    assert len(list_attr) == num
    for i in range(num):
      extra_on_field_change = 'on_change_' + size_attr[i]
      setattr(cls, extra_on_field_change, cls.dex_list_size_change)

  def dex_list_size_change(self, field: QStructField, attr_name, list_size, osize):
    idx = self.q_size_attr.index(attr_name)
    list_attr = self.q_list_attr[idx]
    vector = getattr(self, list_attr)
    # vector.set_dynamic(True)
    vector.set_length(list_size)
    # vector.set_dynamic(False)


class DexMapList(DexDynamicArray, android_dexfile.DexMapList):
  pass


class DexTypeList(DexDynamicArray, android_dexfile.DexTypeList):
  pass


class DexAnnotationSetItem(DexDynamicArray, android_dexfile.DexAnnotationSetItem):
  q_list_attr = 'entries'


class DexStringData(DexDynamicArray, QDexStruct):
  q_list_attr = 'str'
  size = QUInt8
  str = (QTChar[0]).extend(fmt=lambda _, x: (b''.join(x)).decode())


class DexStringId(QDexStruct):
  stringDataOff = DexStringData * 1  # file offset to string_data_item


class DexProtoId(QDexStruct):
  q_desc = 'Direct-mapped "proto_id_item".'
  shortyIdx = QUInt32  # index into stringIds for shorty descriptor
  returnTypeIdx = QUInt32  # index into typeIds list for return type
  parametersOff = DexTypeList * 1  # file offset to type_list for parameter types


class DexHeader(android_dexfile.DexHeader):
  mapOff = (DexMapList * 1)
  stringIdsOff = DexStringId[0] * 1
  typeIdsOff = DexTypeId[0] * 1
  protoIdsOff = DexProtoId[0] * 1
  methodIdsOff = DexMethodId[0] * 1
  fieldIdsOff = DexFieldId[0] * 1
  classDefsOff = DexClassDef[0] * 1

  off_watch = ['stringIdsOff', 'typeIdsOff', 'protoIdsOff', 'methodIdsOff', 'fieldIdsOff', 'classDefsOff']
  size_watch = [i[:-3] + 'Size' for i in off_watch]

  def __init__(self, *args, **kwargs):
    super().__init__(*args, **kwargs)
    self.stringIds = []
    self.typeIds = []
    self.protoIds = []
    self.methodIds = []
    self.fieldIds = []
    self.classDefs = []

  def on_field_change(self, field: QStructField, name, nval, oval):
    if name in self.off_watch:
      if nval <= 0:
        return
      idx = self.off_watch.index(name)
      size = getattr(self, self.size_watch[idx])
      vector = getattr(self, name)[0]  # equal getattr(self, name)*1,take out the pointer value
      vector.set_length(size)
      vector.fetch_value()
    elif name in self.size_watch:
      idx = self.size_watch.index(name)
      vector = getattr(self, self.off_watch[idx])
      if vector > 0:
        vector[0].set_length(nval)

  def finish_load(self):
    if self.stringIdsOff > 0:
      stringIds = self.stringIds
      stringIds.clear()
      stringIdsOff: List[DexStringId] = self.stringIdsOff * 1
      for dex_string_id in stringIdsOff:
        dex_string: DexStringData = dex_string_id.stringDataOff * 1
        stringIds.append(str(dex_string.str))
    else:
      return
    if self.typeIdsOff > 0:
      typeIds = self.typeIds
      typeIds.clear()
      dex_typeids: List[DexTypeId] = self.typeIdsOff * 1
      for typeid in dex_typeids:
        tsid = typeid.descriptorIdx.value()
        data = stringIds[tsid]
        typeIds.append(data)
    else:
      return
    if self.protoIdsOff <= 0:
      return
    protoIds = self.protoIds
    protoIds.clear()
    dex_proto_ids: List[DexProtoId] = self.protoIdsOff * 1
    for item in dex_proto_ids:
      sidx = item.shortyIdx.value()
      name = stringIds[sidx]
      ret = typeIds[item.returnTypeIdx.value()]
      type_list: DexTypeList = item.parametersOff[0]
      params = []
      if type_list is not None and type_list.size > 0:
        tlist: List[DexTypeItem] = type_list.list
        for type_item in tlist:
          ps = typeIds[type_item.typeIdx.value()]
          params.append(ps)
      protoIds.append("{} {}({})".format(ret, name, ''.join(params)))
    if self.methodIdsOff <= 0:
      return

    methodIds = self.methodIds
    methodIds.clear()
    dex_method_ids: List[DexMethodId] = self.methodIdsOff * 1
    for dex_method_id in dex_method_ids:
      class_name = typeIds[dex_method_id.classIdx.value()]
      proto = protoIds[dex_method_id.protoIdx.value()]
      name = stringIds[dex_method_id.nameIdx.value()]
      methodIds.append("{} --> {} {}".format(class_name, proto, name))
    print('\n'.join(methodIds))
    if self.fieldIdsOff <= 0:
      return
    dex_field_ids: List[DexFieldId] = self.fieldIdsOff * 1
    fieldIds = self.fieldIds
    fieldIds.clear()
    for dex_field_id in dex_field_ids:
      class_name = typeIds[dex_field_id.classIdx.value()]
      type_name = typeIds[dex_field_id.typeIdx.value()]
      name = stringIds[dex_field_id.nameIdx.value()]
      fieldIds.append('{} --> {} {}'.format(class_name, type_name, name))

    if self.classDefsOff <= 0:
      return
    classDefs = self.classDefs
    classDefs.clear()
    dex_class_defs: List[DexClassDef] = self.classDefsOff * 1
    for dex_class_def in dex_class_defs:
      class_idx = dex_class_def.classIdx.value()
      cls_name = typeIds[class_idx]
      access_flags = dex_class_def.accessFlags.value()
      super_class = typeIds[dex_class_def.superclassIdx.value()]
      source_file = stringIds[dex_class_def.sourceFileIdx.value()]
      # if dex_class_def.interfacesOff.value():
      #   dex_type_list = DexTypeList(dex_class_def.interfacesOff)
      # if dex_class_def.annotationsOff.value():
      #   annotations_dir = DexAnnotationsDirectoryItem(dex_class_def.annotationsOff)
      # if dex_class_def.classDataOff.value():
      #   dex_class_data: DexClassData = dex_class_def.classDataOff[0]
      #   if dex_class_data.directMethods.get_length() > 0:
      #     pass
      cls_des = "{}:{}  ---> {} {} extends {} {}".format(class_idx, source_file, access_flags, cls_name,
                                                         super_class, '')
      print(cls_des)
      classDefs.append(cls_des)
    if self.mapOff <= 0:
      return
    dex_map_list = self.mapOff * 1
    map_list: List[DexMapItem] = dex_map_list.list
    for dex_map_item in map_list:
      item_type = dex_map_item.type.value()
      if item_type == kDexTypeCodeItem:
        ArrayType = DexCode[dex_map_item.size]
        items = ArrayType(dex_map_item.offset)
        self.parse_code_items(items)

  def parse_code_items(self, dex_code_items: List['DexCode']):
    for dex_code_item in dex_code_items:
      insns: List[DexInsnsItem] = dex_code_item.insns
      for insns_item in insns:
        print(insns_item.desc)
        kind = insns_item.kind
        kind_x = insns_item.kind_x
        proto_x = insns_item.proto_x
        if kind is None and proto_x is None:
          continue
        if proto_x is not None:
          proto = self.protoIds[proto_x]
        else:
          proto = None
        kind_desc = None
        if kind:
          if 'string'.__eq__(kind):
            kind_desc = self.stringIds[kind_x]
          elif 'type'.__eq__(kind):
            kind_desc = self.typeIds[kind_x]
          elif 'field'.__eq__(kind):
            kind_desc = self.fieldIds[kind_x]
          elif 'meth'.__eq__(kind):
            kind_desc = self.methodIds[kind_x]
          elif 'site'.__eq__(kind):
            raise NotImplemented
          elif 'proto'.__eq__(kind):
            proto = self.protoIds[kind_x]
          elif 'vtaboff'.__eq__(kind):
            raise NotImplemented
          elif 'fieldoff'.__eq__(kind):
            raise NotImplemented
        fmt = insns_item.format(kind_desc, proto)
        print(fmt)


# class DexClassData(QDexStruct):
assert DexStringId.q_objsize == 4
assert DexProtoId.q_objsize == 12
assert DexHeader.q_objsize == android_dexfile.DexHeader.q_objsize


class Qleb128(QType):
  q_dynamic = True
  q_def_value = 0
  q_bs = b'\x00'
  q_objsize = 1
  q_value = None
  decode = None
  encode = None

  def fetch_dy_value(self):
    # addr = self.address()
    bs = self.read_self(5)
    v, size = self.decode(bs)
    self.set_value(v)
    assert self.q_objsize == size
    return True

  def set_value(self, val):
    self.q_bs, q_objsize = self.encode(val)
    super().set_value(val)
    self.set_objsize(q_objsize)

  def serial(self) -> Union[Dict[int, bytes], bytes]:
    return self.q_bs

  def unserial(self, datas, offset: int = 0):
    self.set_value(self.decode(datas[offset:offset + 5])[0])


class QUleb128(Qleb128):
  decode = staticmethod(convertUleb128BytesToInt)
  encode = staticmethod(convertIntToUleb128Bytes)


class QSleb128(Qleb128):
  decode = staticmethod(convertSleb128BytesToInt)
  encode = staticmethod(convertIntToSleb128Bytes)


# -------------DexClass-------------------

class DexClassDataHeader(QDexStruct):
  staticFieldsSize = QUleb128
  instanceFieldsSize = QUleb128
  directMethodsSize = QUleb128
  virtualMethodsSize = QUleb128


assert DexClassDataHeader.q_objsize == 4


class DexField(QDexStruct):
  q_desc = """
  expanded form of encoded_field
  """
  fieldIdx = QUleb128  # index to a field_id_item
  accessFlags = QUleb128


class DexMethod(QDexStruct):
  """
  expanded form of encoded_method
  """

  methodIdx = QUleb128  # index to a method_id_item
  accessFlags = QUleb128
  codeOff = QUleb128  # file offset to a code_item


class DexClassData(QDexStruct):
  q_monitor_change = True
  """
  expanded form of class_data_item. Note: If a particular item is
 * absent (e.g., no static fields), then the corresponding pointer
 * is set to NULL.
  """

  header = DexClassDataHeader
  staticFields = DexField[0]
  instanceFields = DexField[0]
  directMethods = DexMethod[0]
  virtualMethods = DexMethod[0]

  # def on_leaf_value_change(self, child, leaf, val, cids):
  #   print(cids, val)

  def on_leaf_change_header_staticFieldsSize(self, child, leaf, val):
    self.staticFields.set_length(val)

  def on_leaf_change_header_instanceFieldsSize(self, child, leaf, val):
    self.instanceFields.set_length(val)

  def on_leaf_change_header_directMethodsSize(self, child, leaf, val):
    self.directMethods.set_length(val)

  def on_leaf_change_header_virtualMethodsSize(self, child, leaf, val):
    self.virtualMethods.set_length(val)


class DexTypeAddrPairData(QDexStruct):
  type_idx = QUleb128
  addr = QUleb128


class DexCatchHandlerData(QDexStruct):
  size = QSleb128
  handlers = DexTypeAddrPairData[0]
  catch_all_addr = QUleb128[0]


class DexCatchHandlerListData(DexDynamicArray, QDexStruct):
  size = QUleb128
  list = DexCatchHandlerData[0]


class DexCode(DexDynamicArray, android_dexfile.DexCode):
  q_list_attr = ["try_item"]
  q_size_attr = ["triesSize"]
  try_item = android_dexfile.DexTry[0]
  handlers = DexCatchHandlerListData[0]

  insns = (DexInsnsItem[0])

  def on_leaf_value_change(self, child, leaf, val, cids: List[str]):
    print(cids, val)

  def on_field_change(self, field: QStructField, name, nval, oval):
    if name == 'triesSize':
      if self.triesSize > 0:
        self.handlers.set_length(1)
    elif name == 'insnsSize':
      if self.insnsSize > 0:
        self.insns.size_fix(self.insnsSize.value() * 2)
      else:
        assert self.insnsSize == 0
        self.insns.set_length(0)


class DexClassDef(android_dexfile.DexClassDef):
  classDataOff = DexClassData * 1
