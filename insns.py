# -- coding: utf-8 --

from typing import Dict

KIND_NONE = ''
# 字符串池索引
KIND_STRING = 'string'
# 类型池索引
KIND_TYPE = 'type'
# 字段池索引
KIND_FIELD = 'field'
# 方法池索引
KIND_METHOD = 'meth'
# 调用点索引
KIND_SITE = 'site'
# 原型池索引
KIND_PROTO = 'proto'
# vtable 偏移
KIND_VTABLE = 'vtaboff'
# 字段偏移
KIND_FIELDOFF = 'fieldoff'


class Op(object):
  def __init__(self, val, fmt, strval, kind):
    self.val = val
    self.strval = strval
    self.kind = kind
    self.format = fmt
    op_map[val] = self

  def __repr__(self):
    return self.strval

  def __hash__(self):
    return self.val.__hash__()

  def __eq__(self, val):
    return self.val.__eq__(val)

  def formatOp(self):
    return '%-24s' % self.strval


op_map: Dict[int, Op] = {}
Op(0x00, '10x', 'nop', KIND_NONE)
Op(0x01, '12x', 'move', KIND_NONE)
Op(0x02, '22x', 'move/from16', KIND_NONE)
Op(0x03, '32x', 'move/16', KIND_NONE)
Op(0x04, '12x', 'move-wide', KIND_NONE)
Op(0x05, '22x', 'move-wide/from16', KIND_NONE)
Op(0x06, '32x', 'move-wide/16', KIND_NONE)
Op(0x07, '12x', 'move-object', KIND_NONE)
Op(0x08, '22x', 'move-object/from16', KIND_NONE)
Op(0x09, '32x', 'move-object/16', KIND_NONE)
Op(0x0A, '11x', 'move-result', KIND_NONE)
Op(0x0B, '11x', 'move-result-wide', KIND_NONE)
Op(0x0C, '11x', 'move-result-object', KIND_NONE)
Op(0x0D, '11x', 'move-exception', KIND_NONE)
Op(0x0E, '10x', 'return-void', KIND_NONE)
Op(0x0F, '11x', 'return', KIND_NONE)

Op(0x10, '11x', 'return-wide', KIND_NONE)
Op(0x11, '11x', 'return-object', KIND_NONE)
Op(0x12, '11n', 'const/4', KIND_NONE)
Op(0x13, '21s', 'const/16', KIND_NONE)
Op(0x14, '31i', 'const', KIND_NONE)
Op(0x15, '21h', 'const/high16', KIND_NONE)
Op(0x16, '21s', 'const-wide/16', KIND_NONE)
Op(0x17, '31i', 'const-wide/32', KIND_NONE)
Op(0x18, '51l', 'const-wide', KIND_NONE)
Op(0x19, '21h', 'const-wide/high16', KIND_NONE)
Op(0x1A, '21c', 'const-string', KIND_STRING)
Op(0x1B, '31c', 'const-string-jumbo', KIND_STRING)
Op(0x1C, '21c', 'const-class', KIND_TYPE)
Op(0x1D, '11x', 'monitor-enter', KIND_NONE)
Op(0x1E, '11x', 'monitor-exit', KIND_NONE)
Op(0x1F, '21c', 'check-cast', KIND_TYPE)

Op(0x20, '22c', 'instance-of', KIND_TYPE)
Op(0x21, '12x', 'array-length', KIND_NONE)
Op(0x22, '21c', 'new-instance', KIND_TYPE)
Op(0x23, '22c', 'new-array', KIND_TYPE)
Op(0x24, '35c', 'filled-new-array', KIND_TYPE)
Op(0x25, '3rc', 'filled-new-array-range', KIND_TYPE)
Op(0x26, '31t', 'fill-array-data', KIND_NONE)
Op(0x27, '11x', 'throw', KIND_NONE)
Op(0x28, '10t', 'goto', KIND_NONE)
Op(0x29, '20t', 'goto/16', KIND_NONE)
Op(0x2A, '30t', 'goto/32', KIND_NONE)
Op(0x2B, '31t', 'packed-switch', KIND_NONE)
Op(0x2C, '31t', 'sparse-switch', KIND_NONE)
Op(0x2D, '23x', 'cmpl-float', KIND_NONE)
Op(0x2E, '23x', 'cmpg-float', KIND_NONE)
Op(0x2F, '23x', 'cmpl-double', KIND_NONE)

Op(0x30, '23x', 'cmpg-double', KIND_NONE)
Op(0x31, '23x', 'cmp-long', KIND_NONE)
Op(0x32, '22t', 'if-eq', KIND_NONE)
Op(0x33, '22t', 'if-ne', KIND_NONE)
Op(0x34, '22t', 'if-lt', KIND_NONE)
Op(0x35, '22t', 'if-ge', KIND_NONE)
Op(0x36, '22t', 'if-gt', KIND_NONE)
Op(0x37, '22t', 'if-le', KIND_NONE)
Op(0x38, '21t', 'if-eqz', KIND_NONE)
Op(0x39, '21t', 'if-nez', KIND_NONE)
Op(0x3A, '21t', 'if-ltz', KIND_NONE)
Op(0x3B, '21t', 'if-gez', KIND_NONE)
Op(0x3C, '21t', 'if-gtz', KIND_NONE)
Op(0x3D, '21t', 'if-lez', KIND_NONE)
Op(0x3E, '', 'unused', KIND_NONE)
Op(0x3F, '', 'unused', 'unused')

Op(0x40, '', 'unused', KIND_NONE)
Op(0x41, '', 'unused', KIND_NONE)
Op(0x42, '', 'unused', KIND_NONE)
Op(0x43, '', 'unused', KIND_NONE)
Op(0x44, '23x', 'aget', KIND_NONE)
Op(0x45, '23x', 'aget-wide', KIND_NONE)
Op(0x46, '23x', 'aget-object', KIND_NONE)
Op(0x47, '23x', 'aget-boolean', KIND_NONE)
Op(0x48, '23x', 'aget-byte', KIND_NONE)
Op(0x49, '23x', 'aget-char', KIND_NONE)
Op(0x4A, '23x', 'aget-short', KIND_NONE)
Op(0x4B, '23x', 'aput', KIND_NONE)
Op(0x4C, '23x', 'aput-wide', KIND_NONE)
Op(0x4D, '23x', 'aput-object', KIND_NONE)
Op(0x4E, '23x', 'aput-boolean', KIND_NONE)
Op(0x4F, '23x', 'aput-byte', KIND_NONE)

Op(0x50, '23x', 'aput-char', KIND_NONE)
Op(0x51, '23x', 'aput-short', KIND_NONE)
Op(0x52, '22c', 'iget', KIND_FIELD)
Op(0x53, '22c', 'iget-wide', KIND_FIELD)
Op(0x54, '22c', 'iget-object', KIND_FIELD)
Op(0x55, '22c', 'iget-boolean', KIND_FIELD)
Op(0x56, '22c', 'iget-byte', KIND_FIELD)
Op(0x57, '22c', 'iget-char', KIND_FIELD)
Op(0x58, '22c', 'iget-short', KIND_FIELD)
Op(0x59, '22c', 'iput', KIND_FIELD)
Op(0x5A, '22c', 'iput-wide', KIND_FIELD)
Op(0x5B, '22c', 'iput-object', KIND_FIELD)
Op(0x5C, '22c', 'iput-boolean', KIND_FIELD)
Op(0x5D, '22c', 'iput-byte', KIND_FIELD)
Op(0x5E, '22c', 'iput-char', KIND_FIELD)
Op(0x5F, '22c', 'iput-short', KIND_FIELD)

Op(0x60, '21c', 'sget', KIND_FIELD)
Op(0x61, '21c', 'sget-wide', KIND_FIELD)
Op(0x62, '21c', 'sget-object', KIND_FIELD)
Op(0x63, '21c', 'sget-boolean', KIND_FIELD)
Op(0x64, '21c', 'sget-byte', KIND_FIELD)
Op(0x65, '21c', 'sget-char', KIND_FIELD)
Op(0x66, '21c', 'sget-short', KIND_FIELD)
Op(0x67, '21c', 'sput', KIND_FIELD)
Op(0x68, '21c', 'sput-wide', KIND_FIELD)
Op(0x69, '21c', 'sput-object', KIND_FIELD)
Op(0x6A, '21c', 'sput-boolean', KIND_FIELD)
Op(0x6B, '21c', 'sput-byte', KIND_FIELD)
Op(0x6C, '21c', 'sput-char', KIND_FIELD)
Op(0x6D, '21c', 'sput-short', KIND_FIELD)
Op(0x6E, '35c', 'invoke-virtual', KIND_METHOD)
Op(0x6F, '35c', 'invoke-super', KIND_METHOD)

Op(0x70, '35c', 'invoke-direct', KIND_METHOD)
Op(0x71, '35c', 'invoke-static', KIND_METHOD)
Op(0x72, '35c', 'invoke-interface', KIND_METHOD)
Op(0x73, '10x', 'unused', KIND_NONE)
Op(0x74, '3rc', 'invoke-virtual/range', KIND_METHOD)
Op(0x75, '3rc', 'invoke-super/range', KIND_METHOD)
Op(0x76, '3rc', 'invoke-direct/range', KIND_METHOD)
Op(0x77, '3rc', 'invoke-static/range', KIND_METHOD)
Op(0x78, '3rc', 'invoke-interface-range', KIND_METHOD)
Op(0x79, '', 'unused', KIND_NONE)
Op(0x7A, '', 'unused', KIND_NONE)
Op(0x7B, '12x', 'neg-int', KIND_NONE)
Op(0x7C, '12x', 'not-long', KIND_NONE)
Op(0x7D, '12x', 'neg-long', KIND_NONE)
Op(0x7E, '12x', 'not-long', KIND_NONE)
Op(0x7F, '12x', 'neg-float', KIND_NONE)

Op(0x80, '12x', 'neg-double', KIND_NONE)
Op(0x81, '12x', 'int-to-long', KIND_NONE)
Op(0x82, '12x', 'int-to-float', KIND_NONE)
Op(0x83, '12x', 'int-to-double', KIND_NONE)
Op(0x84, '12x', 'long-to-int', KIND_NONE)
Op(0x85, '12x', 'long-to-float', KIND_NONE)
Op(0x86, '12x', 'long-to-double', KIND_NONE)
Op(0x87, '12x', 'float-to-int', KIND_NONE)
Op(0x88, '12x', 'float-to-long', KIND_NONE)
Op(0x89, '12x', 'float-to-double', KIND_NONE)
Op(0x8A, '12x', 'double-to-int', KIND_NONE)
Op(0x8B, '12x', 'double-to-long', KIND_NONE)
Op(0x8C, '12x', 'double-to-float', KIND_NONE)
Op(0x8D, '12x', 'int-to-byte', KIND_NONE)
Op(0x8E, '12x', 'int-to-char', KIND_NONE)
Op(0x8F, '12x', 'int-to-short', KIND_NONE)

Op(0x90, '23x', 'add-int', KIND_NONE)
Op(0x91, '23x', 'sub-int', KIND_NONE)
Op(0x92, '23x', 'mul-int', KIND_NONE)
Op(0x93, '23x', 'div-int', KIND_NONE)
Op(0x94, '23x', 'rem-int', KIND_NONE)
Op(0x95, '23x', 'and-int', KIND_NONE)
Op(0x96, '23x', 'or-int', KIND_NONE)
Op(0x97, '23x', 'xor-int', KIND_NONE)
Op(0x98, '23x', 'shl-int', KIND_NONE)
Op(0x99, '23x', 'shr-int', KIND_NONE)
Op(0x9A, '23x', 'ushr-int', KIND_NONE)
Op(0x9B, '23x', 'add-long', KIND_NONE)
Op(0x9C, '23x', 'sub-long', KIND_NONE)
Op(0x9D, '23x', 'mul-long', KIND_NONE)
Op(0x9E, '23x', 'div-long', KIND_NONE)
Op(0x9F, '23x', 'rem-long', KIND_NONE)

Op(0xA0, '23x', 'and-long', KIND_NONE)
Op(0xA1, '23x', 'or-long', KIND_NONE)
Op(0xA2, '23x', 'xor-long', KIND_NONE)
Op(0xA3, '23x', 'shl-long', KIND_NONE)
Op(0xA4, '23x', 'shr-long', KIND_NONE)
Op(0xA5, '23x', 'ushr-long', KIND_NONE)
Op(0xA6, '23x', 'add-float', KIND_NONE)
Op(0xA7, '23x', 'sub-float', KIND_NONE)
Op(0xA8, '23x', 'mul-float', KIND_NONE)
Op(0xA9, '23x', 'div-float', KIND_NONE)
Op(0xAA, '23x', 'rem-float', KIND_NONE)
Op(0xAB, '23x', 'add-double', KIND_NONE)
Op(0xAC, '23x', 'sub-double', KIND_NONE)
Op(0xAD, '23x', 'mul-double', KIND_NONE)
Op(0xAE, '23x', 'div-double', KIND_NONE)
Op(0xAF, '23x', 'rem-double', KIND_NONE)

Op(0xB0, '12x', 'add-int/2addr', KIND_NONE)
Op(0xB1, '12x', 'sub-int/2addr', KIND_NONE)
Op(0xB2, '12x', 'mul-int/2addr', KIND_NONE)
Op(0xB3, '12x', 'div-int/2addr', KIND_NONE)
Op(0xB4, '12x', 'rem-int/2addr', KIND_NONE)
Op(0xB5, '12x', 'and-int/2addr', KIND_NONE)
Op(0xB6, '12x', 'or-int/2addr', KIND_NONE)
Op(0xB7, '12x', 'xor-int/2addr', KIND_NONE)
Op(0xB8, '12x', 'shl-int/2addr', KIND_NONE)
Op(0xB9, '12x', 'shr-int/2addr', KIND_NONE)
Op(0xBA, '12x', 'ushr-int/2addr', KIND_NONE)
Op(0xBB, '12x', 'add-long/2addr', KIND_NONE)
Op(0xBC, '12x', 'sub-long/2addr', KIND_NONE)
Op(0xBD, '12x', 'mul-long/2addr', KIND_NONE)
Op(0xBE, '12x', 'div-long/2addr', KIND_NONE)
Op(0xBF, '12x', 'rem-long/2addr', KIND_NONE)

Op(0xC0, '12x', 'and-long/2addr', KIND_NONE)
Op(0xC1, '12x', 'or-long/2addr', KIND_NONE)
Op(0xC2, '12x', 'xor-long/2addr', KIND_NONE)
Op(0xC3, '12x', 'shl-long/2addr', KIND_NONE)
Op(0xC4, '12x', 'shr-long/2addr', KIND_NONE)
Op(0xC5, '12x', 'ushr-long/2addr', KIND_NONE)
Op(0xC6, '12x', 'add-float/2addr', KIND_NONE)
Op(0xC7, '12x', 'sub-float/2addr', KIND_NONE)
Op(0xC8, '12x', 'mul-float/2addr', KIND_NONE)
Op(0xC9, '12x', 'div-float/2addr', KIND_NONE)
Op(0xCA, '12x', 'rem-float/2addr', KIND_NONE)
Op(0xCB, '12x', 'add-double/2addr', KIND_NONE)
Op(0xCC, '12x', 'sub-double/2addr', KIND_NONE)
Op(0xCD, '12x', 'mul-double/2addr', KIND_NONE)
Op(0xCE, '12x', 'div-double/2addr', KIND_NONE)
Op(0xCF, '12x', 'rem-double/2addr', KIND_NONE)

Op(0xD0, '22s', 'add-int/lit16', KIND_NONE)
Op(0xD1, '22s', 'sub-int/lit16', KIND_NONE)
Op(0xD2, '22s', 'mul-int/lit16', KIND_NONE)
Op(0xD3, '22s', 'div-int/lit16', KIND_NONE)
Op(0xD4, '22s', 'rem-int/lit16', KIND_NONE)
Op(0xD5, '22s', 'and-int/lit16', KIND_NONE)
Op(0xD6, '22s', 'or-int/lit16', KIND_NONE)
Op(0xD7, '22s', 'xor-int/lit16', KIND_NONE)
Op(0xD8, '22b', 'add-int/lit8', KIND_NONE)
Op(0xD9, '22b', 'sub-int/lit8', KIND_NONE)
Op(0xDA, '22b', 'mul-int/lit8', KIND_NONE)
Op(0xDB, '22b', 'div-int/lit8', KIND_NONE)
Op(0xDC, '22b', 'rem-int/lit8', KIND_NONE)
Op(0xDD, '22b', 'and-int/lit8', KIND_NONE)
Op(0xDE, '22b', 'or-int/lit8', KIND_NONE)
Op(0xDF, '22b', 'xor-int/lit8', KIND_NONE)

Op(0xE0, '22b', 'shl-int/lit8', KIND_NONE)
Op(0xE1, '22b', 'shr-int/lit8', KIND_NONE)
Op(0xE2, '22b', 'ushr-int/lit8', KIND_NONE)
Op(0xE3, '', 'unused', KIND_NONE)
Op(0xE4, '', 'unused', KIND_NONE)
Op(0xE5, '', 'unused', KIND_NONE)
Op(0xE6, '', 'unused', KIND_NONE)
Op(0xE7, '', 'unused', KIND_NONE)
Op(0xE8, '', 'unused', KIND_NONE)
Op(0xE9, '', 'unused', KIND_NONE)
Op(0xEA, '', 'unused', KIND_NONE)
Op(0xEB, '', 'unused', KIND_NONE)
Op(0xEC, '', 'unused', KIND_NONE)
Op(0xED, '', 'unused', KIND_NONE)
Op(0xEE, '', 'execute-inline', KIND_NONE)
Op(0xEF, '', 'unused', KIND_NONE)

Op(0xF0, '', 'invoke-direct-empty', KIND_NONE)
Op(0xF1, '', 'unused', KIND_NONE)
Op(0xF2, '', 'iget-quick', KIND_NONE)
Op(0xF3, '', 'iget-wide-quick', KIND_NONE)
Op(0xF4, '', 'iget-object-quick', KIND_NONE)
Op(0xF5, '', 'iput-quick', KIND_NONE)
Op(0xF6, '', 'iput-wide-quick', KIND_NONE)
Op(0xF7, '', 'iput-object-quick', KIND_NONE)
Op(0xF8, '', 'invoke-virtual-quick', KIND_NONE)
Op(0xF9, '', 'invoke-virtual-quick/range', KIND_NONE)
Op(0xFA, '45cc', 'invoke-super-quick', KIND_METHOD)
Op(0xFB, '4rcc', 'invoke-super-quick/range', KIND_METHOD)
Op(0xFC, '35c', 'unused', KIND_NONE)
Op(0xFD, '3rc', 'unused', KIND_NONE)
Op(0xFE, '10x', 'unused', KIND_NONE)
Op(0xFF, '10x', 'unused', KIND_NONE)
