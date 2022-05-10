from qstruct.base import QType, QStructField
from qstruct.contrib.android_dexfile import QDexStruct
from qstruct.primary import QUInt8, QUInt16, QUInt32, QUInt64


class DexInsnsItem(QDexStruct):
  q_align = 1
  op = QUInt8.extend(fmt=lambda x, v: str(v) + '|' + str(x.get_parent().opcode))
  AB = QUInt8[0] + 1
  AG = QUInt8[0] + 1
  AA = QUInt8[0] + 1
  AAAA = QUInt16[0] + 2
  AAAAAAAA = QUInt32[0] + 2
  BB = QUInt8[0] + 2
  BBBB = QUInt16[0] + 4
  BBBBBBBB = QUInt32[0] + 2
  BBBBBBBBBBBBBBBB = QUInt64[0] + 2
  CC = QUInt8[0] + 3
  CCCC = QUInt16[0] + 2
  CD = QUInt8[0] + 4
  EF = QUInt8[0] + 5
  HHHH = QUInt16[0] + 6
  opcode = 'nop'
  desc: str
  q_objsize_expect: int
  fmt: str
  bbbb: QType
  fmt_op: str
  kind = None
  proto_x: str = None
  kind_x: int = None

  def on_change_op(self, field: QStructField, name, nval, oval):
    from qdexplus.insns import op_map
    op = op_map[nval]
    # print(op)
    self.opcode = op
    self.kind = op.kind
    fmt = op.format
    self.fmt = fmt
    self.fmt_op = op.formatOp()
    getattr(self, 'fmt_' + fmt)()

  def fmt_00x(self):
    self.q_objsize_expect = 1

  fmt_10x = fmt_00x

  def desc_00x(self):
    self.desc = '%s'

  def desc_10x(self):
    self.desc = '%s' % self.fmt_op

  def fmt_11x(self):
    self.q_objsize_expect = 2
    self.AA.set_length(1)

  fmt_10t = fmt_11x

  def fmt_12x(self):
    self.q_objsize_expect = 2
    self.AB.set_length(1)

  fmt_11n = fmt_12x

  def desc_12x(self):
    ab = self.AB[0]
    A = ab & 0xf
    B = (ab >> 4) & 0xf
    if self.fmt == '12x':
      self.desc = '%s v%d, v%d' % (self.fmt_op, A, B)
    else:
      self.desc = '%s v%d, #+%x' % (self.fmt_op, A, B)

  desc_11n = desc_12x

  def fmt_35c(self):
    self.q_objsize_expect = 6
    self.AG.set_length(1)
    self.bbbb = self.AAAA
    self.bbbb.set_length(1)
    self.CD.set_length(1)
    self.EF.set_length(1)

  fmt_35ms = fmt_35c
  fmt_35mi = fmt_35c

  def finish_load(self):
    assert self.objsize() == self.q_objsize_expect
    getattr(self, 'desc_' + self.fmt)()
    print(self.desc)

  def desc_10t(self):
    self.desc = '%s +v%d' % (self.fmt_op, self.AA[0])

  def desc_11x(self):
    self.desc = '%s v%d' % (self.fmt_op, self.AA[0])

  def fmt_20t(self):
    self.q_objsize_expect = 0x4
    self.AAAA.set_length(1)

  def fmt_22t(self):
    self.active_args(4, self.AB, self.CCCC)

  fmt_22s = fmt_22t
  fmt_22c = fmt_22t
  fmt_22cs = fmt_22t

  def fmt_20bc(self):
    self.bbbb = self.AAAA
    self.active_args(4, self.AA, self.bbbb)

  fmt_22x = fmt_20bc
  fmt_21t = fmt_20bc
  fmt_21s = fmt_20bc
  fmt_21h = fmt_20bc
  fmt_21c = fmt_20bc

  def desc_20bc(self):
    self.desc = '%s %.2d, %s' % (self.fmt_op, self.AA[0], '%s')
    self.kind_x = self.bbbb[0]

  def desc_22x(self):
    self.desc = '%s v%d, v%d' % (self.fmt_op, self.AA[0], self.bbbb[0])

  def desc_21t(self):
    self.desc = '%s v%d, +%.4x' % (self.fmt_op, self.AA[0], self.bbbb[0])

  def desc_21s(self):
    self.desc = '%s v%d, #+%.4x' % (self.fmt_op, self.AA[0], self.bbbb[0])

  def desc_21h(self):
    self.desc = '%s v%d, #+%.4x0000' % (self.fmt_op, self.AA[0], self.bbbb[0])

  def desc_21c(self):
    self.desc = '%s v%d, %s' % (self.fmt_op, self.AA[0], '%s')
    self.kind_x = self.bbbb[0]

  def fmt_23x(self):
    self.active_args(4, self.AA, self.BB, self.CC)

  fmt_22b = fmt_23x

  def desc_23x(self):
    self.desc = '%s v%d, v%d, v%x' % (self.fmt_op, self.AA[0], self.BB[0], self.CC[0])

  def desc_22b(self):
    self.desc = '%s v%d, v%d, #+%.2x' % (self.fmt_op, self.AA[0], self.BB[0], self.CC[0])

  def desc_22t(self):
    AB = self.AB[0]
    A = (AB >> 0) & 0x0f
    B = (AB >> 4) & 0x0f
    self.desc = '%s v%d, v%d, +%.4x' % (self.fmt_op, A, B, self.CCCC[0])

    if self.fmt == '22t':
      self.desc = '%s v%d, v%d, +%.4x' % (self.fmt_op, A, B, self.CCCC[0])
    elif self.fmt == '22s':
      self.desc = '%s v%d, v%d, #+%.4x' % (self.fmt_op, A, B, self.CCCC[0])
    elif self.fmt == '22c':
      self.desc = '%s v%d, v%d, %s' % (self.fmt_op, A, B, '%s')
      self.kind_x = self.CCCC[0]
    elif self.fmt == '22cs':
      self.desc = '%s v%d, v%d, %s' % (self.fmt_op, A, B, '%s')
      self.kind_x = self.CCCC[0]

  desc_22s = desc_22t
  desc_22c = desc_22t
  desc_22cs = desc_22t

  def desc_20t(self):
    self.desc = '%s +%.4x' % (self.fmt_op, self.AAAA[0])

  def fmt_30t(self):
    self.q_objsize_expect = 6
    self.AAAAAAAA.set_length(1)

  def desc_30t(self):
    self.desc = '%s +%.8x' % (self.fmt_op, self.AAAAAAAA[0])

  def desc_31c(self):
    self.desc = '%s v%d, %s' % (self.fmt_op, self.AA[0], '%s')
    self.kind_x = self.BBBBBBBB[0]

  def active_args(self, expect_len, *args):
    for arg in args:
      arg.set_length(1)
    self.q_objsize_expect = expect_len

  def fmt_32x(self):
    self.active_args(6, self.AAAA, self.BBBB)

  def desc_32x(self):
    self.desc = '%s v%d, v%d' % (self.fmt_op, self.AAAA[0], self.BBBB[0])

  def fmt_31i(self):
    self.active_args(6, self.AA, self.BBBBBBBB)

  fmt_31t = fmt_31i

  fmt_31c = fmt_31i

  def desc_31i(self):
    self.desc = '%s v%d, #+%.8x' % (self.fmt_op, self.AA[0], self.BBBBBBBB[0])

  def desc_31t(self):
    self.desc = '%s v%d, +%.8x' % (self.fmt_op, self.AA[0], self.BBBBBBBB[0])

  def desc_31c(self):
    self.desc = '%s v%d, %s' % (self.fmt_op, self.AA[0], '%s')
    self.kind_x = self.BBBBBBBB[0]

  def desc_35c(self):
    AG = self.AG[0]
    A = AG >> 4 & 0x0f
    G = AG & 0x0f
    BBBB = self.bbbb[0]
    CD = self.CD[0]
    C = CD & 0xf
    D = (CD >> 4) & 0xf
    EF = self.EF[0]
    E = EF & 0xf
    F = (EF >> 4) & 0xf
    self.kind_x = BBBB
    op = self.fmt_op
    if A == 0:
      self.desc = '%s {}, %s' % (op, '%s')
    elif A == 1:
      self.desc = '%s {v%d}, %s' % (op, C, '%s')
    elif A == 2:
      self.desc = '%s {v%d, v%d}, %s' % (op, C, D, '%s')
    elif A == 3:
      self.desc = '%s {v%d, v%d, v%d}, %s' % (op, C, D, E, '%s')
    elif A == 4:
      self.desc = '%s {v%d, v%d, v%d, v%d}, %s' % (op, C, D, E, F, '%s')
    elif A == 5:
      self.desc = '%s {v%d, v%d, v%d, v%d, v%d}, %s' % (op, C, D, E, F, G, '%s')

  desc_35ms = desc_35c
  desc_35mi = desc_35c

  def fmt_3rc(self):
    self.active_args(6, self.AA, self.BBBB, self.CCCC)

  def desc_3rc(self):
    NNNN = self.CCCC[0] + self.AA[0] - 1
    self.desc = '%s {v%d ... v%d} %s' % (self.fmt_op, self.CCCC[0], NNNN, '%s')
    self.kind_x = self.BBBB[0]

  fmt_3rms = fmt_3rc
  fmt_3rmi = fmt_3rc

  desc_3rms = desc_3rc
  desc_3rmi = desc_3rc

  def fmt_45cc(self):
    self.active_args(8, self.AG, self.BBBB, self.CD, self.EF, self.HHHH)

  def desc_45cc(self):
    A = (self.AG[0] >> 4) & 0xf
    G = (self.AG[0] >> 0) & 0xf
    BBBB = self.BBBB[0]
    C = (self.CD[0] >> 0) & 0x0f
    D = (self.CD[0] >> 4) & 0x0f
    E = (self.EF[0] >> 0) & 0x0f
    F = (self.EF[0] >> 4) & 0x0f
    HHHH = self.HHHH[0]
    if A == 1:
      self.desc = '%s {v%d}, %s, %s' % (self.fmt_op, C, '%s', '%s')
      self.kind_x = BBBB
      self.proto_x = HHHH
    elif A == 2:
      self.desc = '%s {v%d, v%d}, %s, %s' % (self.fmt_op, C, D, '%s', '%s')
      self.kind_x = BBBB
      self.proto_x = HHHH
    elif A == 3:
      self.desc = '%s {v%d, v%d, v%d}, %s, %s' % (self.fmt_op, C, D, E, '%s', '%s')
      self.kind_x = BBBB
      self.proto_x = HHHH
    elif A == 4:
      self.desc = '%s {v%d, v%d, v%d, v%d}, %s, %s' % (self.fmt_op, C, D, E, F, '%s', '%s')
      self.kind_x = BBBB
      self.proto_x = HHHH
    elif A == 5:
      self.desc = '%s {v%d, v%d, v%d, v%d, v%d}, %s, %s' % (self.fmt_op, C, D, E, F, G, '%s', '%s')
      self.kind_x = BBBB
      self.proto_x = HHHH

  def fmt_4rcc(self):
    self.active_args(8, self.AA, self.BBBB, self.CCCC, self.HHHH)

  def desc_4rcc(self):
    NNNN = self.CCCC[0] + self.AA[0] - 1
    self.desc = '%s> {v%d ... v%d}, %s, %s' % (self.fmt_op, self.CCCC[0], NNNN, '%s', '%s')
    self.kind_x = self.BBBB[0]
    self.proto_x = self.HHHH[0]

  def fmt_51l(self):
    self.active_args(0xa, self.AA, self.BBBBBBBBBBBBBBBB)

  def desc_51l(self):
    self.desc = '%s v%d, #+%.16x' % (self.fmt_op, self.AA[0], self.BBBBBBBBBBBBBBBB[0])

  def format(self, kind_desc=None, proto_desc=None):
    if self.desc is not None:
      if kind_desc is not None and proto_desc is not None:
        return self.desc % (kind_desc, proto_desc)
      elif kind_desc is not None:
        return self.desc % kind_desc
      else:
        return self.desc
    return None
