# Copyright (c) 2012, Vasilis Pappas <vpappas@cs.columbia.edu>
# This file is part of Orp http://nsl.cs.columbia.edu/projects/orp

import struct
import insn
import inp

# equivalent instructions stuff.. ugly (check x86.py)
both_regs = (0x00, 0x01, 0x08, 0x09, 0x10, 0x11, 0x18, 0x19, 0x20,
             0x21, 0x28, 0x29, 0x30, 0x31, 0x38, 0x39, 0x88, 0x89)
same_regs = {0x84: (0x08, 0x0A, 0x20, 0x22),
             0x08: (0x84, 0x0A, 0x20, 0x22),
             0x0A: (0x84, 0x08, 0x20, 0x22),
             0x20: (0x84, 0x08, 0x0A, 0x22),
             0x22: (0x84, 0x08, 0x0A, 0x20),
             0x85: (0x09, 0x0B, 0x21, 0x23),
             0x09: (0x85, 0x0B, 0x21, 0x23),
             0x0B: (0x85, 0x09, 0x21, 0x23),
             0x21: (0x85, 0x09, 0x0B, 0x23),
             0x23: (0x85, 0x09, 0x0B, 0x21)}
same_reg_modrms = (0xC0, 0xC9, 0xD2, 0xDB, 0xE4, 0xED, 0xF6, 0xFF)
equiv_addsub8 = {0x04: 0x2C, 0x2C: 0x04}
equiv_addsub32 = {0x05: 0x2D, 0x2D: 0x05}
equiv_xorsub = {0x30: 0x28, 0x31: 0x29, 0x32: 0x2A, 0x33: 0x2B}
equiv_xchg = (0x86, 0x87)

def check_equiv(ins):
    """Checks whether this instruction can be changed with an equivalent one.
    'cbytes' is changed if an equivalent instrucion does exist."""

    opcode = ord(ins.bytes[ins.opc_off])
    modrm = ord(ins.bytes[ins.modrm_off])

    # check for equivalent instructions when both operands are registers
    if ins.op1.type == ins.op2.type == insn.Operand.REGISTER:
      dir_bit = 0b00000010
      # check if there is an equivalent when both regs are the same
      if opcode in same_regs and modrm in same_reg_modrms:
        ins.cbytes[ins.opc_off] = same_regs[opcode][0]
        modrm_offset = ins.modrm_mod << 6 | ins.modrm_rm << 3 | ins.modrm_reg
        ins.cbytes[ins.modrm_off] = modrm_offset
      # turn off the dir bit and check again
      elif opcode ^ (opcode & dir_bit) in both_regs:
        ins.cbytes[ins.opc_off] ^= dir_bit
        modrm_offset = ins.modrm_mod << 6 | ins.modrm_rm << 3 | ins.modrm_reg
        ins.cbytes[ins.modrm_off] = modrm_offset
      elif opcode in equiv_xchg and ins.modrm_off > 0:
        modrm_offset = ins.modrm_mod << 6 | ins.modrm_rm << 3 | ins.modrm_reg
        ins.cbytes[ins.modrm_off] = modrm_offset
      #XXX shadowed by first case!
      elif opcode in equiv_xorsub and modrm in same_reg_modrms:
        ins.cbytes[ins.opc_off] = equiv_xorsub[opcode]
    # check for equiv when second openrand is imm (eg, add -> sub)
    elif ins.op2.type == insn.Operand.IMMEDIATE:
      ext_mask = 0b00101000  # modrm = mod 2b | reg 3b | rm 3b
      # 8 bit immediates, extended opcodes
      if opcode in (0x80, 0x83) and ins.modrm_reg in (0b000, 0b101):
        ins.cbytes[ins.modrm_off] ^= ext_mask
        tmp = struct.unpack('b',  chr(ins.cbytes[-1]))[0]
        if tmp != -0x80:  # -128
          ins.cbytes[-1] = struct.pack('b', -tmp)
      # 32 bit immediate, extended opcode
      elif opcode == 0x81 and ins.modrm_reg in (0b000, 0b101):
        ins.cbytes[ins.modrm_off] ^= ext_mask
        tmp = struct.unpack('i',  str(ins.cbytes[-4:]))[0]
        if tmp != -0x80000000:
          ins.cbytes[-4:] = struct.pack('i', -tmp)
      # 8 bit immediate, simple case
      elif opcode in equiv_addsub8:
        ins.cbytes[ins.opc_off] = equiv_addsub8[opcode]
        tmp = struct.unpack('b',  chr(ins.cbytes[-1]))[0]
        if tmp != -0x80:  # -128
          ins.cbytes[-1] = struct.pack('b', -tmp)
      # 32 bit immediate, simple case
      elif opcode in equiv_addsub32:
        ins.cbytes[ins.opc_off] = equiv_addsub32[opcode]
        tmp = struct.unpack('i',  str(ins.cbytes[-4:]))[0]
        if tmp != -0x80000000:
          ins.cbytes[-4:] = struct.pack('i', -tmp)
    return ins.bytes != ins.cbytes  # bytearray with str comparison is ok here


def do_equiv_instrs(instrs, gen_patched, all_diffs=None):
  """Check each instruction if it has an equivalent one and computes the
  changed bytes set. Optionally, it can generate a changed file with the
  equivalent instructions. Returns the list of changed bytes."""

  changed_bytes = set()
  changed = []

  for ins in instrs: 
    if check_equiv(ins):
      changed.append(ins)

  diff = inp.get_diff(changed)

  if gen_patched:
    inp.patch(diff, "equiv")

  changed_bytes.update((ea for ea, orig, new in diff))

  for ins in changed:
    if all_diffs != None:
      all_diffs.append(inp.get_diff([ins]))
    ins.reset_changed()

  return changed_bytes


# executes as an IDA python script
if __name__ == "__main__":
  # Find equivalent instructions between cursor position and end of function
  import idautils
  start_ea = ScreenEA()
  end_ea = idc.FindFuncEnd(start_ea)
  print "\nSearching for equiv instrs in %.8X:%.8X" % (start_ea, end_ea)
  for head in idautils.Heads(start_ea, end_ea):
    ibytes = idc.GetManyBytes(head, idc.ItemEnd(head) - head)
    ins = insn.Instruction(head, ibytes, 0)
    if check_equiv(ins):
      eq_ins = insn.Instruction(head, str(ins.cbytes), 0)
      print ins.disas, "(%s) ->" % ins.bytes.encode("hex"),
      print eq_ins.disas, "(%s)" %eq_ins.bytes.encode("hex")
