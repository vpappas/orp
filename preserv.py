# Copyright (c) 2012, Vasilis Pappas <vpappas@cs.columbia.edu>
# This file is part of Orp http://nsl.cs.columbia.edu/projects/orp

import itertools
import inp

import insn

#should be called after f.analyze_registers() because it needs reg_pairs!
def get_reg_preservations(f):
  """Returns an array containig the preservations and another containing
  the available registers (which can be used for global substitution)."""

  preservs = {} #merge same preserved registers
  remove_ebp = False

  for reg, push, pops in f.reg_pairs:

    if reg == "ebp" and "leave" in (p.mnem for p in pops):
      remove_ebp = True
      continue

    # XXX: relax for now
    #if not f.exported and any([push.spd - 4 != pop.spd for pop in pops]):
      #print push, "does not match", pops
    #  continue

    if reg not in preservs:
      preservs[reg] = (reg, [push], pops)
    else:
      preservs[reg][1].append(push)
      if pops != preservs[reg][2]:
        print "BUG: same push, but different pops", preservs[reg], pops
        
  # we remove the registers in set(preservs) instead of pre_regs as the
  # later set can contain avail_regs due to a calling convention only!
  avail_regs = set(insn.REGS[:8]) - f.touches - set(preservs)
  if remove_ebp and "ebp" in avail_regs:
    avail_regs.remove("ebp")

  # make sure everything is sorted according to the instruction ordering
  pre_array = preservs.values()
  for reg, pushes, pops in pre_array:
    pushes.sort(key=lambda x: x.pos)
    pops.sort(key=lambda x: x.pos)
  pre_array.sort(key=lambda x: x[1][0].pos) # use first push!

  return pre_array, avail_regs


def do_reg_preservs(instrs, blocks, preservs, avail_regs, gen_patched, all_diffs=None):
  """Changes the preserved registers within the given instructions and optionally 
  generates instances of the input file with these permuted register preservations.
  Returns the changed bytes set."""

  changed_bytes = set()

  #f_exit instructions (ret) implicitly use the preserved registers.. exclude them!
  implicit = reduce(lambda x, y: x | y, [i.implicit for i in instrs if not i.f_exit], set())

  regs = [reg for reg, pushes, pops in preservs if reg not in implicit]
  
  if not preservs or (len(regs) == 1 and not avail_regs):
    return changed_bytes

  # preserved registers that are implicitly used should not be touched
  # hmm .. rotation should still happen even when all regs are implicitly used..
  #if not regs:
  #  return changed_bytes
  if len(regs) == 1: #we know we have available
    regs.append(avail_regs.pop())

  if len(regs) >= 2:
    # we do need the combinations here, because we want to change as much
    # as possible in case a register cannot be swapped (e.g. weird modrm/sib)
    for r1, r2 in itertools.combinations(regs, 2):
      for ins in instrs:
        if not ins.swap_registers(r1, r2):
          #print "MAYBEBUG: broke for", ins.disas, "in register preservations!", r1, r2, ins.regs
          break
      else: #no break!
        diff = inp.get_diff(instrs)
        if gen_patched:
          inp.patch(diff, "preserv-%s-%s"%(r1, r2))
        if all_diffs != None:
          all_diffs.append(diff)
        changed_bytes.update((ea for ea, orig, curr in diff))
      for ins in instrs:
        ins.reset_changed()

  # the second part bellow can be useful in cases where global swap
  # cannot  be applied due to implicit uses

  # group preservs in the same block and reorder them
  # augment each ins in the preservs with blocks
  for reg, pushes, pops in preservs:
    for ins in itertools.chain(pushes, pops):
      ins.block = next((b for b in blocks if ins in b.instrs), None)

  preservs_groups = []

  for reg, pushes, pops in preservs:
    if len(preservs_groups) == 0:
      preservs_groups.append([[reg, pushes, pops]])
      continue
    for group in preservs_groups:
      if (all(p1.block == p2.block for p1, p2 in zip(group[0][1], pushes)) and
          all(p1.block == p2.block for p1, p2 in zip(group[0][2], pops))):
        group.append([reg, pushes, pops])
        break
      else:
        preservs_groups.append([[reg, pushes, pops]])
  #print "grouping!:", '\n'.join((str(g) for g in preservs_groups))

  # reorder (rotate) the pushes/pops by placing the last one in the
  # first's position and shifting all the other instrs down
  # TODO: breaks if esp is used within the reordered block! (BIB @ 070012F1)
  for group in (g for g in preservs_groups if len(g) > 1):
    # group them by block
    #pushes_by_block = {}
    ins_by_block = {}
    for reg, pushes, pops in group:
      for ins in itertools.chain(pushes, pops):
        if (ins.block, ins.mnem) not in ins_by_block:
          ins_by_block[(ins.block, ins.mnem)] = []
        ins_by_block[(ins.block, ins.mnem)].append(ins)
    # in each block, move the latest ins to the ealiest's position
    for (block, mnem), instrs in ins_by_block.iteritems():
      instrs.sort(key=lambda x: x.addr)
      first = block.instrs.index(instrs[0])
      last = block.instrs.index(instrs[-1])
      block.rinstrs = block.instrs[:first]
      block.rinstrs.append(block.instrs[last])
      block.rinstrs.extend(block.instrs[first:last])
      block.rinstrs.extend(block.instrs[last+1:])
      diff = inp.get_block_diff(block)
      changed_bytes.update((ea for ea, orig, curr in diff))
      #XXX should also generate patched files ...

  return changed_bytes


# executes as an IDA python script
if __name__ == "__main__":
  import inp_ida
  import func

  # Find preserved registers in the function under the cursor
  ida_func = idaapi.get_func(ScreenEA())
  if not ida_func:
    print "error: cursor is not under a function.."
  else:
    func_ea = ida_func.startEA
    print "\nAnalyzing function starting at %X" % func_ea
    code, blocks = inp_ida.get_code_and_blocks(func_ea)
    f = func.Function(func_ea, code, blocks, set(), set())
    # fill in the pre_regs
    f.analyze_registers({})
    print f,

    preservs, avail_regs = get_reg_preservations(f)
    print "\nAvailable registers (for global substitution):"
    print ', '.join(avail_regs)
    print "\nRegister preservation code:"

    for reg, pushes, pops in preservs:
      print reg, "saved at:"
      print "\n".join(str(push) for push in pushes)
      print reg, "restored at:"
      print "\n".join(str(pop) for pop in pops)
      print 
