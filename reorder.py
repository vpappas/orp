#!/usr/bin/env python

# Copyright (c) 2012, Vasilis Pappas <vpappas@cs.columbia.edu>
# This file is part of Orp http://nsl.cs.columbia.edu/projects/orp

import itertools
import pydasm
import insn
import inp

from pygraph.classes.digraph import digraph


def BuildBBDependenceDAG(bb):
  """Computes the dependence graph of a basic block."""

  # See Section 9.2 (algorithm in Figure 9.6) of Muchnick's
  # Advanced Compiler Design and Implementation

  dependence_graph = digraph()

  # Maintain reachability information to avoid costly graph traversals
  reachable_fwd = {}
  reachable_bkwd = {}

  for j in bb.instrs:
    #print "\n",j, j.op2.type
    dependence_graph.add_node(j)
    conflict = set()

    # Find which of the instructions already in the DAG conflict with j.
    # Check instructions in reverse order to eliminate redundand dependencies
    for k in reversed(bb.instrs[:bb.instrs.index(j)]):
      dependency = Conflict(k, j)
      #print "dependency", k, '->', j, ':', dependency
      if not dependency:
        continue
      # If there is a path from k to one of the instructions already in
      # dependence with j in the current DAG, then k -> j is redundant
      if reachable_fwd.get(k, set()).intersection(conflict):
        continue
      conflict.add(k)

      dependence_graph.add_edge((k, j))   # Add an edge for this conflict

      # Update reachability information
      reachable_fwd.setdefault(k, set()).add(j)
      reachable_bkwd.setdefault(j, set()).add(k)
      # j is also reachable from all the ancestors of k
      for v in reachable_bkwd.get(k, []):
        reachable_fwd[v].add(j)
      # j can also reach backwards all the ancestors of k
      reachable_bkwd.setdefault(j, set()).update(reachable_bkwd.get(k, []))

  return dependence_graph


UNMOVABLE = [
  # branches
  pydasm.INSTRUCTION_TYPE_JMPC,
  pydasm.INSTRUCTION_TYPE_JECXZ,
  pydasm.INSTRUCTION_TYPE_JMP,
  pydasm.INSTRUCTION_TYPE_LOOP,
  pydasm.INSTRUCTION_TYPE_CALL,
  pydasm.INSTRUCTION_TYPE_RET,
  # other
  pydasm.INSTRUCTION_TYPE_OTHER, # TODO overly restrictive, could relax it
  # TODO think about what else should go in here
]

def Conflict(i1, i2):
  """Returns True if i1 must precede i2 for correct execution."""

  # If we cannot figure out any dependency, assume that there is a conflict
  res = 'DEFAULT_CONFLICT'
  found_RAW = True
  found_WAR = True
  found_WAW = True

  if i1.type in UNMOVABLE or i2.type in UNMOVABLE:
    return res

  # We assume all memory operands reference unique addresses
  # (be very conservative for now - TODO: could relax this)

  # RAW: i1 writes a register/address/flag used by i2
  if not i1.DEF.isdisjoint(i2.USE):
    # i1 writes a register read by i2
    return ('RAW', i1.DEF.intersection(i2.USE).pop()) # TODO assert only one reg
  if ((i1.op1.type == insn.Operand.MEMORY or
       i1.type == pydasm.INSTRUCTION_TYPE_PUSH) and
      (i2.op2.type == insn.Operand.MEMORY or
       i2.type == pydasm.INSTRUCTION_TYPE_POP) and
      i2.type != pydasm.INSTRUCTION_TYPE_LEA): # not an actual memory access
    # i1 writes an address read by i2
    return ('RAW', 'MEM')
  if i1.eflags_w & i2.eflags_r:
    # i1 writes at least one flag read by i2
    return ('RAW', 'EFLAGS')
  found_RAW = False

  # WAR: i1 reads a register/address/flag overwritten by i2
  if not i1.USE.isdisjoint(i2.DEF):
    # i1 reads a register written by i2
    return ('WAR', i1.USE.intersection(i2.DEF).pop())
  if ((i1.op2.type == insn.Operand.MEMORY or
       i2.type == pydasm.INSTRUCTION_TYPE_POP) and
      i1.type != pydasm.INSTRUCTION_TYPE_LEA and # not an actual memory access
      (i2.op1.type == insn.Operand.MEMORY or
       i1.type == pydasm.INSTRUCTION_TYPE_PUSH)):
    # i1 reads an address written by i2
    return ('WAR', 'MEM')
  if i1.eflags_r & i2.eflags_w:
    # i1 reads at least one flag written by i2
    return ('WAR', 'EFLAGS')
  found_WAR = False

  # WAW: i1 and i2 both write the same register/address/flag
  if not i1.DEF.isdisjoint(i2.DEF):
    # i1 and i2 both write the same register
    return ('WAW', i1.DEF.intersection(i2.DEF).pop())
  if ((i1.op1.type == insn.Operand.MEMORY or
       i1.type == pydasm.INSTRUCTION_TYPE_PUSH) and
      (i2.op1.type == insn.Operand.MEMORY or
       i2.type == pydasm.INSTRUCTION_TYPE_PUSH)):
    # i1 and i2 both write the same address
    return ('WAW', 'MEM')
  if i1.eflags_w & i2.eflags_w:
    # i1 and i2 both write the same flag(s)
    return ('WAW', 'EFLAGS')
  found_WAW = False

  if not found_RAW and not found_WAR and not found_WAW:
    return None   # No dependency found

  return res


def ReorderGraph(dag):
  """Computes a topological sorting of the input graph. The resulting ordering
  has the highest hamming distance possible copmared to the original ordering.
  CAUTION: destroys the input DAG."""
  # based on http://en.wikipedia.org/wiki/Topological_ordering#Algorithms

  if not dag.edges():
    return []

  ordering = []
  edge_srcs, edge_dsts = zip(*dag.edges())    # unzip list of edge tuples
  roots = set(edge_srcs) - set(edge_dsts)
  # Include any unconnected vertices
  roots.update(set(dag.nodes()) - set(itertools.chain(*dag.edges())))

  while roots:
    # If possible, pick an instruction that will increase the hamming distance
    # of the resulting ordering compared to the original instruction sequence
    n = max(roots, key=lambda i: i.pos) # the farthest instr - greedy choice
    roots.remove(n)
    ordering.append(n)
    for m in dag.node_neighbors[n][:]:  # copy list (modified in the loop)
      dag.del_edge((n, m))
      if not dag.node_incidence[m]:
        roots.add(m)

  assert dag.edges() == []
  return ordering


def do_reordering(blocks, gen_patched, all_diffs=None):
  """Reorders the instructions within the given blocks and optionally generates
  instances of the input file with these instructions reordered. Returns the
  changed bytes set (coverage evaluation)."""

  reordered = []
  changed_bytes = set()
  diff = []
  
  for block in blocks:

    dag = BuildBBDependenceDAG(block)
    block.rinstrs = ReorderGraph(dag)

    # update the address of reordered instrs
    for i, rins in enumerate(block.rinstrs):

      if i == 0:
        rins.raddr = block.begin
      else:
        rins.raddr = block.rinstrs[i-1].raddr + len(block.rinstrs[i-1].bytes)

      if rins.raddr != rins.addr and rins.inst_len > 4:
        reordered.append(rins)

    diff.extend(inp.get_block_diff(block))
  
  reloc_diff = inp.get_reloc_diff(reordered)
  
  if gen_patched:
    inp.patch(diff+reloc_diff, "reorder")

  if all_diffs != None and len(reloc_diff) == 0:
    all_diffs.append(diff+reloc_diff)

  changed_bytes.update((ea for ea, orig, curr in diff))

  return changed_bytes


def gen_topological_sortings(block):
  """Tries to generate all the possible reorderings. Kills the loop after it
  reaches a threshold.. (entropy evaluation)."""

  # Varol and Rotem's algorithm from '79 
  # http://comjnl.oxfordjournals.org/content/24/1/83.full.pdf+html

  dag = BuildBBDependenceDAG(block)

  #util.draw_graph(dag, "reorder-dag.eps")

  R = set(dag.edges())
  P = ReorderGraph(dag)
  N = len(P)
  LOC = range(N)

  yield P
  i = 0

  # huge or infinite loop detection
  loop_cnt = topsort_cnt = 0

  while i < N:

    K = LOC[i]

    if K+1 < N and (P[K], P[K+1]) not in R:
      P[K], P[K+1] = P[K+1], P[K]
      LOC[i] = LOC[i] + 1
      i = 0
      yield P[:]
      topsort_cnt += 1
    else:
      P.insert(i, P.pop(LOC[i]))
      LOC[i] = i
      i = i + 1

    loop_cnt += 1

    if loop_cnt > 1000:
      print "killing topol. sort after 1000 loops (%d topsorts)" % topsort_cnt
      break


# executes as an IDA python script
if __name__ == "__main__":
  import inp_ida
  import func
  import util 

  # Reorder the instructions in the basic block under the cursor
  ida_func = idaapi.get_func(ScreenEA())
  if not ida_func:
    print "error: cursor is not under a function.."
  else:
    func_ea = ida_func.startEA
    code, blocks = inp_ida.get_code_and_blocks(func_ea)
    f = func.Function(func_ea, code, blocks, set(), set())
    for bb in f.blocks:
      if bb.begin <= ScreenEA() < bb.end:
        print "\nBuilding the DAG for the basic block %X:%X"%(bb.begin, bb.end)
        dag = BuildBBDependenceDAG(bb)
        # uncomment to draw the DAG (needs dot from graphviz)
        #util.draw_graph(dag, "dag.eps")
        for ins in ReorderGraph(dag):
          print ins
        break
    else:
      print "could not find the basic block .."
