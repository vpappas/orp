#!/usr/bin/env python

# Copyright (c) 2012, Vasilis Pappas <vpappas@cs.columbia.edu>
# This file is part of Orp http://nsl.cs.columbia.edu/projects/orp

import optparse
import itertools
import random
import subprocess
import os
import sys

import func
import eval
import inp

import swap
import reorder
import equiv
import preserv

VER="0.3"

# check for the prerequisites
try:
  import pydasm
except ImportError, e:
  print "pydasm is not installed"
  sys.exit(1)

#TODO: check that pydasm is patched!

#TODO: warn if IDA is not installed

try:
  import pygraph
except ImportError, e:
  print "pygraph is not installed"
  sys.exit(1)


def randomize(input_file):

  # get the changed byte sets
  functions = inp.get_functions(input_file)
  levels = func.classify_functions(functions)
  func.analyze_functions(functions, levels)

  global_diffs = []
  changeable = 0

  for f in filter(lambda x: x.level != -1, functions.itervalues()):

    # skip the SEH prolog and epilog functions .. they cause trouble
    if "_SEH_" in f.name:  
      continue

    diffs = []

    # swap
    swap.liveness_analysis(f.code)
    live_regs = swap.get_reg_live_subsets(f.instrs, f.code, f.igraph)
    #swap.split_reg_live_subsets(live_regs, f.code)
    swaps = swap.get_reg_swaps(live_regs)
    swap.do_single_swaps(swaps, False, diffs)

    # preserv
    preservs, avail_regs = preserv.get_reg_preservations(f)
    preserv.do_reg_preservs(f.instrs, f.blocks, preservs,
                            avail_regs, False, diffs)

    # equiv
    equiv.do_equiv_instrs(f.instrs, False, diffs)

    # reorder
    reorder.do_reordering(f.blocks, False, diffs)

    if diffs:
      changeable += len(list(itertools.chain(*diffs)))
      global_diffs.extend(random.choice(diffs))

    
  inp.patch(global_diffs, "rand", True)

  print "changed %d bytes of at least %d changeable" % (len(global_diffs), changeable)
  print "(not counting all possible reorderings and preservations)"


def call_ida(input_file):
  script = os.path.join(os.path.dirname(os.path.abspath(__file__)), "inp_ida.py")
  if not os.path.exists(script):
    print "error: could not find inp_ida.py (%s)" % script
    sys.exit(1)
  command = 'idaq -A -S"\\"' + script + '\\"" ' + input_file
  print "executing:", command
  exit_code = subprocess.call(command)
  print "exit code:", exit_code


if __name__=="__main__":

  parser = optparse.OptionParser("usage: %prog [options] input_file")

  parser.add_option("-p", "--profile", dest="profile",
                    action="store_true", default=False,
                    help="profile the execution")

  parser.add_option("-c", "--eval-coverage", dest="coverage",
                    action="store_true", default=False,
                    help="evaluate the randomization coverage")

  parser.add_option("-e", "--eval-payload", dest="payload",
                    action="store_true", default=False,
                    help="check if the payload of the exploit can be broken")

  parser.add_option("-d", "--dump-cfg", dest="dump_cfg",
                    action="store_true", default=False,
                    help="dump the CFG of the input file (using IDA)")

  parser.add_option("-r", "--randomize", dest="randomize",
                    action="store_true", default=True,
                    help="produce a randomized instance of input (default)")

  (options, args) = parser.parse_args()

  print "Orp v%s" % VER

  # check if an input file is given
  if len(args) == 0:
    parser.error("no input file")
  elif len(args) > 1:
    parser.error("more than one input files")

  # check if the input file exists
  if not os.path.exists(args[0]):
    parser.error("cannot access input file '%s'" % args[0])

  # check for incompatible options
  if options.profile and options.dump_cfg:
    parser.error("cannot profile the CFG extraction from IDA")

  # check if we're asked to profile execution
  if options.profile:
    import cProfile
    _run = cProfile.run
  else:
    _run = __builtins__.eval

  if options.coverage:
    _run('eval.eval_coverage(args[0])')
  elif options.payload:
    _run('eval.eval_exploit(args[0])')
  elif options.dump_cfg:
    call_ida(args[0])
  elif options.randomize:
    _run('randomize(args[0])')
  else:
    parser.error("how did you do that?")
