#!/usr/bin/env python
"""Utility to extract .debug_info section and print that in JSON format.
"""

import argparse
from collections import OrderedDict
import json
import logging
from math import floor, log
import os
import re
from subprocess import Popen, PIPE
import sys

def parse_args():
  parser = argparse.ArgumentParser(prog='get_dwarf_info.py')
  parser.add_argument('wasm', help='wasm file')
  parser.add_argument('-o', '--output', required=True, help='output debug info JSON')
  parser.add_argument('-d', '--remove-dead-functions', action='store_true', help='remove dead functions data')
  parser.add_argument('--dwarfdump', nargs='?', help=argparse.SUPPRESS)
  return parser.parse_args()

def extract_debug_info(content):
  logging.debug('Translate the .debug_info section dump')

  lines = content.splitlines()

  # Skip header: format and content marker.
  if "file format WASM" not in lines[0]:
    raise Exception('Bad dwarfdump output')
  if ".debug_info contents" not in lines[2]:
    raise Exception('.debug_info was not found')

  root = OrderedDict()
  stack = [root]
  cur = 3
  while cur < len(lines):
    line = lines[cur]
    cur += 1
    if line == "": continue
    if line.startswith('.debug_line contents'): break

    # Removing address or initial indent.
    if re.search(r'^(\s{11}|0x[0-9a-f]{8}:)\s', line) is None:
      raise Exception("Invalid input line %d: %s" % (cur, line))
    line = line[12:]
    # Calculate indent level and match stack depth to current indent level.
    line_spaces = re.search(r'\S', line).start()
    indent_level = 1 + (line_spaces >> 1)
    while indent_level < len(stack):
      stack.pop()
    if indent_level != len(stack):
      raise Exception("Misaligned data at line %d" % cur)
    line = line[line_spaces:]

    top_obj = stack[-1]

    if 'DW_TAG_' in line:
      # Create new object and that to the stack and parents children.
      obj_tag = line
      new_obj = OrderedDict([('tag', line[len('DW_TAG_'):])])
      if 'children' not in stack[-1]:
        top_obj['children'] = []
      top_obj['children'].append(new_obj)
      stack.append(new_obj)
      continue

    if 'DW_AT_' in line:
      # Parse attribute name and value.
      attr_name = re.search(r'DW_AT_(\S+)', line).group(1)
      attr_value = None
      if line[-2:] == '")': # string
        attr_value = line[line.find('"') + 1 : -2]
      elif re.search(r'\((0x[0-9a-f]+|[\-+]?\d+)\)$', line) is not None: # number
        attr_value = int(re.search(r'\((0x[0-9a-f]+|[\-+]?\d+)\)$', line).group(1), 0)
      elif '(<0x' in line: # binary
        arr_match = re.search(r'\(\<(0x[0-9a-f]+)\> ([^)]*)\)', line)
        items = arr_match.group(2).strip().split(' ')
        attr_value = []
        for i in items:
          attr_value.append(int(i, 16))
        if int(arr_match.group(1), 0) != len(attr_value):
          raise Exception("Invalid binary attribute at line %d: %s" % (cur, line))
      elif '(DW_' in line and 'DW_OP_' not in line: # enumeration
        attr_value = re.search(r'\(DW_[^_]+_([^)]+)\)', line).group(1)
      elif attr_name == "location" and '(DW_OP_' in line:
        attr_value = line[line.find('(') + 1 : -1]
      elif attr_name == "ranges":
        # Parse ranges values.
        last_range = False
        attr_value = []
        while not last_range:
          range_match = re.search(r'\[(0x[0-9a-f]+), (0x[0-9a-f]+)\)', lines[cur])
          attr_value.append([int(range_match.group(1), 0), int(range_match.group(2), 0)])
          last_range = lines[cur][-2:] == '))'
          cur += 1
      elif attr_name == "location":
        # Parse locations.
        last_loc = False
        attr_value = []
        while not last_loc:
          range_match = re.search(r'\[(0x[0-9a-f]+),\s+(0x[0-9a-f]+)\): ', lines[cur])
          range = [int(range_match.group(1), 0), int(range_match.group(2), 0)]
          expr = lines[cur][range_match.end():]
          if expr[-1] == ')':
            expr = expr[:-1]
            last_loc = True
          attr_value.append(OrderedDict([('range', range), ('expr', expr)]))
          cur += 1
      elif '(true)' in line: # boolean: true
        attr_value = True
      elif '(false)' in line: # boolean: false
        attr_value = False
      elif 'error extracting location list' in line: # errors
        attr_value = None
      else:
        raise Exception("Unrecognized attribute format at line %d: %s" % (cur, line))
      top_obj[attr_name] = attr_value
      continue

    if 'Compile Unit:' in line: continue

    if 'NULL' in line:
      stack.pop()
      continue

    raise Exception("Unrecognized construct at line %d: %s" % (cur, line))

  return root['children']

def check_range(low_pc, high_pc):
  min_acceptable_pc = 1 + floor(log(high_pc - low_pc, 128)) + 1
  return low_pc >= min_acceptable_pc

def remove_dead_subprograms(items):
  assert isinstance(items, list)

  dead = []
  for x in items:
    assert isinstance(x, OrderedDict)
    if x['tag'] == 'subprogram' and 'low_pc' in x:
      if not check_range(x['low_pc'], x['high_pc']):
        if 'inline' in x and x['inline'].endswith('_inlined'):
          del x['low_pc']
          del x['high_pc']
        else:
          dead.append(x)
        continue

    if 'ranges' in x:
      x['ranges'] = list(filter(lambda x: check_range(x[0], x[1]), x['ranges']))
      if x['tag'] == 'subprogram' and len(x['ranges']) == 0:
        if 'inline' in x and x['inline'].endswith('_inlined'):
          del x['ranges']
        else:
          dead.append(x)
        continue

    if 'children' in x:
      remove_dead_subprograms(x['children'])

  for x in dead:
    items.remove(x)

def read_dwarfdump(wasm, dwarfdump):
  if dwarfdump:
    output = open(dwarfdump, 'r').read()
  else:
    logging.debug('Reading DWARF information from %s' % wasm)
    process = Popen(['llvm-dwarfdump', '-debug-info', wasm], stdout=PIPE)
    (output, err) = process.communicate()
    exit_code = process.wait()
    if exit_code != 0:
      logging.info('Error during llvm-dwarfdump execution (%s)' % exit_code)
      exit(1)
  return output

def main():
  args = parse_args()

  dwarfdump_content = read_dwarfdump(args.wasm, args.dwarfdump)

  debug_info = extract_debug_info(dwarfdump_content)

  if args.remove_dead_functions:
    logging.debug('Remove dead functions')
    remove_dead_subprograms(debug_info)

  logging.debug('Write JSON')
  with open(args.output, 'w') as outfile:
    json.dump(debug_info, outfile, indent=2, separators=(',', ':'))

if __name__ == '__main__':
  logging.basicConfig(level=logging.DEBUG)
  sys.exit(main())
