#!/usr/bin/env python
"""Utility to extract .debug_info section and print that in JSON format.
"""

import argparse
from collections import OrderedDict
import ctypes
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


def encode_fixed(num, bytes):
  value = int(num, 16) if '0x' in num else int(num)
  value = hex(ctypes.c_ulong(value).value)[2:-1] # remove 0x and L
  value = value.rjust(bytes * 2, '0')[-bytes * 2:]
  result = ''
  while len(value) > 0:
    result = value[:2] + result
    value = value[2:]
  return result

def encode_leb(num, signed):
  value = int(num, 16) if '0x' in num else int(num)
  value = bin(ctypes.c_ulong(value).value)[2:].rjust(64, '0')[1::] # remove 0b and first digit
  result = ''
  while len(value) > 0:
    part = value[-7:]
    value = value[:-7]
    last = value.replace(part[0], '') == '' if signed else value.replace('0', '') == ''
    if last:
      result = result + hex(int(part, 2))[2:].rjust(2, '0')
      break
    result = result + hex(int('1' + part, 2))[2:]
  return result

def encode_expr(dump):
  # returning expression dump to its binary form
  ops = {
    'DW_OP_addr': ("03", "A"),
    'DW_OP_deref': ("06", ""),
    'DW_OP_const1u': ("08", "1"),
    'DW_OP_const1s': ("09", "1"),
    'DW_OP_const2u': ("0a", "2"),
    'DW_OP_const2s': ("0b", "2"),
    'DW_OP_const4u': ("0c", "4"),
    'DW_OP_const4s': ("0d", "4"),
    'DW_OP_const8u': ("0e", "8"),
    'DW_OP_const8s': ("0f", "8"),
    'DW_OP_constu': ("10", "U"),
    'DW_OP_consts': ("11", "S"),
    'DW_OP_dup': ("12", ""),
    'DW_OP_drop': ("13", ""),
    'DW_OP_over': ("14", ""),
    'DW_OP_pick': ("15", "1"),
    'DW_OP_swap': ("16", ""),
    'DW_OP_rot': ("17", ""),
    'DW_OP_xderef': ("18", ""),
    'DW_OP_abs': ("19", ""),
    'DW_OP_and': ("1a", ""),
    'DW_OP_div': ("1b", ""),
    'DW_OP_minus': ("1c", ""),
    'DW_OP_mod': ("1d", ""),
    'DW_OP_mul': ("1e", ""),
    'DW_OP_neg': ("1f", ""),
    'DW_OP_not': ("20", ""),
    'DW_OP_or': ("21", ""),
    'DW_OP_plus': ("22", ""),
    'DW_OP_plus_uconst': ("23", "U"),
    'DW_OP_shl': ("24", ""),
    'DW_OP_shr': ("25", ""),
    'DW_OP_shra': ("26", ""),
    'DW_OP_xor': ("27", ""),
    'DW_OP_skip': ("2f", "2"),
    'DW_OP_bra': ("28", "2"),
    'DW_OP_eq': ("29", ""),
    'DW_OP_ge': ("2A", ""),
    'DW_OP_gt': ("2B", ""),
    'DW_OP_le': ("2C", ""),
    'DW_OP_lt': ("2D", ""),
    'DW_OP_ne': ("2E", ""),
    'DW_OP_lit0': ("30", ""),
    'DW_OP_lit1': ("31", ""),
    'DW_OP_lit2': ("32", ""),
    'DW_OP_lit3': ("33", ""),
    'DW_OP_lit4': ("34", ""),
    'DW_OP_lit5': ("35", ""),
    'DW_OP_lit6': ("36", ""),
    'DW_OP_lit7': ("37", ""),
    'DW_OP_lit8': ("38", ""),
    'DW_OP_lit9': ("39", ""),
    'DW_OP_lit10': ("3A", ""),
    'DW_OP_lit11': ("3B", ""),
    'DW_OP_lit12': ("3C", ""),
    'DW_OP_lit13': ("3D", ""),
    'DW_OP_lit14': ("3E", ""),
    'DW_OP_lit15': ("3F", ""),
    'DW_OP_lit16': ("40", ""),
    'DW_OP_lit17': ("41", ""),
    'DW_OP_lit18': ("42", ""),
    'DW_OP_lit19': ("43", ""),
    'DW_OP_lit20': ("44", ""),
    'DW_OP_lit21': ("45", ""),
    'DW_OP_lit22': ("46", ""),
    'DW_OP_lit23': ("47", ""),
    'DW_OP_lit24': ("48", ""),
    'DW_OP_lit25': ("49", ""),
    'DW_OP_lit26': ("4A", ""),
    'DW_OP_lit27': ("4B", ""),
    'DW_OP_lit28': ("4C", ""),
    'DW_OP_lit29': ("4D", ""),
    'DW_OP_lit30': ("4E", ""),
    'DW_OP_lit31': ("4F", ""),
    'DW_OP_reg0': ("50", ""),
    'DW_OP_reg1': ("51", ""),
    'DW_OP_reg2': ("52", ""),
    'DW_OP_reg3': ("53", ""),
    'DW_OP_reg4': ("54", ""),
    'DW_OP_reg5': ("55", ""),
    'DW_OP_reg6': ("56", ""),
    'DW_OP_reg7': ("57", ""),
    'DW_OP_reg8': ("58", ""),
    'DW_OP_reg9': ("59", ""),
    'DW_OP_reg10': ("5A", ""),
    'DW_OP_reg11': ("5B", ""),
    'DW_OP_reg12': ("5C", ""),
    'DW_OP_reg13': ("5D", ""),
    'DW_OP_reg14': ("5E", ""),
    'DW_OP_reg15': ("5F", ""),
    'DW_OP_reg16': ("60", ""),
    'DW_OP_reg17': ("61", ""),
    'DW_OP_reg18': ("62", ""),
    'DW_OP_reg19': ("63", ""),
    'DW_OP_reg20': ("64", ""),
    'DW_OP_reg21': ("65", ""),
    'DW_OP_reg22': ("66", ""),
    'DW_OP_reg23': ("67", ""),
    'DW_OP_reg24': ("68", ""),
    'DW_OP_reg25': ("69", ""),
    'DW_OP_reg26': ("6A", ""),
    'DW_OP_reg27': ("6B", ""),
    'DW_OP_reg28': ("6C", ""),
    'DW_OP_reg29': ("6D", ""),
    'DW_OP_reg30': ("6E", ""),
    'DW_OP_reg31': ("6F", ""),
    'DW_OP_breg0': ("70", ""),
    'DW_OP_breg1': ("71", ""),
    'DW_OP_breg2': ("72", ""),
    'DW_OP_breg3': ("73", ""),
    'DW_OP_breg4': ("74", ""),
    'DW_OP_breg5': ("75", ""),
    'DW_OP_breg6': ("76", ""),
    'DW_OP_breg7': ("77", ""),
    'DW_OP_breg8': ("78", ""),
    'DW_OP_breg9': ("79", ""),
    'DW_OP_breg10': ("7A", ""),
    'DW_OP_breg11': ("7B", ""),
    'DW_OP_breg12': ("7C", ""),
    'DW_OP_breg13': ("7D", ""),
    'DW_OP_breg14': ("7E", ""),
    'DW_OP_breg15': ("7F", ""),
    'DW_OP_breg16': ("80", ""),
    'DW_OP_breg17': ("81", ""),
    'DW_OP_breg18': ("82", ""),
    'DW_OP_breg19': ("83", ""),
    'DW_OP_breg20': ("84", ""),
    'DW_OP_breg21': ("85", ""),
    'DW_OP_breg22': ("86", ""),
    'DW_OP_breg23': ("87", ""),
    'DW_OP_breg24': ("88", ""),
    'DW_OP_breg25': ("89", ""),
    'DW_OP_breg26': ("8A", ""),
    'DW_OP_breg27': ("8B", ""),
    'DW_OP_breg28': ("8C", ""),
    'DW_OP_breg29': ("8D", ""),
    'DW_OP_breg30': ("8E", ""),
    'DW_OP_breg31': ("8F", ""),

    'DW_OP_regx': ("90", "U"),
    'DW_OP_fbreg': ("91", "S"),
    'DW_OP_bregx': ("92", "US"),
    'DW_OP_piece': ("93", "U"),
    'DW_OP_deref_size': ("94", "1"),
    'DW_OP_xderef_size': ("95", "1"),
    'DW_OP_nop': ("96", ""),
    'DW_OP_push_object_address': ("97", "0"),
    'DW_OP_call2': ("98", "2"),
    'DW_OP_call4': ("99", "4"),
    'DW_OP_callref': ("9a", "4"),
    'DW_OP_form_tls_address': ("9b", ""),
    'DW_OP_call_frame_cfa': ("9C", ""),
    'DW_OP_bit_piece': ("9D", "UU"),
    'DW_OP_implicit_value': ("9E", "UU"),
    'DW_OP_stack_value': ("9F", ""),
    'DW_OP_WASM_location': ("ED", "US")
  }
  operands = {
    '1': lambda x: encode_fixed(x, 1),
    '2': lambda x: encode_fixed(x, 2),
    '4': lambda x: encode_fixed(x, 4),
    '8': lambda x: encode_fixed(x, 8),
    'A': lambda x: encode_fixed(x, 4),
    'U': lambda x: encode_leb(x, False),
    'S': lambda x: encode_leb(x, True)
  } # assuming address length is 4 and all little-endian
  result = []
  for op in dump.split(', '):
    parts = op.split(' ')
    desc = ops[parts[0]]
    result.append(desc[0])
    if len(desc[1]) + 1 != len(parts):
      raise Exception('Bad amount of expr operands')
    for i in range(0, len(desc[1])):
      result.append(operands[desc[1][i]](parts[i + 1]))
  return ''.join(result).upper() + ' // ' + dump

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
        attr_value = encode_expr(line[line.find('(') + 1 : -1])
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
          attr_value.append(OrderedDict([('range', range), ('expr', encode_expr(expr))]))
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
