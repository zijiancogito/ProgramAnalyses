from sys import path, setdlopenflags
import angr
import sys

from angrutils import plot_cfg, hook0, set_plot_style
import bingraphvis
import networkx as nx

import argparse

class Proj:
  def __init__(self, binfile) -> None:
    self.p = angr.Project(binfile, load_options={"auto_load_libs": False})
    self.cfg = self.p.analyses.CFGFast(keep_state=True, normalize=True)
    self._function_map = self.cfg.kb.functions._function_map

  def plot(self, address, funcname):
    plot_cfg(self.cfg, f"{funcname}_cfg", format="png", asminst=True, vexinst=False, func_addr={address:True}, debug_info=False, remove_imports=True, remove_path_terminator=True, color_depth=True)

def get_func_addrs(binfile):
  p = angr.Project(binfile, load_options={'auto_load_libs': False})
  cfg = p.analyses.CFGEmulated(keep_state=True, normalize=True)
  ddg = p.analyses.DDG(cfg)
  import os
  dg_view = ddg.view
  # print(ddg._data_graph.nodes)
  d = os.path.dirname(binfile) 
  # print(cfg.kb.functions.block_map)
  for address, function in cfg.kb.functions._function_map.items():
    # print(function._addr_to_block_node)
    if function.name != "main":
      continue
    graph = function.graph_ex(True)
    print(function.operations)
    print(function.code_constants)
    print(function.local_runtime_values)
    print(function.startpoint)
    print(list(function._endpoints["return"])[0])
    for path in nx.all_simple_paths(graph, function.startpoint, list(function._endpoints["return"])[0]):
      print(path)
      print(len(path))
    # graph.render(filename='MyPicture', directory="./",view=False, format="png")
    plot_cfg(cfg, os.path.join(d,f"{function.name}_cfg"), format="png", asminst=True, vexinst=False, func_addr={address:True}, debug_info=False, remove_imports=True, remove_path_terminator=True)

    regx = ['rax', 'rbx', 'rax', 'rdx', 'rsi', 'rdi', 'rip', 'rbp', 'rsp', 'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15', 'eax', 'ebx', 'ecx', 'edx', 'esi', 'edi', 'eip', 'ebp', 'esp']
    # for blk in function.blocks:
    #   caps = blk.capstone
    #   print(caps)
    #   print()
      # insns = caps.insns
      # for ins in insns:
      #   addr = ins.address
      #   view = dg_view[addr]
      #   for key in regx:
      #     try:
      #       print(view[key]._variable)
      #     except:
      #       pass
        # print(ins.address)
      #   print(ins.mnemonic)
      #   print(ins.op_str)
      #   print(blk.addr)
      # print(type(caps))

def main():
  parser = argparse.ArgumentParser(description='Extract ASM CFG from Projects.')
  subparsers = parser.add_subparsers(help='sub-command help')

  parser_1 = subparsers.add_parser('dot-cfg', help="Only build cfg.")
  parser_1.add_argument('-i', '--bin')

  parser_2 = subparsers.add_parser('analyses-cfg', help="Analyses entrie CFG.")
  parser_2.add_argument('-i', '--bin')

  args = parser.parse_args()

  subp = sys.argv[1]
  if subp == "dot-cfg":
    get_func_addrs(args.bin)

if __name__ == "__main__":
  main()
