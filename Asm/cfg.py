from sys import setdlopenflags
import angr
import sys

from angrutils import plot_cfg, hook0, set_plot_style
import bingraphvis

import argparse

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

class Proj:
  def __init__(self, binfile) -> None:
    self.p = angr.Project(binfile, load_options={"auto_load_libs": False})
    self.cfg = self.p.analyses.CFGFast(keep_state=True, normalize=True)
    self._function_map = self.cfg.kb.functions._function_map
    self.cfgs = {}
    self._cfgs()
    self._addr_to_func , self._func_to_addr = self._addr_vs_func()
    self.ins_map = self._ins_map()
    self.block_map = self._block_map()

  @property
  def function_addrs(self):
    func_addrs = []
    for address, func in self._function_map.items():
      func_addrs.append(address)
    return func_addrs

  def _addr_vs_func(self):
    dic = {}
    dic2 = {}
    for address, func in self._function_map.items():
      dic[address] = func
      dic2[func.name] = address
    return dic, dic2

  def _ins_map(self):
    """
      Return: {addr : ((opc, ops), block_addr)}
    """
    dic = {}
    for address, func in self._function_map.items():
      for blk in func.blocks:
        caps = blk.capstone
        insns = caps.insns
        for ins in insns:
          dic[ins.address] = ((ins.mnemonic, ins.op_str), blk.addr)
        # print(blk.instructions)
    return dic

  def _block_map(self):
    """
      Return: {addr : object<block>}
    """
    dic = {}
    for address, func in self._function_map.items():
      blocks = func.blocks
      for blk in blocks:
        addr = blk.addr
        dic[addr] = blk
    return dic

  def _edges(self):
    edges = self.cfg.graph.edges
    return

  def _cfgs(self):
    for address, func in self._function_map.items():
      self.cfgs[address] = func
  
  def get_address(self, funcname) -> int:
    """
      Return: address of function
    """
    return self._func_to_addr[funcname]

  def get_funcname(self, address):
    return self._addr_to_func[address]
  
  def get_function_graph_ex(self, address):
    return self.cfgs[address].graph_ex(False)

  def get_function_graph(self, address):
    return self.cfgs[address].graph()

  def get_function_blocks(self, address):
    return self.cfgs[address].blocks

  def get_block_capstone(self, block) -> list :
    """
      Return: list of instructions  (addr, opc, ops)
    """
    caps = block.capstone
    insns = caps.insns
    instructions = []
    for ins in insns:
      instructions.append((ins.address, ins.mnemonic, ins.op_str))
    return instructions

  def split_bb(self, blocks):

    return

  def plot(self, address, funcname):
    plot_cfg(self.cfg, f"{funcname}_cfg", format="png", asminst=True, vexinst=False, func_addr={address:True}, debug_info=False, remove_imports=True, remove_path_terminator=True)

def get_func_addrs(binfile):
  p = angr.Project(binfile, load_options={'auto_load_libs': False})
  cfg = p.analyses.CFGEmulated(keep_state=True, normalize=True)
  
  # print(cfg.kb.functions.block_map)
  for address, function in cfg.kb.functions._function_map.items():
    # print(function._addr_to_block_node)
    plot_cfg(cfg, f"{function.name}_cfg", format="png", asminst=True, vexinst=False, func_addr={address:True}, debug_info=False, remove_imports=True, remove_path_terminator=True)
    # print(function.name)
    # graph = function.graph_ex(True)
    # edges = graph.edges
    # nodes = graph.nodes
    # print(edges)
    # print(cfg.indirect_jumps)
    # print(cfg._loop_back_edges)
    # for blk in function.blocks:
    #   caps = blk.capstone
    #   insns = caps.insns
      # for ins in insns:
      #   print(ins.address)
      #   print(ins.mnemonic)
      #   print(ins.op_str)
      #   print(blk.addr)
      # print(type(caps))

# def test_get_func_addrs():
#   import pdb
#   import sys
#   pdb.set_trace()
#   test = sys.argv[1]
#   get_func_addrs(test)
