import os
import sys
from sys import prefix
import angr
import re
from angrutils import plot_cfg, hook0, set_plot_style, plot_cdg
import networkx as nx
from networkx.algorithms.centrality import dispersion
from networkx.readwrite.nx_shp import edges_from_line
from utils import x86

import argparse

class ProjAsm:
  def __init__(self, file_prefix) -> None:
    self.cfgs = {}
    # TODO
    pass

class BinAsm:
  def __init__(self, binfile) -> None:
    self.binfile = binfile
    self.p = angr.Project(binfile, load_options={"auto_load_libs": False})
    self.cfg = self.p.analyses.CFGEmulated(keep_state=True, normalize=True)
    self._function_map = self.cfg.kb.functions._function_map
    self.cfgs = {}
    # TODO: build self.cfgs

  def plot(self, address, function):
    """ address, function: _function_map.items() """
    _dir = os.path.dirname(self.binfile)
    plot_cfg(self.cfg, os.path.join(_dir,f"{function.name}_cfg"), format="png", asminst=True, vexinst=False, func_addr={address:True}, debug_info=False, remove_imports=True, remove_path_terminator=True)

class CFGAsm:
  def __init__(self, address, function) -> None:
    self.address = address
    self.function = function
    self._graph, self._useless_nodes = self.normalize_graph()
    # self.start = function.
  

  def to_dec(self):
    hex_ptn = re.compile('0x[0-9a-f]+')
    for node in self._graph.nodes:
        block = self.function._get_block(node.addr, node.size)
        caps = block.capstone
        for ins in caps.insns:
            hexnum = hex_ptn.findall(ins.op_str)
            for _h in hexnum:
                decnum = int(_h, 16)
                ins.op_str = ins.op_str.replace(_h, str(decnum), 1)


  def to_hex(self):
    # warn: take care !
    #   1. 1 and 12 appear at the same
    #   2. hex and decimal appear at the same
    hex_ptn = re.compile('0x[0-9a-f]+')
    for node in self._graph.nodes:
        block = self.function._get_block(node.addr, node.size)
        caps = block.capstone
        for ins in caps.insns:
            print('start --- ' + str(ins))
            op_str = ins.op_str
            # first we extract hex number and replace it with a magic number in case it affects the following dec replace
            hexnum = hex_ptn.findall(op_str)
            magic = ['hpwa', 'hpwb', 'hpwc', 'hpwd']
            hex_dic = dict()
            for _r in range(len(hexnum)):
                _h = hexnum[_r]
                hex_dic[_h] = magic[_r]
                op_str = op_str.replace(_h, hex_dic[_h], 1)
            # now we start decimal replacement
            op_str = re.sub('(\d+)', lambda x : hex(int(x.group(1))), op_str, 0)
            # withdraw former hex number
            for _k in hex_dic.keys():
                op_str = op_str.replace(hex_dic[_k], _k)
            print('after ---- ' + op_str)
            ins.op_str = op_str
    
  
  def rm_nop(self):
    for node in self._graph.nodes:
        block = self.function._get_block(node.addr, node.size)
        caps = block.capstone
        rm = []
        for ins in caps.insns:
            if ins.mnemonic == 'nop':
                rm.append(ins)
        for _r in rm:
            caps.insns.remove(_r)
            #print('rm ' + str(_r))


  def show_ins(self):
    for node in self._graph.nodes:
        block = self.function._get_block(node.addr, node.size)
        caps = block.capstone
        for ins in caps.insns:
            print(ins)


  def expand_addr(self):
    for node in self._graph.nodes:
      block = self.function._get_block(node.addr, node.size)
      caps = block.capstone
      if caps.insns[-1].mnemonic.startswith('j'):
        # expand addr
        for _n in self._graph.neighbors(node):
          block = self.function._get_block(_n.addr, _n.size)
          if len(block.capstone.insns) > 0:
            addr = hex(block.capstone.insns[0].address)
            if not addr in caps.insns[-1].op_str:
              caps.insns[-1].op_str += (', ' + addr)
  

  def normalize_graph(self):
    print(f"Function Name: {self.function.name}")
    graph = self.function.graph_ex(False) # networkx.DiGraph
    useless_nodes = []
    for node in graph.nodes:
      # print('new node')
      block = self.function._get_block(node.addr, node.size)
      caps = block.capstone
      insns = []
      for cap in caps.insns:
        insns.append((cap.mnemonic, cap.op_str))
        # print((cap.mnemonic, cap.op_str, cap.address))
      if len(insns) == 0:
        print("No Function Body.")
        break
      flag = 0
      if insns[-1][0].startswith('jmp') or insns[-1][0].startswith('nop'):
        for insn in insns[:-1]:
          mne = insn[0]
          ops = re.sub('[\s]+', '', insn[1], 10).split(',')
          for op in ops:
            if op not in x86.all_regxs and mne != 'nop':
              flag = 1
              break
          if flag == 1:
            break
        if flag == 0:
          useless_nodes.append(node)
    return graph, useless_nodes
  
  @property
  def dfs(self):
    dfs_list = []
    for node in nx.dfs_postorder_nodes(self._graph):
      if node in self._useless_nodes:
        continue
      block = self.function._get_block(node.addr, node.size)
      dfs_list.append((node, block))
      print(str(block.capstone), '\n')
    return dfs_list
  
  @property
  def scc(self):
    sccs = []
    for cc in nx.strongly_connected_components(self._graph):
      tmp_cc = []
      for node in cc:
        if node in self._useless_nodes:
          continue
        block = self.function._get_block(node.addr, node.size)
        tmp_cc.append((node, block))
        print(str(block.capstone))
        print()
      print(len(tmp_cc))
      print('\n')
      if len(tmp_cc) > 0:
        sccs.append(tmp_cc)
    return sccs

  @property
  def asp(self):
    """ all simple path """

class ProjIr:
  def __init__(self, file_prefix) -> None:
    """
      file_prefix: dir of case, e.g. /home/caoy/proj/case/casexxx/
    """
    self.dir = file_prefix
    self.dots = {}
    for level in range(3):
      d = os.path.join(self.dir, f'o{level}')
      ir = os.path.join(d, f'main_o{level}.ll')
      tmp = []
      for f in os.listdir(d):
        if f.endswith('.dot'):
          tmp.append(f)
      self.dots[level] = tmp
    self.cfgs = {}
    for level, dots in self.dots.items():
      tmp = {}
      for dot in dots:
        function_name = dot.split('.')[1]
        dot_file = os.path.join(self.dir, f'o{level}', dot)
        dot_cfg = CFGIr(dot_file)
        tmp[function_name] = dot_cfg
      self.cfgs[level] = tmp

class CFGIr:
  def __init__(self, dotfile) -> None:
    self.dotfile = dotfile
    import Src
    self._nodes, self._node_info, self._edges = Src.cfg.parse_dot(dotfile)
    self._graph = nx.DiGraph()
    self._graph.add_nodes_from(self._nodes)
    self._graph.add_edges_from(self._edges)

  def _re_rotate_graph(self):

    pass

  @property
  def dfs(self):
    dfs_list = []
    for node in nx.dfs_postorder_nodes(self._graph):
      block = self._node_info[node]
      for ins in block:
        if 'call' in ins:
          print(ins, '\n')
        else:
          print(ins)
      print()
      dfs_list.append((node, block))
    return dfs_list

  @property
  def scc(self):
    sccs = []
    for cc in nx.strongly_connected_components(self._graph):
      tmp_cc = []
      for node in cc:
        block = self._node_info[node]
        tmp_cc.append((node, block))
        for ins in block:
          if 'call' in ins:
            print(ins, '\n')
          else:
            print(ins)
        print()
      print(len(tmp_cc))
      print('\n')
      sccs.append(tmp_cc)
    return sccs
    
class CFG:
  """
  docstring
  """
  def __init__(self, file_prefix) -> None:
    """
      file_prefix: /home/caoy/proj/case/casexxx/
    """
    self.cfgs = {}
    # 
    # TODO: 

def test():
  # ircfg = CFGIr(sys.argv[2])
  # irscc = ircfg.scc
  # print(len(irscc))
  # irdfs = ircfg.dfs
  # print()
  cfg = ProjAsm(sys.argv[1])
  for address, function in cfg._function_map.items():
    if function.name != "main":
      continue
    #cfg.plot(address, function)
    # print(str(address) + "   + " + function.name)
    graph = CFGAsm(address, function)
    graph.to_hex()
    graph.show_ins()
    # print(graph.dfs)
    # dfs = graph.dfs
    # asmscc = graph.scc
    # print(len(asmscc))
  
    # ged = nx.optimize_edit_paths(graph._graph, ircfg._graph)
    # for dis in ged:
    #   print(dispersion)

if __name__ == '__main__':
  test()
