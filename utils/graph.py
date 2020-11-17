from logging import info
import angr

class Stack:
  def __init__(self) -> None:
    self.s = []
    
  def push(self, node):
    self.s.append(node)
  
  def pop(self):
    item = None
    if len(self.s) > 0:
      item = self.s.pop()
    return item
  
  def isEmpty(self):
    if len(self.s) > 0:
      return False
    else:
      return True

class Node:
  def __init__(self, vertex, firstIn, firstOut) -> None:
    self.vertex = vertex
    self.firstIn = firstIn
    self.firstOut = firstOut

class Edge:
  def __init__(self, tailvex, headvex, info, hlink, tlink) -> None:
    self.tailvex = tailvex
    self.headvex = headvex
    self.info = info
    self.hlink = hlink
    self.tlink = tlink

class Graph:
  def __init__(self, nodes, edges, exit_addr) -> None:
    """
      nodes: a list of node. Entry node is in nodes[0], sorted by address
      edges: a list of edge < start, end , info>

    """
    self.entry = 0
    self.exit = -1
    self.node_list = []
    self.edge_list = []
    self.node_dict = []
    self._init_nodes(self, nodes, exit_addr)
    self._create_dg(self, edges)

  def dfs(self):
    S, Q = set(), []
    Q.append(self.entry)
    while Q:
      u = Q.pop()
      if u in S: continue
      S.add(u)
      while True:
        Q.append()
    

  def _init_nodes(self, nodes, exit_addr):
    for index, node in enumerate(nodes):
      N = Node(node, None, None)
      self.node_list.append(N)
      self.node_dict[node] = index
      if node.addr == exit_addr:
        self.exit = index

  def _create_dg(self, edges):
    #横向
    for index, node in enumerate(self.node_list):
      ptail = -1
      for idx, edge in enumerate(edges):
        E = Edge(edge[0], edge[1], edge[2], None, None)
        self.edge_list.append(E)
        if node.firstOut == None:
          node.firstOut = len(self.edge_list)
          ptail = node.firstOut
        else:
          self.edge_list[ptail].tlink = len(self.edge_list)
          ptail = self.edge_list[ptail].tlink

    # 纵向
    for index, node in enumerate(self.node_list):
      phead = -1
      for idx, edge in enumerate(self.edge_list):
        if node.firstIn == None:
          node.firstIn = idx
          phead = node.firstIn
        else:
          edge.hlink = idx
          phead = edge.hlink
