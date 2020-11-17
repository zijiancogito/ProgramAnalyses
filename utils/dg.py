from networkx import DiGraph as DG
import networkx as nx
import sys

from networkx.algorithms.isomorphism.isomorph import fast_could_be_isomorphic

def read_graph(edgeList, nodetype, weighted=False, directed=True):
  if weighted:
    G = nx.read_edgelist(edgeList, nodetype=nodetype, data=(('type', int), ('weight', float), ('id', int)), create_using=DG)
  else:
    G = nx.read_edgelist(edgeList, nodetype=nodetype, data=(('type', int), ('id', int)), create_using=DG)
    for edge in G.edges():
      G[edge[0]][edge[1]]['weight'] = 1.0
  if not directed:
    G = G.to_undirected()

  return G

if __name__ == '__main__':
  el = [(0x400640, 0x400671), (0x400671, 0x400696), (0x400671, 0x400676), (0x40068d, 0x400696), (0x40068d, 0x400680), (0x400680, 0x40068d), (0x400676, 0x400680)]
  nl = set()
  for i in el:
    nl.add(i[0])
    nl.add(i[1])
  G = nx.DiGraph()
  G.add_nodes_from(list(nl))
  G.add_edges_from(el)
  for node in nx.dfs_postorder_nodes(G, 0x400640):
    print(node)