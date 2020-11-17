import os
import sys
import re

import networkx as nx


path = ''
node_lst = []
node_info = dict()
edges = []

# there are two types of line: new node introduction, edge relationship
def parse_dot():
    with open(path, 'r') as r:
        for _line in r.readlines():
            if _line.strip().startswith('Node'):
                if 'shape' in _line and 'label' in _line:
                    # new node
                    start_index = _line.index('Node')
                    end_index = _line.index('[') - 2
                    node = _line[start_index:end_index+1]
                    node_lst.append(node)
                    ir = _line[_line.index('[')+1:_line.rindex(']')]
                    ir = re.match( r'shape=.*?,label="\{(.*?)\}"', ir, re.M|re.I).group(1)
                    ir = [_i.strip() for _i in ir.split('\l')]
                    ir = [_i for _i in ir if _i != '' ]
                    # print(ir)
                    node_info[node] = ir
                    
                elif '->' in _line and _line.index('Node') != _line.rindex('Node'):
                    # edge relationship
                    s_index_left = _line.index('Node')
                    e_index_left = _line.index('->') - 2
                    s_index_right = _line.rindex('Node')
                    e_index_right = _line.rindex(';') - 1
                    left_node = _line[s_index_left:e_index_left + 1].split(':')[0]
                    right_node = _line[s_index_right:e_index_right + 1].split(':')[0]
                    edges.append((left_node, right_node))

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print('usage: python[3] parse_dot.py /path/to/dot/file')
        sys.exit(-1)
    
    path = sys.argv[1]
    if not os.path.exists(path):
        print('file does not exist...')
        sys.exit(-1)
    
    parse_dot()
    # print(node_lst)
    # print(edges)
    # print(node_info)
    G = nx.DiGraph()
    G.add_nodes_from(node_lst)
    G.add_edges_from(edges)
    start = node_lst[0]
    print(start)
    end = node_lst[-1]
    print(end)
    for path in nx.all_simple_paths(G, start, end):
      print(path)
      print(len(path))
    
