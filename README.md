# ProgramAnalyses

### Print CFG to PNG
- **asm**: python Asm/cfg.py dot-cfg -i <binary>
- **ir**: ./Src/llvm-ir.sh <dir> <prefix> <opt-level>

### Tool
- llc -print-after-all a.ll > a.log 2>&1
- clang -mllvm -print-after-all bar.c -S -emit-llvm > log.txt 2 > &1

### 需要增加的部分
- SCC子图导出
- 汇编和IR的SCC排序，保持一致的顺序，拓扑排序
- IR中对于icmp语句顺序的调整，检查所有的基本块中的icmp语句，如果存在icmp和对应的br不在同一个基本块中的情况，那么将icmp移动到br所在的基本块中，位置在它支配的所有语句之前
- 根据汇编的跳转指令和IR的br指令对分量进行分割，然后形成翻译的基本单元。
- 汇编和IR的基本块支配树
- 汇编和IR的数据流分析，主要是针对变量、寄存器和内存

### 存储结构
- cfg.py
  - self.function type: angr.Function
  - self._graph networkx.DiGraph
  - self._graph.nodes type: \<BlockNode\>
  - self._graph.edges type: (\<BlockNode\>, \<BlockNode\>)
  - self._useless_nodes：无意义的基本块
  - 获取Block：self.function._get_block(node.addr, node.size)
  - Block类型：block.capstone > angr.CapstoneBlock
  - capstone.insns > list(angr.CapstoneInsn) 获取这个基本块中的每一条指令。
  - insns.address 这条指令的地址 insns.mnemonic 这条指令的操作码 insns.op_str 这条指令的操作数
  - 上述类型都是angr中定义的，可以参考angr源码来获取相应的API信息，地址：https://github.com/angr/angr/blob/master/angr/knowledge_plugins/functions/function.py
