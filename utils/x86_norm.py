import re
from x86 import *
def Regx_label(insn: str) -> dict:
  """
  insn: string <mov eax, ebx>
  return: dict
  """
  dic = {}
  if re.match(mov2, insn):
    mat = re.match(mov2, insn)
    dic['Mnemonic'] = mat[1]
    dic['dst'] = [mat[2]]
    dic['src'] = [mat[3]]
    dic['Condition'] = []
    dic['src_cflags'] = []
    dic['dst_cflags'] = []
  elif re.match(cmov2, insn):
    mat = re.match(cmov2, insn)
    dic['Mnemonic'] = mat[1]
    dic['dst'] = [mat[2]]
    dic['src'] = [mat[3]]
    dic['Condition'] = []
    dic['src_cflags'] = []
    dic['dst_cflags'] = []
  elif re.match(exchange2, insn):
    mat = re.match(exchange2, insn)
    dic['Mnemonic'] = mat[1]
    dic['dst'] = [mat[2], mat[3]]
    dic['src'] = [mat[2], mat[3]]
    dic['Condition'] = []
    dic['src_cflags'] = []
    dic['dst_cflags'] = []
  elif re.match(cexchange2, insn):
    mat = re.match(cexchange2, insn)
    dic['Mnemonic'] = mat[1]
    dic['dst'] = [mat[2], 'rax']
    dic['src'] = [mat[2], mat[3]]
    dic['Condition'] = []
    # dic['Condition'] = [('rax', mat[2], '==')]
    dic['src_cflags'] = []
    dic['dst_cflags'] = []
  elif re.match(bytechg1, insn):
    mat = re.match(bytechg1, insn)
    dic['Mnemonic'] = mat[1]
    dic['dst'] = [mat[2]]
    dic['src'] = [mat[2]]
    dic['Condition'] = []
    dic['src_cflags'] = []
    dic['dst_cflags'] = []
  elif re.match(cbytechg1, insn):
    mat = re.match(cbytechg1, insn)
    dic['Mnemonic'] = mat[1]
    dic['dst'] = [mat[2], 'rdx:rax']
    dic['src'] = [mat[2], 'rcx:rbx']
    dic['Condition'] = []
    dic['src_cflags'] = []
    dic['dst_cflags'] = []
  elif re.match(stack1push, insn):
    mat = re.match(stack1push, insn)
    dic['Mnemonic'] = mat[1]
    dic['dst'] = ['stack', 'rsp']
    dic['src'] = [mat[2]]
    dic['Condition'] = []
    dic['src_cflags'] = []
    dic['dst_cflags'] = []
  elif re.match(stack1pop, insn):
    mat = re.match(stack1pop, insn)
    dic['Mnemonic'] = mat[1]
    dic['dst'] = [mat[2], 'rsp']
    dic['src'] = ['stack', 'rsp']
    dic['Condition'] = []
    dic['src_cflags'] = []
    dic['dst_cflags'] = []
  elif re.match(stack0push, insn):
    mat = re.match(stack0push, insn)
    dic['Mnemonic'] = mat[1]
    dic['dst'] = ['stack', 'rsp']
    dic['src'] = ['rax', 'rcx', 'rdx', 'rbx', 'rsp', 'rbp', 'rsi', 'rdi']
    dic['Condition'] = []
    dic['src_cflags'] = []
    dic['dst_cflags'] = []
  elif re.match(stack0pop, insn):
    mat = re.match(stack0pop, insn)
    dic['Mnemonic'] = mat[1]
    dic['dst'] = ['rax', 'rcx', 'rdx', 'rbx', 'rsp', 'rbp', 'rsi', 'rdi']
    dic['src'] = ['stack', 'rsp']
    dic['Condition'] = []
    dic['src_cflags'] = []
    dic['dst_cflags'] = []
  elif re.match(cwd0, insn):
    mat = re.match(cwd0, insn)
    dic['Mnemonic'] = mat[1]
    dic['dst'] = ['rdx:rax']
    dic['src'] = ['rax']
    dic['Condition'] = []
    dic['src_cflags'] = []
    dic['dst_cflags'] = []
  elif re.match(move2, insn):
    mat = re.match(move2, insn)
    dic['Mnemonic'] = mat[1]
    dic['dst'] = [mat[2]]
    dic['src'] = [mat[3]]
    dic['Condition'] = []
    dic['src_cflags'] = []
    dic['dst_cflags'] = []
  elif re.match(addsub2, insn):
    mat = re.match(addsub2, insn)
    dic['Mnemonic'] = mat[1]
    dic['dst'] = [mat[2]]
    dic['src'] = [mat[3]]
    dic['Condition'] = []
    dic['src_cflags'] = []
    dic['dst_cflags'] = []
  elif re.match(mul1, insn):
    mat = re.match(mul1, insn)
    dic['Mnemonic'] = mat[1]
    dic['dst'] = ['rdx:rax']
    dic['src'] = ['rax', mat[2]]
    dic['Condition'] = []
    dic['src_cflags'] = []
    dic['dst_cflags'] = []
  elif re.match(mul2, insn):
    mat = re.match(mul2, insn)
    dic['Mnemonic'] = mat[1]
    dic['dst'] = [mat[2]]
    dic['src'] = [mat[2], mat[3]]
    dic['Condition'] = []
    dic['src_cflags'] = []
    dic['dst_cflags'] = []
  elif re.match(mul3, insn):
    mat = re.match(mul3, insn)
    dic['Mnemonic'] = mat[1]
    dic['dst'] = [mat[2]]
    dic['src'] = [mat[3], mat[4]]
    dic['Condition'] = []
    dic['src_cflags'] = []
    dic['dst_cflags'] = []
  elif re.match(div1, insn):
    mat = re.match(div1, insn)
    dic['Mnemonic'] = mat[1]
    dic['dst'] = ['rdx', 'rax']
    dic['src'] = ['rdx:rax', mat[2]]
    dic['Condition'] = []
    dic['src_cflags'] = []
    dic['dst_cflags'] = []
  elif re.match(incdecneg1, insn):
    mat = re.match(incdecneg1, insn)
    dic['Mnemonic'] = mat[1]
    dic['dst'] = [mat[2]]
    dic['src'] = ['0x1', mat[2]]
    dic['Condition'] = []
    dic['src_cflags'] = []
    dic['dst_cflags'] = []
  elif re.match(incdecneg1, insn):
    mat = re.match(incdecneg1, insn)
    dic['Mnemonic'] = mat[1]
    dic['dst'] = [mat[2]]
    dic['src'] = [mat[2]]
    dic['Condition'] = []
    dic['src_cflags'] = []
    dic['dst_cflags'] = []
  elif re.match(cmp2, insn):
    mat = re.match(cmp2, insn)
    dic['Mnemonic'] = mat[1]
    dic['dst'] = []
    dic['src'] = [mat[2], mat[3]]
    dic['Condition'] = []
    dic['src_cflags'] = []
    dic['dst_cflags'] = []
  elif re.match(dai0, insn):
    mat = re.match(dai0, insn)
    dic['Mnemonic'] = mat[1]
    dic['dst'] = ['rax']
    dic['src'] = []
    dic['Condition'] = []
    dic['src_cflags'] = []
    dic['dst_cflags'] = []
  elif re.match(dai0, insn):
    mat = re.match(dai0, insn)
    dic['Mnemonic'] = mat[1]
    dic['dst'] = ['rax']
    dic['src'] = []
    dic['Condition'] = []
    dic['src_cflags'] = []
    dic['dst_cflags'] = []
  elif re.match(log2, insn):
    mat = re.match(log2, insn)
    dic['Mnemonic'] = mat[1]
    dic['dst'] = [mat[2]]
    dic['src'] = [mat[2], mat[3]]
    dic['Condition'] = []
    dic['src_cflags'] = []
    dic['dst_cflags'] = []
  elif re.match(log1, insn):
    mat = re.match(log1, insn)
    dic['Mnemonic'] = mat[1]
    dic['dst'] = [mat[2]]
    dic['src'] = [mat[2]]
    dic['Condition'] = []
    dic['src_cflags'] = []
    dic['dst_cflags'] = []
  elif re.match(shift1, insn):
    mat = re.match(shift1, insn)
    dic['Mnemonic'] = mat[1]
    dic['dst'] = [mat[2]]
    dic['src'] = [mat[2]]
    dic['Condition'] = []
    dic['src_cflags'] = []
    dic['dst_cflags'] = []
  elif re.match(shift2, insn):
    mat = re.match(shift2, insn)
    dic['Mnemonic'] = mat[1]
    dic['dst'] = [mat[2]]
    dic['src'] = [mat[2], mat[3]]
    dic['Condition'] = []
    dic['src_cflags'] = []
    dic['dst_cflags'] = []
  elif re.match(shift3, insn):
    mat = re.match(shift3, insn)
    dic['Mnemonic'] = mat[1]
    dic['dst'] = [mat[2]]
    dic['src'] = [mat[2], mat[3], mat[4]]
    dic['Condition'] = []
    dic['src_cflags'] = []
    dic['dst_cflags'] = []
  elif re.match(rotate2, insn):
    mat = re.match(rotate2, insn)
    dic['Mnemonic'] = mat[1]
    dic['dst'] = [mat[2]]
    dic['src'] = [mat[2], mat[3]]
    dic['Condition'] = []
    dic['src_cflags'] = []
    dic['dst_cflags'] = []
  elif re.match(bt2, insn):
    mat = re.match(bt2, insn)
    dic['Mnemonic'] = mat[1]
    dic['dst'] = []
    dic['src'] = [mat[2], mat[3]]
    dic['Condition'] = []
    dic['src_cflags'] = []
    dic['dst_cflags'] = []
  elif re.match(set1, insn):
    mat = re.match(set1, insn)
    dic['Mnemonic'] = mat[1]
    dic['dst'] = [mat[2]]
    dic['src'] = []
    dic['Condition'] = []
    dic['src_cflags'] = []
    dic['dst_cflags'] = []
  elif re.match(test2, insn):
    mat = re.match(test2, insn)
    dic['Mnemonic'] = mat[1]
    dic['dst'] = []
    dic['src'] = [mat[2], mat[3]]
    dic['Condition'] = []
    dic['src_cflags'] = []
    dic['dst_cflags'] = []
  elif re.match(jmp1, insn):
    mat = re.match(jmp1, insn)
    dic['Mnemonic'] = mat[1]
    dic['dst'] = ['rip']
    dic['src'] = [mat[2]]
    dic['Condition'] = []
    dic['src_cflags'] = []
    dic['dst_cflags'] = []
  elif re.match(loop1, insn):
    mat = re.match(loop1, insn)
    dic['Mnemonic'] = mat[1]
    dic['dst'] = ['rcx']
    dic['src'] = [mat[2]]
    dic['Condition'] = []
    dic['src_cflags'] = []
    dic['dst_cflags'] = []
  elif re.match(call1, insn):
    mat = re.match(call1, insn)
    dic['Mnemonic'] = mat[1]
    dic['dst'] = ['rip']
    dic['src'] = [mat[2]]
    dic['Condition'] = []
    dic['src_cflags'] = []
    dic['dst_cflags'] = []
  elif re.match(ret1, insn):
    mat = re.match(ret1, insn)
    dic['Mnemonic'] = mat[1]
    dic['dst'] = ['rip', 'stack']
    dic['src'] = [mat[2]]
    dic['Condition'] = []
    dic['src_cflags'] = []
    dic['dst_cflags'] = []
  elif re.match(ret0, insn):
    mat = re.match(ret0, insn)
    dic['Mnemonic'] = mat[1]
    dic['dst'] = ['rip']
    dic['src'] = [mat[2]]
    dic['Condition'] = []
    dic['src_cflags'] = []
    dic['dst_cflags'] = []
  elif re.match(int1, insn):
    mat = re.match(int1, insn)
    dic['Mnemonic'] = mat[1]
    dic['dst'] = []
    dic['src'] = [mat[2]]
    dic['Condition'] = []
    dic['src_cflags'] = []
    dic['dst_cflags'] = []
  elif re.match(int0, insn):
    mat = re.match(int0, insn)
    dic['Mnemonic'] = mat[1]
    dic['dst'] = []
    dic['src'] = ['4']
    dic['Condition'] = []
    dic['src_cflags'] = []
    dic['dst_cflags'] = []
  elif re.match(bound2, insn):
    mat = re.match(bound2, insn)
    dic['Mnemonic'] = mat[1]
    dic['dst'] = []
    dic['src'] = [mat[2], mat[3]]
    dic['Condition'] = []
    dic['src_cflags'] = []
    dic['dst_cflags'] = []
  elif re.match(enter2, insn):
    mat = re.match(enter2, insn)
    dic['Mnemonic'] = mat[1]
    dic['dst'] = ['stack']
    dic['src'] = [mat[2], mat[3]]
    dic['Condition'] = []
    dic['src_cflags'] = []
    dic['dst_cflags'] = []
  elif re.match(leave, insn):
    mat = re.match(leave, insn)
    dic['Mnemonic'] = mat[1]
    dic['dst'] = ['rsp', 'stack']
    dic['src'] = ['rbp']
    dic['Condition'] = []
    dic['src_cflags'] = []
    dic['dst_cflags'] = []
  