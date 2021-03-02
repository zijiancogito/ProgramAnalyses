
# general purpose registers
regx_gpr_64 = ['rax', 'rbx', 'rax', 'rdx', 'rsi', 'rdi', 'rbp', 'rsp', 'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15']
regx_gpr_32 = ['eax', 'ebx', 'ecx', 'edx', 'esi', 'edi', 'ebp', 'esp', 'r8d', 'r9d', 'r10d', 'r11d', 'r12d', 'r13d', 'r14d', 'r15d']
regx_gpr_16 = ['ax', 'bx', 'cx', 'dx', 'si', 'di', 'bp', 'sp', 'r8w', 'r9w', 'r10w', 'r11w', 'r12w', 'r13w', 'r14w', 'r15w' ]
regx_gpr_8 = ['al', 'bl', 'cl', 'dl', 'ah', 'bh', 'ch', 'dh', 'sil', 'dil', 'bpl', 'spl', 'r8l', 'r9l', 'r10l', 'r11l', 'r12l', 'r13l', 'r14l', 'r15l' ]

regx_64 = ['edx:eax']
regx_128 = ['rdx:rax']
seg_addr_regx_32 = ['ds:esi', 'es:edi']
seg_addr_regx_16 = ['ds:si', 'es:di']

# segment registers
regx_segr = ['es', 'cs', 'ss', 'ds', 'fs', 'gs']

# Flag registers
regx_flag = ['rflags', 'eflags']

regx_x87_fpu = ['st0', 'st1', 'st2', 'st3', 'st4', 'st5', 'st6', 'st7']

regx_mmx = ['mm0', 'mm1', 'mm2', 'mm3', 'mm4', 'mm5', 'mm6', 'mm7']

regx_xmm = ['xmm0', 'xmm1', 'xmm2', 'xmm3', 'xmm4', 'xmm5', 'xmm6', 'xmm7']

regx_ctrl = ['cr0', 'cr1', 'cr2', 'cr3', 'cr4', 'cr5', 'cr6', 'cr7']

regx_sys_tab = ['gdtr', 'ldtr', 'idtr']

regx_dbg = ['dr0', 'dr1', 'dr2', 'dr3', 'dr4', 'dr5', 'dr6', 'dr7']

regx_msr = ['msr']

all_regxs = regx_128 + regx_ctrl + regx_dbg + regx_flag + regx_gpr_16 + regx_gpr_32 + regx_gpr_64 + regx_gpr_8 + regx_mmx + regx_msr + regx_segr + regx_sys_tab + regx_x87_fpu + regx_xmm

# address = base + (index * scale) + displacement

displacement = r'[0-9]'
base = r'[e|r][ax|bx|cx|dx|si|di|sp|bp]'
index = r'[e|r][ax|bx|cx|dx|si|di|bp]'
scale = r'[1248]'

addr32_disp = r'(^\[[0-9]+\])'
addr32_base = r'(^\[e(ax|bx|cx|dx|si|di|sp|bp)\])'
addr32_base_disp = r'(^\[e(ax|bx|cx|dx|si|di|sp|bp) [\+\-] [0-9]+\])'
addr32_index_scale_disp = r'(^\[e(ax|bx|cx|dx|si|di|bp)\*[1248] [\+\-] [0-9]+\])'
addr32_base_index_scale_disp = r'(^\[e(ax|bx|cx|dx|si|di|sp|bp) [\+\-] e(ax|bx|cx|dx|si|di|bp)\*[1248] [\+\-] [0-9]+\])'

addr64_base = r'(^\[(rax|rbx|rcx|rdx|rsi|rdi|rsp|rbp|r[0-9^6]{1,2}[d]*)\])'
addr64_base_disp = r'(^\[(rax|rbx|rcx|rdx|rsi|rdi|rsp|rbp|r[0-9^6]{1,2}[d]*) [\+\-] [0-9]+\])'
addr64_index_scale_disp = r'(^\[(rax|rbx|rcx|rdx|rsi|rdi|rbp|r[0-9^6]{1,2}[d]*)\*[1248] [\+\-] [0-9]+\])'
addr64_base_index_scale_disp = r'(^\[(rax|rbx|rcx|rdx|rsi|rdi|rsp|rbp|r[0-9^6]{1,2}[d]*) [\+\-] (rax|rbx|rcx|rdx|rsi|rdi|rbp|r[0-9^6]{1,2}[d]*)\*[1248] [\+\-] [0-9]+\])'

regx_dict = {'eax': 'rax_32', 'ax': 'rax_16', 
             'ah': 'rax_8h', 'al': 'rax_8l', 
             'ebx': 'rbx_32', 'bx': 'rbx_16',
             'bh': 'rbx_8h', 'bl': 'rbx_8l', 
             'ecx': 'rcx_32', 'cx': 'rcx_16',
             'ch': 'rcx_8h', 'cl': 'rcx_8l', 
             'edx': 'rdx_32', 'dx': 'rdx_16',
             'dh': 'rdx_8h', 'dl': 'rdx_8l', 
             'esi': 'rsi_32', 'si': 'rsi_16',
             'sih': 'rsi_8h', 'sil': 'rsi_8l',
             'edi': 'rdi_32', 'di': 'rdi_16',
             'dih': 'rdi_8h', 'dil': 'rdi_8l',
             'ebp': 'rbp_32', 'bp': 'rbp_16',
             'bph': 'rbp_8h', 'bpl': 'rbp_8l',
             'esp': 'rsp_32', 'sp': 'rsp_16',
             'sph': 'rsp_8h', 'spl': 'rsp_8l',
             'r8d': 'r8_32', 'r8w': 'r8_16',
             'r8h': 'r8_8h', 'r8l': 'r8_8l',
             'r9d': 'r9_32', 'r9w': 'r9_16',
             'r9h': 'r9_8h', 'r9l': 'r9_8l',
             'r10d': 'r10_32', 'r10w': 'r10_16',
             'r10h': 'r10_8h', 'r10l': 'r10_8l',
             'r11d': 'r11_32', 'r11w': 'r11_16',
             'r11h': 'r11_8h', 'r11l': 'r11_8l',
             'r12d': 'r12_32', 'r12w': 'r12_16',
             'r12h': 'r12_8h', 'r12l': 'r12_8l',
             'r13d': 'r13_32', 'r13w': 'r13_16',
             'r13h': 'r13_8h', 'r13l': 'r13_8l',
             'r14d': 'r14_32', 'r14w': 'r14_16',
             'r14h': 'r14_8h', 'r14l': 'r14_8l',
             'r15d': 'r15_32', 'r15w': 'r15_16',
             'r15h': 'r15_8h', 'r15l': 'r15_8l',
             }

# op
# mem = ""

# insn set
# general data movement
mov2 = r'(mov) ([^,]+), ([^,]+)'
cmov2 = r'(cmov(e|z|ne|nz|a|nbe|ae|nb|b|nae|be|na|g|nle|ge|nl|l|nge|le|ng|c|nc|o|no|s|ns|p|pe|np|po)) ([^,]+), ([^,]+)'
exchange2 = r'(xchg|xadd) ([^,]+), ([^,]+)'
cexchange2 = r'(cmpxchg) ([^,]+), ([^,]+)'
bytechg1 = r'(bswap) ([^,]+)'
cbytechg1 = r'(cmpxchg8b) ([^,]+)'
stack1push = r'(push) ([^,]+)'
stack1pop = r'(pop) ([^,]+)'
stack0push = r'(pusha|pushad)'
stack0pop = r'(popa|popad)'
cwd0 = r'(cwd|cdq|cbw|cwde)'
move2 = r'(movsx|movzx|movsxd|movzxd) ([^,]+), ([^,]+)'

# Binary Arithmetic Instruction
addsub2 = r'(adcx|addx|add|adc|sub|sbb) ([^,]+), ([^,]+)'
mul1 = r'(imul|mul) ([^,]+)'
mul2 = r'(imul) ([^,]+), ([^,]+)'
mul3 = r'(imul) ([^,]+), ([^,]+), ([^,]+)'
div1 = r'(div|idiv) ([^,]+)'
incdecneg1 = r'(inc|dec|neg) ([^,]+)'
cmp2 = r'(cmp) ([^,]+), ([^,]+)'

# Decimal Arithmetic Instruction
dai0 = r'(daa|das|aaa|aas|aam|aad)'

# Logical Instruction
log2 = r'(and|or|xor) ([^,]+), ([^,]+)'
log1 = r'(not) ([^,]+)'

# Shift and Rotate Instructions
shift1 = r'(sar|shr|sal|shrd) ([^,]+)'
shift2 = r'(sar|shr|sal|shrd) ([^,]+), ([^,]+)'
shift3 = r'(shrd|shld) ([^,]+), ([^,]+), ([^,]+)'
rotate2 = r'(ror|rol|rcr|rcl) ([^,]+), ([^,]+)'

# Bit and Byte Instructions
bt2 = r'(bt|btc|btr|bts|bsf|bsr) ([^,]+), ([^,]+)'
set1 = r'(set(e|z|ne|nz|a|nbe|ae|nb|nc|b|nae|c|be|na|g|nle|ge|nl|l|nge|le|ng|s|ns|o|no|pe|p|po|np)) ([^,]+), ([^,]+)'
test2 = r'(test) ([^,]+), ([^,]+)'

# Control Transfer Instructions
jmp1 = r'(j(mp|e|z|ne|nz|a|nbe|ae|nb|b|nae|be|na|g|nle|ge|nl|l|nge|le|ng|c|nc|o|no|s|ns|po|np|pe|cxz|cexz|)) ([^,]+)'
loop1 = r'(loop|loopz|loope|loopne|loopnz) ([^,]+)'
call1 = r'(call) ([^,]+)'
ret1 = r'(ret) ([^,]+)'
ret0 = r'(ret|iret|iretd)'
int1 = r'(int) ([^,]+)'
int0 = r'(into)'
bound2 = r'(bound) ([^,]+), ([^,]+)'
enter2 = r'(enter) ([^,]+), ([^,]+)'
leave = r'(leave)'

# String Operations
str2 = r'(movs|cmps|scas|lods|stos) ([^,]+), ([^,]+)'
str0 = r'(movsb|movsw|movsd|cmpsb|cmpsw|cmpsd|scasb|scasw|scasd|lodsb|lodsw|lodsd|stosb|stosw|stosd)'
rep2 = r'(rep) (ins|movs|outs) ([^,]+), ([^,]+)'
rep1 = r'(rep) (lods|stos) ([^,]+)'
repe2 = r'(repe|repne|repz|repnz) (cmps) ([^,]+), ([^,]+)'
repe1 = r'(repe|repne|repz|repnz) (scas) ([^,]+)'

# I/O Instructions
io2 = r'(in|ins|out|outs) ([^,]+), ([^,]+)'
io0 = r'(insb|insw|insd|outsb|outsw|outsd)'

# Flag Control Instructions
flag0 = r'(stc|clc|cmc|cld|std|lahf|sahf|pushf|pushfd|popf|popfd|sti|cli)'

# Segment Register Instructions
seg2 = r'(lds|lss|les|lfs|lgs) ([^,]+), ([^,]+)'

# Miscellaneous Instructions
lea2 = r'(lea) ([^,]+), ([^,]+)'
nop0 = r'(nop|ud2)'
nopn = r'(nop) ([\S\s]+)'
xlat1 = r'(xlat) ([^,]+)'
xlat0 = r'(xlatb)'
cpuid0 = r'(cpuid)'
movbe2 = r'(movbe) ([^,]+), ([^,]+)'
# prefetch1 = r'(prefetcht0|prefetcht1|prefetcht2|prefetchnta|prefetchw|prefetchwt1) ([^,]+)'
# clf1 = r'(clflush|clflushopt) ([^,]+)'

