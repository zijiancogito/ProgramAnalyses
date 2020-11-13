import Asm
import sys

def test_asm(binfile):
  proj = Asm.cfg.Proj(binfile)
  print(proj.cfg)
  for address in proj._addr_to_func:
    proj.plot(address, proj._addr_to_func[address].name)


test_asm(sys.argv[1])