# ugly hack that shouldw ork 
import multiprocessing
multiprocessing.set_start_method('fork', force=True)

import angr
import angrop


print("kernel")
proj = angr.Project("~/xps/imgs/fbsdkern", auto_load_libs=False, main_opts={"base_addr": 0xffffffff80000000, "force_rebase": True})
print("ok DONE LOAD")

print("gadgets find")
rop = proj.analyses.ROP()
rop.find_gadgets()
print(f"DONE FOUND gadgets: {len(rop.rop_gadgets)} pivots:{len(rop.pivot_gadgets)}")
rop.save_gadgets("/tmp/angrscrape")

print("\n\n\n\nfind pivots====")
for g in rop.pivot_gadgets:
    print(f"FOUND {hex(g.addr)}, {g}")

print("\n\n\n\nfind rsp-related====")
for g in rop.rop_gadgets:
    if g.stack_change != 0:
        print(f"RSP FOUND {hex(g.addr)}, change {g.stack_change}, {g}")

print("fin")