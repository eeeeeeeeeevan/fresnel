# detector

## methodology
STRONG indicators are immediately marked as rk detected
WEAK indicators require >= 2 hits to be marked as rk detected

## checking for hidden files
the detector checks for hidden files in two ways:
1. by intentionally hiding files (canaries) with certain names (sourced from the midpoint submissions of other groups) and doing simple `ls` checks on those filenames. if they come up invisible then rootkit is present
2. checks direct path lookups in the kernel as opposed to simple directory listings, if they dont match up then rk is present

## hidden klds
1. attempts to subvert kldstat hiding by finding modules by name using `kldfind`, asking for known rk names directly (using midpoint including one which calls itself 'kernel' lol)
2. crossreferences kernel linked lists by collecting modules inside visible files and walking the global module list, this is because when a module is registered it is added to two lists: the global `modules` list and the files `lf->modules` list which are called differently
therefore a kit that hides its file from kldstat but leaves its module in the list will be detected

## kernel code patching
1. reads the live sysent table out of kernel memory and compares it with the kernel file on disk at `/boot/kernel/kernel`
2. compares the first 16 bytes of a lot of kernel functions in memory with the same bytes in the kernel file. any files which start with jmp bytes are marked as strong and other as weak
3. vnodes are structs in the kernel representing open files or dirs and have a ptr v_op to its fs operations table which provide a list of func ptrs. check_vnode_ops. we can check these vnode ptrs and if they point to some file that is hidden or an invisible module then rk is clearly present.

## hidden running procs
1. procs which are hidden in allproc and ps are still detected through proc-tree as sys/proc.h has many lists for processes including p->children and p->siblings. so we also check this and it will cover the bases so if anyone hasnt removed from allproc or ps it will still catch
2. sweeps pids and if any respond to being killed but do not exist in ps then rk detected
3. compare nprocs to ps and check the gap - if there is a large gap then this is a weak indicator

## persistence
1. flags any unusual sysctls (ones which can be written by low priv users) or hidden from sysctl -a
2. checks boot configs and cron jobs - if rk names are found then strong indicator otherwise if the job loads a mod which doesnt exist then weak indicator
