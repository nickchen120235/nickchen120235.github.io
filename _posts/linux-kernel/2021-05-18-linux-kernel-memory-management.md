---
layout: post
title: Linux Kernel Memory Management
tags: [Linux]
---

## Objective
Create a module `mtest`. When it is loaded into the kernel, a proc file `/proc/mtest` is created. The file accepts parameters as following:
- `listvma`: print all virtual addresses of all processes in the format of `start-addr end-addr permission`.
- `findpage addr`: print the corresponding physical address of virtual address `addr`. If no such translation exists, print `translation not found`.
- `writeval addr val`: try to write `val` to `addr`.

Enviroment: Ubuntu Server 20.04 with kernel version `5.4.0-73-generic `inside VMware hosted on Ubuntu Desktop 20.04

## listvma
`struct mm_struct* mm` inside `struct task_struct` points to the memory descriptor of current process. The structure of `struct mm_struct` is defined inside `linux/mm_types.h` as
```c
struct mm_struct {
  struct {
    struct vm_area_struct *mmap;    /* list of VMAs */
    struct rb_root mm_rb;
    /* ... */
  } __randomize_layout;

  /*
   * The mm_cpumask needs to be at the end of mm_struct, because it
   * is dynamically sized based on nr_cpu_ids.
   */
  unsigned long cpu_bitmap[];
};
```
`struct vm_area_struct* mmap` points to the list of VMAs, or Virtual Memory Area. The structure is also defined in the same file as
```c
/*
 * This struct describes a virtual memory area. There is one of these
 * per VM-area/task. A VM area is any part of the process virtual memory
 * space that has a special rule for the page-fault handlers (ie a shared
 * library, the executable area etc).
 */
struct vm_area_struct {
  /* The first cache line has the info for VMA tree walking. */

  unsigned long vm_start;   /* Our start address within vm_mm. */
  unsigned long vm_end;   /* The first byte after our end address
             within vm_mm. */

  /* linked list of VM areas per task, sorted by address */
  struct vm_area_struct *vm_next, *vm_prev;

  struct rb_node vm_rb;

  /*
   * Largest free memory gap in bytes to the left of this VMA.
   * Either between this VMA and vma->vm_prev, or between one of the
   * VMAs below us in the VMA rbtree and its ->vm_prev. This helps
   * get_unmapped_area find a free area of the right size.
   */
  unsigned long rb_subtree_gap;

  /* Second cache line starts here. */

  struct mm_struct *vm_mm;  /* The address space we belong to. */

  /*
   * Access permissions of this VMA.
   * See vmf_insert_mixed_prot() for discussion.
   */
  pgprot_t vm_page_prot;
  unsigned long vm_flags;   /* Flags, see mm.h. */

  /* ... */
} __randomize_layout;
```
The areas are connected using double linked list (`vm_next`, `vm_prev`).

Some interesting members
- `vm_start`: start address
- `vm_end`: end address
- `vm_flags`: permission and other flags

he flags are defined in `include/linux/mm.h` as
```c
#define VM_READ   0x00000001
#define VM_WRITE  0x00000002
#define VM_EXEC   0x00000004
```
For iterating over all processes, a macro `for_each_process` is defined in `include/linux/sched/signal.h` as
```c
#define for_each_process(p) \
  for (p = &init_task ; (p = next_task(p)) != &init_task ; )
```
So pass a `struct tast_struct*` to `p` and `p` will iterate through all processes.

The `listvma` function then can be implemented as
```c
void listvma(void) {
  struct task_struct* task; // #include <linux/sched.h>
  struct mm_struct* mm; // #include <linux/mm_types.h>
  struct vm_area_struct* vma_iter; // #include <linux/mm_types.h>
  unsigned long perm_flags;
  char perm_str[4];
  perm_str[3] = '\0';

  for_each_process(task) { // #include <linux/sched/signal.h>
    mm = task -> mm;
    if (mm != NULL) {
      vma_iter = mm->mmap;
      while (vma_iter) {
        perm_flags = vma_iter -> vm_flags;
        // #include <linux/mm.h>
        if (perm_flags & VM_READ) perm_str[0] = 'r';
        else perm_str[0] = '-';
        if (perm_flags & VM_WRITE) perm_str[1] = 'w';
        else perm_str[1] = '-';
        if (perm_flags & VM_EXEC) perm_str[2] = 'x';
        else perm_str[2] = '-';
        pr_info("[mtest] 0x%lx 0x%lx %s", vma_iter -> vm_start, vma_iter -> vm_end, perm_str);
        vma_iter = vma_iter -> vm_next;
      }
    }
  }
}
```
Example `dmesg` output looks like
```c
[ 4247.708654] [mtest] 0x7f9b18324000 0x7f9b18325000 r--
[ 4247.708654] [mtest] 0x7f9b18325000 0x7f9b18348000 r-x
[ 4247.708655] [mtest] 0x7f9b18348000 0x7f9b18350000 r--
[ 4247.708656] [mtest] 0x7f9b18351000 0x7f9b18352000 r--
[ 4247.708656] [mtest] 0x7f9b18352000 0x7f9b18353000 rw-
[ 4247.708657] [mtest] 0x7f9b18353000 0x7f9b18354000 rw-
[ 4247.708658] [mtest] 0x7ffe505f6000 0x7ffe50617000 rw-
[ 4247.708658] [mtest] 0x7ffe5069a000 0x7ffe5069d000 r--
```

## findpage
Notice that there’s a function `virt_to_phys` in `asm/io.h`. This only works for memory allocated by `kmalloc` because of its implementation. Also the `virt_addr_valid` doesn’t work either.
```c
#ifndef virt_to_phys
#define virt_to_phys virt_to_phys
static inline unsigned long virt_to_phys(volatile void *address)
{
  return __pa((unsigned long)address);
}
#endif
```
Starting from version 4.12, the kernel uses 5-level paging instead of 4. The definition of page tables and related functions/macros are defined in `asm/pgtable.h` as `p??_t`.
- `p??_offset`: get the offset of a specific address from upper level
- `p??_val`: get the value of correspond address segment
- `p??_index`: where the entry is at in current directory

So the idea is, use `p??_offset` to walk through each level and get the final physical address.
```c
void findpage(unsigned long vaddr) {
  pgd_t* pgd; p4d_t* p4d; pud_t* pud; pmd_t* pmd; pte_t* pte;
  unsigned long paddr; unsigned long page_addr;
  unsigned long page_offset;
  pr_info("[mtest.findpage] vaddr = 0x%lx", vaddr);

  pr_info("[mtest.findpage] pgtable_l5_enabled = %u\n", pgtable_l5_enabled());

  pgd = pgd_offset(current -> mm, vaddr);
  pr_info("[mtest.findpage] pgd_val = 0x%lx\n", pgd_val(*pgd));
  pr_info("[mtest.findpage] pgd_index = %lu\n", pgd_index(vaddr));
  if (pgd_none(*pgd)) {
    pr_info("[mtest.findpage] not mapped in pgd\n");
    return;
  }

  p4d = p4d_offset(pgd, vaddr);
  pr_info("[mtest.findpage] p4d_val = 0x%lx\n", p4d_val(*p4d));
  pr_info("[mtest.findpage] p4d_index = %lu\n", p4d_index(vaddr));
  if (p4d_none(*p4d)) {
    pr_info("[mtest.findpage] not mapped in p4d\n");
    return;
  }

  pud = pud_offset(p4d, vaddr);
  pr_info("[mtest.findpage] pud_val = 0x%lx\n", pud_val(*pud));
  pr_info("[mtest.findpage] pud_index = %lu\n", pud_index(vaddr));
  if (pud_none(*pud)) {
    pr_info("[mtest.findpage] not mapped in pud\n");
    return;
  }

  pmd = pmd_offset(pud, vaddr);
  pr_info("[mtest.findpage] pmd_val = 0x%lx\n", pmd_val(*pmd));
  pr_info("[mtest.findpage] pmd_index = %lu\n", pmd_index(vaddr));
  if (pmd_none(*pmd)) {
    pr_info("[mtest.findpage] not mapped in pmd\n");
    return;
  }

  pte = pte_offset_kernel(pmd, vaddr);
  pr_info("[mtest.findpage] pte_val = 0x%lx\n", pte_val(*pte));
  pr_info("[mtest.findpage] pte_index = %lu\n", pte_index(vaddr));
  if (pte_none(*pte)) {
    pr_info("[mtest.findpage] not mapped in pte\n");
    return;
  }

  page_addr = pte_val(*pte) & PAGE_MASK;
  page_offset = vaddr & ~PAGE_MASK;
  paddr = page_addr | page_offset;
  pr_info("[mtest.findpage] page_addr = 0x%lx, page_offset = 0x%lx\n", page_addr, page_offset);
  pr_info("[mtest.findpage] vaddr = 0x%lx -> paddr = 0x%lx\n", vaddr, paddr);
}
```
Easy, right?

One can compile a C code allocating some space and use `listvma` to find the corresponding virtual address. Use infinite loop like `while (1)` to keep the program running and prevent the address from changing between restarts.
```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main() {
  char* dummy = (char*) malloc(64 * sizeof(char));
  memset(dummy, 'A', 64 * sizeof(char));
  printf("Ready\n");
  while (1);
}
```
So make the module and listvma.
```c
[14584.897003] [mtest] Got command: listvma
[14584.897031] [mtest.listvma] Process = test, PID = 73409
[14584.897032] [mtest.listvma] 0x561dfa461000 0x561dfa462000 r--
[14584.897033] [mtest.listvma] 0x561dfa462000 0x561dfa463000 r-x
...
[14584.897040] [mtest.listvma] 0x7fffc7f8d000 0x7fffc7fae000 rw-
[14584.897041] [mtest.listvma] 0x7fffc7fb5000 0x7fffc7fb8000 r--
```
Let’s `findpage 0x561dfa462000`.
```c
[14809.161773] [mtest.findpage] vaddr = 0x561dfa462000
[14809.161774] [mtest.findpage] pgtable_l5_enabled = 0
[14809.161774] [mtest.findpage] pgd_val = 0x0
[14809.161775] [mtest.findpage] pgd_index = 172
[14809.161775] [mtest.findpage] p4d_val = 0x0
[14809.161775] [mtest.findpage] p4d_index = 0
[14809.161776] [mtest.findpage] not mapped in p4d
```
Wait, not mapped? What process `current` really is pointing to?
```c
[15101.776245] [mtest.findpage] current = sh, PID = 75820
```
The problem is, each process owns different parts of memory, so it is clearly not able to find the mapping from different process.

Solving is easy though, just use `for_each_process` to find the corresponding process.
```c
void findpage(unsigned long vaddr) {
  struct task_struct* task;
  pgd_t* pgd; p4d_t* p4d; pud_t* pud; pmd_t* pmd; pte_t* pte;
  unsigned long paddr; unsigned long page_addr;
  unsigned long page_offset;
  pr_info("[mtest.findpage] vaddr = 0x%lx", vaddr);

  pr_info("[mtest.findpage] pgtable_l5_enabled = %u\n", pgtable_l5_enabled());

  for_each_process(task) if (strncmp(task -> comm, "test", 4) == 0) break;
  pr_info("[mtest.findpage] current = %s, PID = %d", task -> comm, task -> pid);

  pgd = pgd_offset(task -> mm, vaddr);
  pr_info("[mtest.findpage] pgd_val = 0x%lx\n", pgd_val(*pgd));
  pr_info("[mtest.findpage] pgd_index = %lu\n", pgd_index(vaddr));
  if (pgd_none(*pgd)) {
    pr_info("[mtest.findpage] not mapped in pgd\n");
    return;
  }

  p4d = p4d_offset(pgd, vaddr);
  pr_info("[mtest.findpage] p4d_val = 0x%lx\n", p4d_val(*p4d));
  pr_info("[mtest.findpage] p4d_index = %lu\n", p4d_index(vaddr));
  if (p4d_none(*p4d)) {
    pr_info("[mtest.findpage] not mapped in p4d\n");
    return;
  }

  pud = pud_offset(p4d, vaddr);
  pr_info("[mtest.findpage] pud_val = 0x%lx\n", pud_val(*pud));
  pr_info("[mtest.findpage] pud_index = %lu\n", pud_index(vaddr));
  if (pud_none(*pud)) {
    pr_info("[mtest.findpage] not mapped in pud\n");
    return;
  }

  pmd = pmd_offset(pud, vaddr);
  pr_info("[mtest.findpage] pmd_val = 0x%lx\n", pmd_val(*pmd));
  pr_info("[mtest.findpage] pmd_index = %lu\n", pmd_index(vaddr));
  if (pmd_none(*pmd)) {
    pr_info("[mtest.findpage] not mapped in pmd\n");
    return;
  }

  pte = pte_offset_kernel(pmd, vaddr);
  pr_info("[mtest.findpage] pte_val = 0x%lx\n", pte_val(*pte));
  pr_info("[mtest.findpage] pte_index = %lu\n", pte_index(vaddr));
  if (pte_none(*pte)) {
    pr_info("[mtest.findpage] not mapped in pte\n");
    return;
  }

  page_addr = pte_val(*pte) & PAGE_MASK;
  page_offset = vaddr & ~PAGE_MASK;
  paddr = page_addr | page_offset;
  pr_info("[mtest.findpage] page_addr = 0x%lx, page_offset = 0x%lx\n", page_addr, page_offset);
  pr_info("[mtest.findpage] vaddr = 0x%lx -> paddr = 0x%lx\n", vaddr, paddr);
}
```
Try again with different address, and here we go
```c
[15877.695677] [mtest] Got command: findpage 0x7f116269a000
[15877.695678] [mtest.findpage] vaddr = 0x7f116269a000
[15877.695679] [mtest.findpage] pgtable_l5_enabled = 0
[15877.695706] [mtest.findpage] current = test, PID = 73409
[15877.695706] [mtest.findpage] pgd_val = 0x8000000077627067
[15877.695707] [mtest.findpage] pgd_index = 254
[15877.695707] [mtest.findpage] p4d_val = 0x8000000077627067
[15877.695707] [mtest.findpage] p4d_index = 0
[15877.695708] [mtest.findpage] pud_val = 0x6dca6067
[15877.695708] [mtest.findpage] pud_index = 69
[15877.695709] [mtest.findpage] pmd_val = 0x7779d067
[15877.695709] [mtest.findpage] pmd_index = 275
[15877.695710] [mtest.findpage] pte_val = 0x139e37025
[15877.695710] [mtest.findpage] pte_index = 154
[15877.695711] [mtest.findpage] page_addr = 0x139e37000, page_offset = 0x0
[15877.695711] [mtest.findpage] vaddr = 0x7f116269a000 -> paddr = 0x139e37000
```
> *Note: Sometimes the address still can't be mapped, I don't know why. Maybe it is pointed to somewhere not in memory.*

## writeval
To find the corresponding page of the pte, use macro `pte_page(pte_t)` which is also defined in `asm/pgtable.h`.
```c
#define pte_page(pte) pfn_to_page(pte_pfn(pte))
```
Use `page_address(addr)`, which is defined in `linux/mm.h`, to get the pointer to the physical address.
```c
#define page_address(page) lowmem_page_address(page)

static __always_inline void *lowmem_page_address(const struct page *page)
{
  return page_to_virt(page);
}
```
Combine the power(?) of listvma and findpage, `writeval` can be implemented like
```c
struct vm_area_struct* _findvma(unsigned long vaddr) {
  struct task_struct* task;
  struct mm_struct* mm;
  struct vm_area_struct* vma_iter;

  for_each_process(task) if (strncmp(task -> comm, "test", 4) == 0) break;
  mm = task -> mm;
  if (mm != NULL) {
    vma_iter = mm->mmap;
    while (vma_iter) {
      if (vaddr >= vma_iter -> vm_start && vaddr <= vma_iter -> vm_end) return vma_iter;
      vma_iter = vma_iter -> vm_next;
    }
  }
  return NULL;
}

inline int _vmacanwrite(struct vm_area_struct* vma) {
  if (vma -> vm_flags & VM_WRITE) return 1;
  else return -1;
}

pte_t* _findpte(unsigned long vaddr) {
  struct task_struct* task;
  pgd_t* pgd; p4d_t* p4d; pud_t* pud; pmd_t* pmd; pte_t* pte;

  for_each_process(task) if (strncmp(task -> comm, "test", 4) == 0) break;
  pgd = pgd_offset(task -> mm, vaddr);
  if (pgd_none(*pgd)) return NULL;
  p4d = p4d_offset(pgd, vaddr);
  if (p4d_none(*p4d)) return NULL;
  pud = pud_offset(p4d, vaddr);
  if (pud_none(*pud)) return NULL;
  pmd = pmd_offset(pud, vaddr);
  if (pmd_none(*pmd)) return NULL;
  pte = pte_offset_kernel(pmd, vaddr);
  if (pte_none(*pte)) return NULL;
  return pte;
}

void writeval(unsigned long vaddr, unsigned long val) {
  struct vm_area_struct* vma;
  pte_t* pte; void* addr;
  struct page* page;

  vma = _findvma(vaddr);
  if (!vma) {
    pr_info("[mtest.writeval] vma not found\n");
    return;
  }
  if (_vmacanwrite(vma) < 0) {
    pr_info("[mtest.writeval] vma has no write permission\n");
    return;
  }
  pte = _findpte(vaddr);
  if (!pte) {
    pr_info("[mtest.writeval] pte not found\n");
    return;
  }
  page = pte_page(*pte);
  addr = page_address(page);
  pr_info("[mtest.writeval] found\n");
  memset(addr, val, 1);
}
```
Try it!
```c
[ 6036.884772] [mtest] Got command: listvma
[ 6036.884819] [mtest.listvma] Process = test, PID = 19364
[ 6036.884820] [mtest.listvma] 0x55e3073bd000 0x55e3073be000 r--
[ 6036.884821] [mtest.listvma] 0x55e3073be000 0x55e3073bf000 r-x
[ 6036.884822] [mtest.listvma] 0x55e3073bf000 0x55e3073c0000 r--
...
[ 6036.884828] [mtest.listvma] 0x7f0bb470a000 0x7f0bb4710000 rw-
...
[ 6036.884833] [mtest.listvma] 0x7ffe6578e000 0x7ffe6578f000 r-x

[ 6220.488094] [mtest] Got command: findpage 0x7f0bb470a000
[ 6220.488095] [mtest.findpage] vaddr = 0x7f0bb470a000
[ 6220.488095] [mtest.findpage] pgtable_l5_enabled = 0
[ 6220.488121] [mtest.findpage] current = test, PID = 19364
[ 6220.488122] [mtest.findpage] pgd_val = 0x8000000126cdd067
[ 6220.488123] [mtest.findpage] pgd_index = 254
[ 6220.488123] [mtest.findpage] p4d_val = 0x8000000126cdd067
[ 6220.488123] [mtest.findpage] p4d_index = 0
[ 6220.488124] [mtest.findpage] pud_val = 0x126cdb067
[ 6220.488124] [mtest.findpage] pud_index = 46
[ 6220.488125] [mtest.findpage] pmd_val = 0x126cda067
[ 6220.488125] [mtest.findpage] pmd_index = 419
[ 6220.488125] [mtest.findpage] pte_val = 0x8000000106141867
[ 6220.488126] [mtest.findpage] pte_index = 266
[ 6220.488126] [mtest.findpage] page_addr = 0x8000000106141000, page_offset = 0x0
[ 6220.488127] [mtest.findpage] vaddr = 0x7f0bb470a000 -> paddr = 0x8000000106141000

[ 7015.494534] [mtest] Got command: writeval 0x7f0bb470a000 0x1
[ 7015.494568] [mtest.writeval] found
```
To verify, `hexdump /dev/mem` won’t work because there’s protection implemented. Use [`NateBrune/fmem`](https://github.com/NateBrune/fmem), which creates a unrestriced `/dev/fmem` device for memory dumping.
```
root@nick-ubuntu-vm:~/module# hd -s 0x106141000 -n 8 /dev/fmem
106141000  00 00 00 00 00 00 00 00                           |........|
106141008
root@nick-ubuntu-vm:~/module# make writeval addr=0x7f0bb470a000 val=0x1
echo writeval 0x7f0bb470a000 0x1 > /proc/mtest
root@nick-ubuntu-vm:~/module# hd -s 0x106141000 -n 8 /dev/fmem
106141000  01 00 00 00 00 00 00 00                           |........|
106141008
```

## Reference
- [https://linux-kernel-labs.github.io/refs/heads/master/labs/memory_mapping.html](https://linux-kernel-labs.github.io/refs/heads/master/labs/memory_mapping.html)
- [https://gist.github.com/anryko/c8c8788ccf7d553a140a03aba22cab88](https://gist.github.com/anryko/c8c8788ccf7d553a140a03aba22cab88)
- [http://books.gigatux.nl/mirror/kerneldevelopment/0672327201/ch14lev1sec2.html](http://books.gigatux.nl/mirror/kerneldevelopment/0672327201/ch14lev1sec2.html)
- [https://stackoverflow.com/questions/66593710/how-to-check-an-address-is-accessible-in-the-kernel-space](https://stackoverflow.com/questions/66593710/how-to-check-an-address-is-accessible-in-the-kernel-space)
- [https://stackoverflow.com/questions/41090469/linux-kernel-how-to-get-physical-address-memory-management](https://stackoverflow.com/questions/41090469/linux-kernel-how-to-get-physical-address-memory-management)
- [https://blog.csdn.net/dog250/article/details/102292288](https://blog.csdn.net/dog250/article/details/102292288)