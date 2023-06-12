---
layout: post
title: Linux Kernel Debugging - Kernel Oops
tags: [Linux]
---

開發核心模組最大的難題就是 debug，特別是碰到記憶體存取的部份，碰到非法記憶體操作時並不像一般程式可以容易地接上 gdb 去檢查。
Linux kernel 提供一個提示性的功能「kernel oops」，在碰到非法但不影響核心運作的情況下會在 `dmesg` (或 `syslogd`) 看到由核心生成的訊息，透過它來嘗試找 bug。
當非法操作導致核心無法正常運作時則會產生「kernel panic」，此時*可能可以正常運作*，不過通常會導致整個系統必須重新啟動。

這篇文章會透過一個簡單的非法記憶體操作來展示如何運用 kernel oops

## 有問題的模組

```c
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>

MODULE_LICENSE("GPL");

#define OP_READ  0
#define OP_WRITE 1
#define OP_OOPS  OP_READ

static int __init my_init(void)
{
    int* a;
    a = (int*) 0xDEADBEEF;
#if OP_OOPS == OP_WRITE
    *a = 3;
#elif OP_OOPS == OP_READ
    pr_info("value = %d\n", *a);
#endif
    return 0;
}

static void __exit my_exit(void)
{
}

module_init(my_init);
module_exit(my_exit);
```

在這個模組中有一個指向非法空間的 pointer，如果我們嘗試對其進行讀或寫，就會觸發 exception，而產生 kernel oops

編譯的時候在 `KCFLAGS` 中加入 `-g`，保留 symbol

### 非法讀操作

首先先來看看進行一個非法讀操作會發生什麼事，雙開 terminal，其中一個用來處理模組，另一個用來看 `dmesg` 的輸出

```
[ 1213.434455] BUG: unable to handle page fault for address: 00000000deadbeef
[ 1213.434477] #PF: supervisor read access in kernel mode
[ 1213.434486] #PF: error_code(0x0000) - not-present page
[ 1213.434494] PGD 0 P4D 0 
[ 1213.434501] Oops: 0000 [#1] PREEMPT SMP NOPTI
[ 1213.434510] CPU: 1 PID: 1666 Comm: insmod Tainted: G           O      5.19.0-43-generic #44~22.04.1-Ubuntu
[ 1213.434525] Hardware name: QEMU Standard PC (Q35 + ICH9, 2009), BIOS 0.0.0 02/06/2015
[ 1213.434536] RIP: 0010:my_init+0xb/0x1000 [oops]
[ 1213.434549] Code: Unable to access opcode bytes at RIP 0xffffffffc06e6fe1.
[ 1213.434578] RSP: 0018:ffffadf7c0a97be8 EFLAGS: 00010246
[ 1213.434588] RAX: 00000000deadbeef RBX: 0000000000000000 RCX: 0000000000000000
[ 1213.434598] RDX: 0000000000000000 RSI: 0000000000000000 RDI: 0000000000000000
[ 1213.434608] RBP: ffffadf7c0a97c58 R08: 0000000000000000 R09: 0000000000000000
[ 1213.434618] R10: 0000000000000000 R11: 0000000000000000 R12: ffffffffc06e7000
[ 1213.434628] R13: ffffa0181b77ced0 R14: ffffffffc06f1018 R15: ffffffffc06f1000
[ 1213.434638] FS:  00007f3b79531c40(0000) GS:ffffa0187bd00000(0000) knlGS:0000000000000000
[ 1213.434650] CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
[ 1213.434659] CR2: ffffffffc06e6fe1 CR3: 0000000115fcc002 CR4: 0000000000770ee0
[ 1213.434672] PKRU: 55555554
[ 1213.434678] Call Trace:
[ 1213.434683]  <TASK>
[ 1213.434689]  ? do_one_initcall+0x46/0x230
[ 1213.434700]  ? kmem_cache_alloc_trace+0x1a6/0x330
[ 1213.434712]  do_init_module+0x52/0x220
[ 1213.434721]  load_module+0xb56/0xd40
[ 1213.434728]  ? security_kernel_post_read_file+0x5c/0x80
[ 1213.434739]  ? kernel_read_file+0x245/0x2a0
[ 1213.434748]  __do_sys_finit_module+0xcc/0x150
[ 1213.434757]  ? __do_sys_finit_module+0xcc/0x150
[ 1213.434767]  __x64_sys_finit_module+0x18/0x30
[ 1213.434776]  do_syscall_64+0x59/0x90
[ 1213.434785]  ? exit_to_user_mode_prepare+0x3b/0xd0
[ 1213.434795]  ? syscall_exit_to_user_mode+0x2a/0x50
[ 1213.434805]  ? do_syscall_64+0x69/0x90
[ 1213.434822]  ? syscall_exit_to_user_mode+0x2a/0x50
[ 1213.434898]  ? do_syscall_64+0x69/0x90
[ 1213.434906]  ? do_syscall_64+0x69/0x90
[ 1213.434913]  ? exit_to_user_mode_prepare+0x3b/0xd0
[ 1213.434923]  ? syscall_exit_to_user_mode+0x2a/0x50
[ 1213.434932]  ? do_syscall_64+0x69/0x90
[ 1213.434940]  ? exc_page_fault+0x92/0x1b0
[ 1213.434950]  entry_SYSCALL_64_after_hwframe+0x63/0xcd
[ 1213.434960] RIP: 0033:0x7f3b78d1ea3d
[ 1213.435226] Code: 5b 41 5c c3 66 0f 1f 84 00 00 00 00 00 f3 0f 1e fa 48 89 f8 48 89 f7 48 89 d6 48 89 ca 4d 89 c2 4d 89 c8 4c 8b 4c 24 08 0f 05 <48> 3d 01 f0 ff ff 73 01 c3 48 8b 0d c3 a3 0f 00 f7 d8 64 89 01 48
[ 1213.435739] RSP: 002b:00007ffcc2b5a288 EFLAGS: 00000246 ORIG_RAX: 0000000000000139
[ 1213.436008] RAX: ffffffffffffffda RBX: 0000557a6cf3f790 RCX: 00007f3b78d1ea3d
[ 1213.436284] RDX: 0000000000000000 RSI: 0000557a6bb9ecd2 RDI: 0000000000000003
[ 1213.436560] RBP: 0000000000000000 R08: 0000000000000000 R09: 0000000000000000
[ 1213.436828] R10: 0000000000000003 R11: 0000000000000246 R12: 0000557a6bb9ecd2
[ 1213.437071] R13: 0000557a6cf3f760 R14: 0000557a6bb9d888 R15: 0000557a6cf3f8a0
[ 1213.437314]  </TASK>
[ 1213.437573] Modules linked in: oops(O+) intel_rapl_msr intel_rapl_common kvm_intel nls_iso8859_1 kvm input_leds serio_raw qemu_fw_cfg mac_hid sch_fq_codel dm_multipath scsi_dh_rdac scsi_dh_emc scsi_dh_alua msr ramoops efi_pstore reed_solomon pstore_blk pstore_zone virtio_rng ip_tables x_tables autofs4 btrfs blake2b_generic raid10 raid456 async_raid6_recov async_memcpy async_pq async_xor async_tx xor raid6_pq libcrc32c raid1 raid0 multipath linear crct10dif_pclmul crc32_pclmul ghash_clmulni_intel qxl aesni_intel drm_ttm_helper crypto_simd ttm cryptd drm_kms_helper i2c_i801 i2c_smbus syscopyarea sysfillrect sysimgblt fb_sys_fops xhci_pci virtio_net xhci_pci_renesas psmouse ahci libahci net_failover lpc_ich failover virtio_blk drm
[ 1213.439579] CR2: 00000000deadbeef
[ 1213.439882] ---[ end trace 0000000000000000 ]---
```

內容看起來很多，挑幾個重點出來看

```
BUG: unable to handle page fault for address: 00000000deadbeef
```

告訴我們一個非法記憶體操作造成這個 kernel oops 的產生

```
Oops: 0000 [#1] PREEMPT SMP NOPTI
```

首先 `[#1]` 代表這是一系列 oops 中的第一個，oops 有可能產生其他 oops，而通常第一個 oops 是罪魁禍首

再來是前面的 `0000` (oops code)，在這邊主要要注意的是第 0 到 2 bits，詳細定義可以參考核心原始碼中的 [`arch/x86/include/asm/trap_ph.h`](https://elixir.bootlin.com/linux/v5.10/source/arch/x86/include/asm/trap_pf.h)

||bit 2|bit 1|bit 0|
|:-:|:-:|:-:|:-:|
|0|kernel mode|read|no page found|
|1|user mode|write|protection fault|

```
RIP: 0010:my_init+0xb/0x1000 [oops]
```

有問題的部份在 `my_init` 函數入口 + `0xb`

有這些資訊就可以搭配 `objdump` 或 `addr2line` 等工具找出製造 oops 的位置，以這裡來說

```
nick@nick-ubuntu-vm:~/coding/oops$ addr2line -e oops.o 0xb
/home/nick/coding/oops/oops.c:18
```

### 非法寫操作

再來看看非法寫操作會發生什麼事，這裡我們主要關心的是 oops code 跟 addr2line 的變化

```
Oops: 0002 [#1] PREEMPT SMP NOPTI
```

參考上面的表格，可以發現這次 bit 1 是 1，也就是 write access 錯誤

```
nick@nick-ubuntu-vm:~/coding/oops$ addr2line -e oops.o 0xb
/home/nick/coding/oops/oops.c:16
```

> 在使用 `objdump` 或 `addr2line` 時，編譯的 `.o` 或 `.ko` 都可以用

## Reference
- [https://linux-kernel-labs.github.io/refs/heads/master/labs/kernel_modules.html#kernel-module-debugging](https://linux-kernel-labs.github.io/refs/heads/master/labs/kernel_modules.html#kernel-module-debugging)
