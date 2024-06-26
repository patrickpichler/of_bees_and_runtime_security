---
colorSchema: light
theme: apple-basic
highlighter: shiki
lineNumbers: false
drawings:
  persist: false
transition: slide-left
title: Of bees and Kubernetes Runtime Security
mdc: true
layout: section
class: text-center
defaults:
    layout: center
---

# Of bees and Kubernetes Runtime Security

---
layout: full
---

<div class="grid grid-cols-[1fr_35%] gap-6">

<div>
<h1 class="bold">Who am I?</h1>

<br/>

<h2>Software engineer turned Cloud Enthusiast <noto-cloud /></h2>
<br/>
<h2>Kubernetes wizard <noto-magic-wand /></h2>
<br/>
<h2>Linux Nerd <devicon-linux /></h2>
</div>

<div>
<img src="/profile_pic_compressed.jpg" style="border-radius: 50%;"/>
</div>

</div>

<!--
Originally I started my career as a Java Software Developer, but everything changed when I stumbled
upon Linux and the cloud. This definitely transformed me into a full-on Linux nerd. Do not question the MacBook though.
-->

---
layout: image
image: /philosoraptor.png
backgroundSize: contain
---

<!--
Let me first ask you a question, who of you here has heared about ebpf? has anyone already
consciously used it?
-->

---
layout: image
image: /ebpf_overview.png
backgroundSize: contain
---

---
layout: fact
---

History of eBPF

---
layout: section
---

<div class="items">

* Merged with Linux 3.18 (2014)

<v-clicks>

* Alexei Strarovoitov (creator)
* Original use-case software defined networking
* Now serves many other use-cases

</v-clicks>

</div>

---
layout: image
image: /ebpf_history.svg
backgroundSize: 40%
---

<div style="display: flex; align-items: end; height: 100%; justify-content: center">
<span style="color: black; font-size: 2em;">
eBPF’s Creation Story – Unlocking The Kernel
</span>
</div>

---
layout: fact
---

Let's get technical!

---
layout: image
image: /syscall-hook.png
backgroundSize: contain
---

---
layout: image
image: /source-to-vm.svg
backgroundSize: 70%
---
---

# eBPF Virtual Machine

---
layout: full
---

<div class="full-center fancy-table">

| Register | Function |
| -------- | -------- |
| REG-0    | Return value |
| REG-1 - REG-5    | Pass arguments to functions |
| REG-6 - REG-9    | No special function |
| REG-10    | Stack frame pointer |

</div>

---
layout: full
---

<div class="full-center">
<div>
<div class="filepath">
<a href="https://elixir.bootlin.com/linux/latest/source/include/uapi/linux/bpf.h#L77">include/uapi/linux/bpf.h</a>
</div>

```c
bpf_insn {
	__u8	code;		/* opcode */
	__u8	dst_reg:4;	/* dest register */
	__u8	src_reg:4;	/* source register */
	__s16	off;		/* signed offset */
	__s32	imm;		/* signed immediate constant */
};
```

</div>
</div>

---
layout: full
---

<div class="full-center fancy-table">

| OpCode | Mnemonic |
| -------- | -------- |
| 0x07    | add dst, imm |
| 0x85    | call imm  |
| 0x5f    | and dst, src  |

</div>

---
layout: image
image: /bpf_isa_docs.svg
backgroundSize: 40%
---

<div style="display: flex; align-items: end; height: 100%; justify-content: center">
<span style="color: black; font-size: 2em;">
BPF Instruction Set Architecture Docs
</span>
</div>

---
layout: image
image: map-architecture.png
backgroundSize: 70%
---
---
layout: section
---

<v-switch>
<template #0>

<div class="items">

* HashTable, Arrays
* LRU (Least Recently Used)
* Perf and Ring Buffer
* TailCall maps


</div>
</template>

<template #1>

<div class="items highlighted-listing">

<ul>
<li>HashTable, Arrays</li>
<li>LRU (Least Recently Used)</li>
<li>Perf and Ring Buffer</li>
<li class="current"> TailCall maps </li>
</ul>

</div>

</template>

</v-switch>

---
layout: fact
---

<span class="fact">

Instruction Limit of <span class="highlighted-element"> 1 Million </span> (Linux 6.0)

</span>

---
layout: image
image: tailcall.png
backgroundSize: 70%
---

---
layout: full
---

<div class="full-center">
<div>
<div class="filepath">
<a href="https://elixir.bootlin.com/linux/latest/source/include/uapi/linux/bpf.h#L1024">include/uapi/linux/bpf.h</a>
</div>

```c
// There are ~30 different program types
enum bpf_prog_type {
    BPF_PROG_TYPE_UNSPEC,
    BPF_PROG_TYPE_SOCKET_FILTER,
    BPF_PROG_TYPE_KPROBE,
    BPF_PROG_TYPE_SCHED_CLS,
    BPF_PROG_TYPE_SCHED_ACT,
    BPF_PROG_TYPE_TRACEPOINT,
    BPF_PROG_TYPE_XDP,
    BPF_PROG_TYPE_PERF_EVENT,
    // ...
}
```

</div>
</div>

---
layout: section
---

# Tracepoint

---
layout: section
---

<div class="items">

* Marked location in the kernel

<v-clicks>

* Not specific to eBPF
* Considered kernel API (stable)
* 1400+ Tracepoints defined (Linux 5.15)

</v-clicks>

</div>

---
layout: full
---


<div class="full-center">
<div>
<div class="filepath">
/sys/kernel/traceing/available_events
</div>

```
syscalls:sys_exit_accept
syscalls:sys_enter_accept
syscalls:sys_exit_accept4
syscalls:sys_enter_accept4
syscalls:sys_exit_listen
syscalls:sys_enter_listen
syscalls:sys_exit_bind
syscalls:sys_enter_bind
syscalls:sys_exit_socketpair
syscalls:sys_enter_socketpair
syscalls:sys_exit_socket
syscalls:sys_enter_socket
```

</div>

</div>

---
layout: section
---

# Kprobe/Kretprobe

---
layout: section
---

<div class="items">

* Can hook <span class="highlighted-element">any</span> kernel function

<v-clicks>

* No stability guarantee (kernel functions can change)

</v-clicks>

</div>

---
layout: section
---

# LSM

---
layout: section
---

<div class="items">

* Linux Security Modules

<v-clicks>

* Return value controls how kernel behaves

</v-clicks>

</div>

---
layout: section
---

# XDP

---
layout: section
---

<div class="items">

* EXpress Data Path

<v-clicks>

* Used to filter packets (controlled by return value)

</v-clicks>

</div>

---
layout: full
---

<div class="full-center fancy-table">

| Value | Action |
| -------- | -------- |
| XDP_ABORTED | Signals error in the Program (should never be used) |
| XDP_DROP    | Drop the packet |
| XDP_PASS | Sends packet further up the network stack |
| XDP_TX | Bounces packets out the same NIC it arrived on |
| XDP_REDIRECT | Sends packet to different NIC |

</div>

---
layout: fact
---

sched-ext (Linux 6.11)

---
layout: section
---

# Helpers

---
layout: image
image: /helper.png
backgroundSize: 90%
---
---

```c {|2|4|5-9}{lines:true}
struct bpf_func_proto {
    u64 (*func)(u64 r1, u64 r2, u64 r3, u64 r4, u64 r5);
    bool gpl_only;
    enum bpf_return_type ret_type;
    enum bpf_arg_type arg1_type;
    enum bpf_arg_type arg2_type;
    enum bpf_arg_type arg3_type;
    enum bpf_arg_type arg4_type;
    enum bpf_arg_type arg5_type;
    bool (*allowed)(const struct bpf_prog *prog);
};
```

---

```c {|3}{lines:true}
const struct bpf_func_proto bpf_for_each_map_elem_proto = {
	.func		= bpf_for_each_map_elem,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_CONST_MAP_PTR,
	.arg2_type	= ARG_PTR_TO_FUNC,
	.arg3_type	= ARG_PTR_TO_STACK_OR_NULL,
	.arg4_type	= ARG_ANYTHING,
};
```

---
layout: section
---
```c
long bpf_probe_read_kernel(void *dst, u32 size, const void *unsafe_ptr)
```

---
layout: section
---

<div class="items">

* Read arbitrary data from kernel memory

<v-clicks>

* You are responsible for what you read
* More stable alternative: CO-RE

</v-clicks>

</div>

---
layout: section
---
```c
void *bpf_map_lookup_elem(struct bpf_map *map, const void *key)
```
---
layout: section
---

<div class="items">

* Read data from an eBPF map

<v-clicks>

* <mdi-warning class="text-red-400"/> Pointer to memory region is returned

</v-clicks>

</div>

---
layout: section
---
```c
long bpf_map_update_elem(struct bpf_map *map, const void *key,
                            const void *value, u64 flags)
```
---
layout: full
---

<div class="full-center fancy-table">

| Flag | Description |
| -------- | -------- |
| BPF_NOEXIT | Fails if key exist |
| BPF_EXIST | Fails if key does not exist |
| BPF_ANY | Doesn't care |

</div>

---
layout: section
---
```c
u64 bpf_get_current_task(void)
```
---
layout: section
---

<div class="items">

* Return pointer to `task_struct`

<v-clicks>

* Contains data such as:
    * Current Namespaces
    * PID/TGID
    * Opened Files

</v-clicks>

</div>

---
layout: full
---


<div class="full-center">
<div>
<div class="filepath">
<a href="https://elixir.bootlin.com/linux/latest/source/include/linux/sched.h#L748">include/linux/sched.h</a>
</div>

```c {all}
struct task_struct {
    // ...
    struct sched_info		sched_info;
    struct list_head		tasks;
    // ...
    struct mm_struct		*mm;
    // ...
    unsigned int			personality;
    // ...
    struct files_struct		*files;
    // ...
    struct nsproxy			*nsproxy;
}
```

</div>
</div>

---
layout: section
---

# Bytecode in Action

---
layout: full
---

<div class="full-center">

```c {all|4|6|8-9|11-13|14|all}{lines:true}
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "GPL";

SEC("xdp")
int hello(void *ctx) {
  __u64 tgid = bpf_get_current_pid_tgid();
  __u32 pid = tgid >> 32;

  if (pid == 32) {
    return XDP_DROP;
  }
  return XDP_PASS;
}
```

</div>

---
layout: full
---

<div class="full-center">

```sh
clang \
    -target bpf \
    -I/usr/include/aarch64-linux-gnu \
    -g \
    -O2 -o hello.bpf.o -c hello.bpf.c
```

</div>

---
layout: full
---

<div class="full-center">

```sh
llvm-objdump-14 --section xdp hello.bpf.o -d
```

</div>

---
layout: full
---

<div class="full-center code-small-font">

```plain {all|6}{lines:true}
hello.bpf.o:    file format elf64-bpf

Disassembly of section xdp:

0000000000000000 <hello>:
       0:       85 00 00 00 0e 00 00 00 call 14
       1:       bf 01 00 00 00 00 00 00 r1 = r0
       2:       18 02 00 00 00 00 00 00 00 00 00 00 ff ff ff ff r2 = -4294967296 ll
       4:       5f 21 00 00 00 00 00 00 r1 &= r2
       5:       b7 00 00 00 01 00 00 00 r0 = 1
       6:       18 02 00 00 00 00 00 00 00 00 00 00 20 00 00 00 r2 = 137438953472 ll
       8:       1d 21 01 00 00 00 00 00 if r1 == r2 goto +1 <LBB0_2>
       9:       b7 00 00 00 02 00 00 00 r0 = 2

0000000000000050 <LBB0_2>:
      10:       95 00 00 00 00 00 00 00 exit
```

</div>

---
layout: full
---


<div class="full-center">
<div>
<div class="filepath">
<a href="https://elixir.bootlin.com/linux/v6.9.6/source/include/uapi/linux/bpf.h#L5801">include/uapi/linux/bpf.h</a>
</div>

```c {all|12}{lines:true}
#define ___BPF_FUNC_MAPPER(FN, ctx...)			\
    // ...
	FN(ktime_get_ns, 5, ##ctx)			\
	FN(trace_printk, 6, ##ctx)			\
	FN(get_prandom_u32, 7, ##ctx)			\
	FN(get_smp_processor_id, 8, ##ctx)		\
	FN(skb_store_bytes, 9, ##ctx)			\
	FN(l3_csum_replace, 10, ##ctx)			\
	FN(l4_csum_replace, 11, ##ctx)			\
	FN(tail_call, 12, ##ctx)			\
	FN(clone_redirect, 13, ##ctx)			\
	FN(get_current_pid_tgid, 14, ##ctx)		\
    // ...
```

</div>
</div>

---
layout: full
---

<div class="full-center code-small-font">

```plain {7|8|9|8}{lines:true}
hello.bpf.o:    file format elf64-bpf

Disassembly of section xdp:

0000000000000000 <hello>:
       0:       85 00 00 00 0e 00 00 00 call 14
       1:       bf 01 00 00 00 00 00 00 r1 = r0
       2:       18 02 00 00 00 00 00 00 00 00 00 00 ff ff ff ff r2 = -4294967296 ll
       4:       5f 21 00 00 00 00 00 00 r1 &= r2
       5:       b7 00 00 00 01 00 00 00 r0 = 1
       6:       18 02 00 00 00 00 00 00 00 00 00 00 20 00 00 00 r2 = 137438953472 ll
       8:       1d 21 01 00 00 00 00 00 if r1 == r2 goto +1 <LBB0_2>
       9:       b7 00 00 00 02 00 00 00 r0 = 2

0000000000000050 <LBB0_2>:
      10:       95 00 00 00 00 00 00 00 exit
```

</div>

---
layout: image
image: endianess.png
backgroundSize: 80%
---
<div class="attribution">
    By <a href="//commons.wikimedia.org/wiki/User:Aeroid" title="User:Aeroid">Aeroid</a> - <span class="int-own-work" lang="en">Own work</span>, <a href="https://creativecommons.org/licenses/by-sa/4.0" title="Creative Commons Attribution-Share Alike 4.0">CC BY-SA 4.0</a>, <a href="https://commons.wikimedia.org/w/index.php?curid=137790829">Link</a>
</div>

---
layout: full
---

<div class="full-center code-small-font">

```plain {10|11|12|13|16|all|6-8|8-9}{lines:true}
hello.bpf.o:    file format elf64-bpf

Disassembly of section xdp:

0000000000000000 <hello>:
       0:       85 00 00 00 0e 00 00 00 call 14
       1:       bf 01 00 00 00 00 00 00 r1 = r0
       2:       18 02 00 00 00 00 00 00 00 00 00 00 ff ff ff ff r2 = -4294967296 ll
       4:       5f 21 00 00 00 00 00 00 r1 &= r2
       5:       b7 00 00 00 01 00 00 00 r0 = 1
       6:       18 02 00 00 00 00 00 00 00 00 00 00 20 00 00 00 r2 = 137438953472 ll
       8:       1d 21 01 00 00 00 00 00 if r1 == r2 goto +1 <LBB0_2>
       9:       b7 00 00 00 02 00 00 00 r0 = 2

0000000000000050 <LBB0_2>:
      10:       95 00 00 00 00 00 00 00 exit
```

</div>

---
layout: section
---

# Verifier

---
layout: image
image: verifier.png
backgroundSize: 90%
---

---
layout: section
---

# Stage 1

---
layout: section
---

<div class="items">

* Turn ByteCode into DAG

<v-clicks>

* Check for unbounded loops
* Check for dead code

</v-clicks>

</div>

---
layout: section
---

# Stage 2

---
layout: section
---

<div class="items">

* Descend all possible paths

<v-clicks>

* Simulate execution
* Verify state changes

</v-clicks>

</div>

---
layout: fact
---

Learn to read verifier errors!

---
layout: full
---

<div class="full-center">

```plain
unreachable insn 1
```

</div>

---
layout: full
---

<div class="full-center">

```plain
0: (7a) *(u64 *)(r10 -8) = 0
1: (bf) r2 = r10
2: (07) r2 += -8
3: (b7) r1 = 1
4: (85) call 1
5: (15) if r0 == 0x0 goto pc+2
 R0=map_ptr R10=fp
6: (7a) *(u64 *)(r0 +0) = 0
7: (95) exit

from 5 to 8: R0=imm0 R10=fp
8: (7a) *(u64 *)(r0 +0) = 1
R0 invalid mem access 'imm'
```

</div>

---
layout: section
---

# eBPF in the wild

---
layout: section
---

# Katran

---
layout: section
---

<div class="items">

* Central component of Facebook's network infrastructure

<v-clicks>

* Makes heavy use of XDP
* Relatively low CPU impact

</v-clicks>

</div>

---
layout: section
---

# Cilium

---
layout: section
---

<div class="items">

* CNI plugin for Kubernets Clusters

<v-clicks>

* Full blown network observability/security solution
* Uses XDP for all sorts of things
    * Network Policies
    * kube-proxy replacement

</v-clicks>

</div>

---
layout: section
---

# Datadog Agent

---
layout: section
---

<div class="items">

* Mostly Tracing

<v-clicks>

* LSM for blocking syscalls

</v-clicks>

</div>

---
layout: section
---

# Tetragon

---
layout: section
---

<div class="items">

* Allows you to hook kernel functions/tracepoints

<v-clicks>

* Kill processes on custom written policies
* Signal is send in process

</v-clicks>

</div>

---
layout: section
---

# CAST.AI kvisor

---
layout: fact
---

<div>

**FULL DISCLAIMER:**

</div>
<div style="margin-top: 40px;">

I work there

</div>

---
layout: fact
---

Meet CAST.AI

---
layout: image
image: /kvisor.png
backgroundSize: 90%
---

---
layout: section
---

# Detecting container drift with eBPF


---
layout: fact
---

Kudos to Falco!

---
layout: image
image: /kvisor-architecture.svg
backgroundSize: 90%
---

<v-switch>
<template #1>
<Arrow x1=300 y1=500 x2=390 y2=400 color='red' width=4 />
</template>
<template #2>
<Arrow x1=20 y1=220 x2=180 y2=245 color='red' width=4 />
</template>
<template #3>
<Arrow x1=230 y1=100 x2=385 y2=180 color='red' width=4 />
</template>
<template #4>
<Arrow x1=800 y1=400 x2=650 y2=300 color='red' width=4 />
</template>
<template #5>
<Arrow x1=800 y1=350 x2=850 y2=200 color='red' width=4 />
</template>
<template #6>
</template>
</v-switch>

---
layout: image
image: /detecting-containerdrift.svg
backgroundSize: contain
---

---
layout: section
---

# Inode

---
layout: section
---

<div class="items">

* Stands for Index Node

<v-clicks>

* Used in FS
* Unique Identifier + Metadata

</v-clicks>

</div>

---
layout: full
---


<div class="full-center">
<div>
<div class="filepath">
<a href="https://elixir.bootlin.com/linux/latest/source/include/linux/fs.h#L632">include/linux/fs.h</a>
</div>

```c {all}
struct inode {
    umode_t			i_mode;
    unsigned short		i_opflags;
    kuid_t			i_uid;
    kgid_t			i_gid;
    // ...
    const struct inode_operations	*i_op;
    struct super_block	*i_sb;
    // ...
    loff_t			i_size;
    struct timespec64	__i_atime;
    struct timespec64	__i_mtime;
    struct timespec64	__i_ctime;
//...
}
```

</div>
</div>

---
layout: full
---

<div class="full-center code-small-font">
<div>
<div class="filepath">
<a href="https://elixir.bootlin.com/linux/latest/source/fs/overlayfs/ovl_entry.h#L162">fs/overlayfs/ovl_entry.h</a>
</div>

```c {all|9|10}
struct ovl_inode {
    union {
        struct ovl_dir_cache *cache;	/* directory */
        const char *lowerdata_redirect;	/* regular file */
    };
    const char *redirect;
    u64 version;
    unsigned long flags;
    struct inode vfs_inode;
    struct dentry *__upperdentry;
    struct ovl_entry *oe;

    /* synchronize copy up and more */
    struct mutex lock;
};

```

</div>
</div>

---
layout: section
---

<div class="items">

* `ovl_inode` has `__upperdentry != NULL`

<v-clicks>

* `__upperdentry->d_fsdata` has `OVL__UPPER_ALIAS` set

</v-clicks>

</div>

---
layout: full
---

<div class="full-center">
<div>
<div class="filepath">
<a href="https://github.com/castai/kvisor/blob/f62942841fde29d01b326bb43fd698387d077cde/pkg/ebpftracer/c/tracee.bpf.c#L1218">pkg/ebpftracer/c/tracee.bpf.c:1218</a>
</div>

```c {all}
SEC("raw_tracepoint/sched_process_exec")
int tracepoint__sched__sched_process_exec(struct bpf_raw_tracepoint_args *ctx)
{
    program_data_t p = {};
    if (!init_program_data(&p, ctx)) {
        return 0;
    }

    // ...
}

```

</div>
</div>

---
layout: full
---

<div class="full-center code-small-font">
<div>
<div class="filepath">
<a href="https://github.com/castai/kvisor/blob/f62942841fde29d01b326bb43fd698387d077cde/pkg/ebpftracer/c/tracee.bpf.c#L1218">pkg/ebpftracer/c/tracee.bpf.c:1218</a>
</div>

```c {all|13}
SEC("raw_tracepoint/sched_process_exec")
int tracepoint__sched__sched_process_exec(struct bpf_raw_tracepoint_args *ctx)
{
    // ...
    struct linux_binprm *bprm = (struct linux_binprm *) ctx->args[2];
    struct file *file = get_file_ptr_from_bprm(bprm);
    // ...
    struct path f_path = (struct path)BPF_CORE_READ(file, f_path);
    struct dentry* dentry = f_path.dentry;
    struct super_block *sb = BPF_CORE_READ(inode, i_sb);
    u32 flags = 0;
    if (sb && inode) {
        if (get_exe_upper_layer(dentry, sb)) {
            flags |= FS_EXE_UPPER_LAYER;
        }
    // ...
    }
    // ...
}

```

</div>
</div>

---
layout: full
---

<div class="full-center">
<div>
<div class="filepath">
<a href="https://elixir.bootlin.com/linux/latest/source/include/linux/fs.h#L1207">include/linux/fs.h</a>
</div>

```c {all|10}
struct super_block {
    struct list_head	s_list;
    // ...
    unsigned long		s_blocksize;
    loff_t			s_maxbytes;
    struct file_system_type	*s_type;
    const struct super_operations	*s_op;
    // ...
    unsigned long		s_flags;
    unsigned long		s_magic;
    struct dentry		*s_root;
    // ...
}

```

</div>
</div>

---
layout: full
---

<div class="full-center">
<div>
<div class="filepath">
<a href="https://elixir.bootlin.com/linux/v6.9.6/source/include/linux/dcache.h#L82">include/linux/dcache.h</a>
</div>

```c {all|5-6}
struct dentry {
    // ...
    unsigned int d_flags;
    seqcount_spinlock_t d_seq;
    struct qstr d_name;
    struct inode *d_inode;
    // ...
    void *d_fsdata;			/* fs-specific data */
    // ...
};

```

</div>
</div>

---
layout: full
---

<div class="full-center code-small-font">
<div>
<div class="filepath">
<a href="https://github.com/castai/kvisor/blob/f62942841fde29d01b326bb43fd698387d077cde/pkg/ebpftracer/c/tracee.bpf.c#L1218">pkg/ebpftracer/c/tracee.bpf.c:1218</a>
</div>

```c {5-10}
SEC("raw_tracepoint/sched_process_exec")
int tracepoint__sched__sched_process_exec(struct bpf_raw_tracepoint_args *ctx)
{
    // ...
    struct linux_binprm *bprm = (struct linux_binprm *) ctx->args[2];
    struct file *file = get_file_ptr_from_bprm(bprm);
    // ...
    struct path f_path = (struct path)BPF_CORE_READ(file, f_path);
    struct dentry* dentry = f_path.dentry;
    struct super_block *sb = BPF_CORE_READ(inode, i_sb);
    u32 flags = 0;
    if (sb && inode) {
        if (get_exe_upper_layer(dentry, sb)) {
            flags |= FS_EXE_UPPER_LAYER;
        }
    // ...
    }
    // ...
}

```

</div>
</div>

---
layout: full
---

<div class="full-center code-small-font">
<div>
<div class="filepath">
<a href="https://github.com/castai/kvisor/blob/f62942841fde29d01b326bb43fd698387d077cde/pkg/ebpftracer/c/headers/common/filesystem.h#L503">pkg/ebpftracer/c/headers/common/filesystem.h:503</a>
</div>

```c {all|2-5|8|15|all}{lines:true}
statfunc bool get_exe_upper_layer(struct dentry *dentry, struct super_block *sb) {
    unsigned long sb_magic = BPF_CORE_READ(sb, s_magic);
    if (sb_magic != FS_OVERLAYFS_SUPER_MAGIC) {
        return false;
    }
    struct dentry *upper_dentry = NULL;
    char *vfs_inode = (char *) BPF_CORE_READ(dentry, d_inode);
    struct dentry *tmp = (struct dentry *) (vfs_inode + sizeof(struct inode));
    upper_dentry = READ_KERNEL(tmp);
    if (!upper_dentry) {
        return false;
    }
    // ...
    unsigned long flags = (unsigned long) READ_KERNEL(dentry->d_fsdata);
    unsigned long has_upper = (flags & (1U << (OVL_E_UPPER_ALIAS)));
    if (has_upper) {
        return true;
    }
    return false;
}
```

</div>
</div>

---
layout: fact
---

And that is about it!

---
layout: section
---

<div class="items">

* eBPF is like JS for the kernel

<v-clicks>

* Wide array of use-cases
    * Monitoring (tracepoints)
    * Networking (XDP)
    * Security (LSM)
* More exiting things on the horizon
    * E.g. sched-ext

</v-clicks>

</div>

---
layout: fact
---

Check out <a href="https://patrickpichler.dev">patrickpichler.dev</a>

---
layout: image
image: blog.png
backgroundSize: contain
---

---
layout: image
image: blog-meme.png
backgroundSize: 50%
---

---
layout: image
image: cast-hiring.svg
backgroundSize: 40%
---

<div style="display: flex; align-items: end; height: 100%; justify-content: center">
<span style="color: black; font-size: 2em;">
Senior Software Engineer - Security Product Team
</span>
</div>

---
layout: fact
---

Thanks!
