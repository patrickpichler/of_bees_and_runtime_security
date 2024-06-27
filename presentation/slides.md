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

* goal of the talk: give you better understanding why ebpf next gen tech
* we do it by deep dive
* checkout how it is used in cloud native landscape
-->

---
layout: image
image: /ebpf-comic.png
backgroundSize: 80%
---

<div class="attribution">
    eBPF Comic by Philipp Meier and Thomas Graf
</div>

<!--
* think of it as JS for linux kernel
* why big deal? before it was hard to extend
* ebpf changed this by offering secure way
-->

---
layout: image
image: /ebpf_overview.png
backgroundSize: contain
---

<!--
* used today in quite a lot of different tools/products
* quite a few components involved
* we are going to have a look at them
-->

---
layout: fact
---

History of eBPF

<!--
* quick history lesson
* i will not turn this into a lengthy lecture
-->

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

<!--
* eBPF was introduced in linux 3.18
* lot of hard work by alexei strarovoitov
* originally extended berkely package filter, now its own term
* original use case network virtualisation and software defined networking
* now caters many use cases
-->

---
layout: image
image: /ebpf_history.svg
backgroundSize: 40%
---

<div style="display: flex; align-items: end; height: 100%; justify-content: center">
<span style="color: black; font-size: 2em;">
<a href="https://isovalent.com/blog/post/ebpf-documentary-creation-story/">
eBPF’s Creation Story – Unlocking The Kernel
</a>
</span>
</div>

<!--
* to learn more, checkout the 30min doc about ebpf
* all key people are mentioned
-->

---
layout: fact
---

Let's get technical!

---
layout: image
image: /syscall-hook.png
backgroundSize: contain
---

<!--
* ebpf programs are event driven
* run when kernel passes hook points
* hook points are either predefined, or arbitrary function within linux kernel
-->

---
layout: image
image: /source-to-vm.svg
backgroundSize: 70%
---

<!--
* code is first compiled down to byte code
* when prog is first loaded, compiled to native code
* earlier versions interpreted instead
* bytecode consists of instructions acting on virtual registers
* designed to neatly map to common cpu archs
* virtual machine uses 10 general purpose 64 bit register
* registers are purely virtual, implemented in software
-->

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

<!--
* reg 0 holds return value
* reg 1- 5 used to pass args to functions
* reg 6-9 no special meaning
* reg 10 is used as read only stack frame pointer

* ebpf instructions are represented in the kernel as bpf_insn struct
-->

---
layout: full
---

<div class="full-center">
<div>
<div class="filepath">
<a href="https://elixir.bootlin.com/linux/v6.9.6/source/include/trace/events/sched.h">include/uapi/linux/bpf.h</a>
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

<!--
* instructions are 8 bytes long
* sometimes need more space, e.g. when setting reg to 64 bit value
* when loaded prog is internally represented by series of bpf_insns
-->

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

<!--
* quick sample of opcodes
* follow special encoding scheme we sadly will not elaborate
* checkout Instruction Set Architecture docs over at kernel docs
-->

---
layout: image
image: /bpf_isa_docs.svg
backgroundSize: 40%
---

<div style="display: flex; align-items: end; height: 100%; justify-content: center">
<span style="color: black; font-size: 2em;">
<a href="https://docs.kernel.org/bpf/standardization/instruction-set.html">
BPF Instruction Set Architecture Docs
</a>
</span>
</div>

---
layout: image
image: /map-architecture.png
backgroundSize: 70%
---

<!--
* To store state and share state, ebpf has maps
* maps = data structures
* can be accessed from ebpf + user space
* use cases: share events with user space, configure ebpf from user space, storing context from different progs to further enhance collected data
-->

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

<!--
* maps come in different types and shapes
* there are types for particular operations such as hash maps, LRU data stores, arrays
* some maps come in per cpu variants
* kernel allocates memory for maps per CPU
* useful since programs might run in parallel
* tail call maps special case
* tail calls required since max instruction limit per prog = 1million
-->

---
layout: fact
---

<span class="fact">

Instruction Limit of <span class="highlighted-element"> 1 Million </span> (Linux 6.0)

</span>

<!--
* tail calls work like execve
* replace context of program with a different one
-->

---
layout: image
image: /tailcall.png
backgroundSize: 70%
---

<!--
* even though stack frame is shared, vars cannot be accessed
* to share state => use maps
* as already mentioned, different prog types
-->

---
layout: full
---

<div class="full-center">
<div>
<div class="filepath">
<a href="https://elixir.bootlin.com/linux/v6.9.6/source/include/uapi/linux/bpf.h#L1024">include/uapi/linux/bpf.h</a>
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

<!--
* ~30 prog types
* nobody cares about me babbling on for days
* going to give you info on some common ones
-->

---
layout: section
---

# Tracepoint

<!--
* first up tracepoints
* marked locations within the kernel code
-->

---
layout: section
---

<div class="items">

* Marked location in the kernel

<v-clicks>

* Considered kernel API (stable)
* Not specific to eBPF
* 1400+ Tracepoints defined (Linux 5.15)

</v-clicks>

</div>

<!--
* considered kernel API = there are some stability guarantees
* not ebpf specific, uses perf subsystem for hooking
* perf subsystem is also used by systemtap/dtrace
* list of all available tracepoints: /sys/kernel/tracing/available_events
* ~1400+ in linux 5.15
-->

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
layout: full
---

<div class="full-center">
<div>
<div class="filepath">
<a href="https://elixir.bootlin.com/linux/v6.9.6/source/include/trace/events/sched.h#L400">include/trace/events/sched.h</a>
</div>

```c
TRACE_EVENT(sched_process_exec,
    TP_PROTO(struct task_struct *p, pid_t old_pid,
         struct linux_binprm *bprm),
    TP_ARGS(p, old_pid, bprm),
    TP_STRUCT__entry(
        __string(	filename,	bprm->filename	)
        __field(	pid_t,		pid		)
        __field(	pid_t,		old_pid		)
    ),
    TP_fast_assign(
        __assign_str(filename, bprm->filename);
        __entry->pid		= p->pid;
        __entry->old_pid	= old_pid;
    ),
    TP_printk("filename=%s pid=%d old_pid=%d", __get_str(filename),
          __entry->pid, __entry->old_pid)
);
```

</div>

</div>

---
layout: full
---

<div class="full-center">
<div>
<div class="filepath">
<a href="https://elixir.bootlin.com/linux/v6.8.6/source/fs/exec.c#L1814">fs/exec.c</a>
</div>

```c {11}
static int exec_binprm(struct linux_binprm *bprm) {
    pid_t old_pid, old_vpid;
    int ret, depth;
    /* Need to fetch pid before load_binary changes it */
    old_pid = current->pid;
    rcu_read_lock();
    old_vpid = task_pid_nr_ns(current, task_active_pid_ns(current->parent));
    rcu_read_unlock();
    // ...
    audit_bprm(bprm);
    trace_sched_process_exec(current, old_pid, bprm);
    ptrace_event(PTRACE_EVENT_EXEC, old_vpid);
    proc_exec_connector(current);
    return 0;
}
```

</div>

</div>

---
layout: section
---

# Kprobe/Kretprobe

<!--
* unlike tracepoints, can hook any function
-->

---
layout: section
---

<div class="items">

* Can hook <span class="highlighted-element">any</span> kernel function

<v-clicks>

* No stability guarantee (kernel functions can change)

</v-clicks>

</div>

<!--
* kretprobe -> hook exit, kprobe -> attach to any offset within function
* warning, not stable
* functions might get inlined/change signature
* might work fine on 5.15, but broken on 6.1
-->

---
layout: section
---

# LSM

<!--
* BPF_PROG_TYPE_LSM prog type
* LSM = Linux Security Modules
-->

---
layout: section
---

<div class="items">

* Linux Security Modules

<v-clicks>

* Return value controls how kernel behaves

</v-clicks>

</div>

<!--
* allow to decline certain actions such as syscalls to user
* program pretty much the same as e.g. tracepoints
* return value decides if an action is allowed or not
* return value != 0 == decline
-->

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

<!--
* allows filter/edit network packets on NIC
* as with LSM, return value decides what happens
* 5 different return codes
-->

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

<!--
* DROP will drop packet
* PASS will allow packet up the network stack
* prog has full access to complete packet
* is also free to modify it
* very useful for e.g. load balancers facebook katran
-->

---
layout: fact
---

sched-ext (Linux 6.11)

<!--
* as heard there are many prog types
* honorable mention: starting with 6.11 it is possible to write cpu schedulers in ebpf
* you cannot just call any kernel function from ebpf
* would couple prog to exact kernel version/hard to guarantee stability
* this is where helper functions come into play
-->

---
layout: section
---

# Helpers

---
layout: image
image: /helper.png
backgroundSize: 90%
---

<!--
* in a nutshell, helper allow you to retrieve data/interact with kernel
* helpers available are coupled to program type
* e.g. reading data directly, updating vlan info on network packet
* prog can call helper without need for FFI => no overhead
* are represented by bpf_func_proto struct
-->

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

<!--
* pointer to underlying implementation
* info on return type/argument types
-->

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

<!--
* here example
* interesting field gpl_only
* some helpers are only available to progs with gpl compatible license
* lets look into helper samples
-->

---
layout: section
---

```c
long bpf_probe_read_kernel(void *dst, u32 size, const void *unsafe_ptr)
```

<!--
* first up bpf_probe_read_kernel
* read any data from unsafe_ptr into dst
* means you can read any data you want
-->

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

<!--
* one downside: internal structs can change
* no type info at memory locations (we are in C land)
* you need to know how to interpret memory
* co-re leverages BTF
* adjusts offsets on the fly
* not going into more details
* next up bpf_map_lookup_elem
-->

---
layout: section
---

```c
void *bpf_map_lookup_elem(struct bpf_map *map, const void *key)
```

<!--
* allows to retrieve pointer to element stored for key
-->

---
layout: section
---

<div class="items">

* Read data from an eBPF map

<v-clicks>

* <mdi-warning class="text-red-400"/> Pointer to memory region is returned

</v-clicks>

</div>

<!--
* if element not found NULL is returned
* since pointer to memory in map, any modifications also modify value in map
-->

---
layout: section
---

```c
long bpf_map_update_elem(struct bpf_map *map, const void *key,
                            const void *value, u64 flags)
```

<!--
* bpf_map_update_elem allows to add keys to map
* special behavior controlled by value passed to flag
-->

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

<!--
* NO_EXIST fails on existing => insert
* EXISTS fails on non existing => update
* ANY doesn't care
-->

---
layout: section
---

# Bytecode in Action

<!--
* with helpers out of the way, let's dig deeper and see bytecode in action
-->

---
layout: full
---

<div class="full-center">

```c {all|4|6|8-9|11-13|14|all}{lines:true}
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "GPL";

SEC("tracepoint/sched_process_fork")
int hello(void *ctx) {
    __u64 val = bpf_get_current_pid_tgid();
    __u32 pid = val >> 32;

    if (pid == 32) {
        bpf_printk("fork detected");
    }
    return 0;
}
```

</div>

<!--
* todays sample is a simple tracepoint program
* will print trace log if PID 13 is forked
* we are going to compile it to bytecode and have a look
* first lets understand what c code is doing
* kick it off with setting license to GPL, good reason for this, as we want to use helpers
* the strange SEC macro is instructing the compiler to put generated byte code under ELF section specified
* not going into more details about elf
* might be confusing why we right shift result of helper
* in linux threads have PIDs, we do not care about thread PIDs, we want all forks of process 13. this is represented as the thread group id, which is encoded in the higher 32 bits, hence right shift
* compare pid to 13 and if matches print message with bpf_prinkt
* last return 0
-->

---
layout: full
---

<div class="full-center">

```c {all}
#define bpf_printk(fmt, ...)				\
({							\
    char ____fmt[] = fmt;				\
    bpf_trace_printk(____fmt, sizeof(____fmt),	\
             ##__VA_ARGS__);		\
})
```

</div>

<!--
* quick note about bpf_printk, it is defined as a macro
* this will be important when looking at bytecode
* it allocates variable for format we pass to it
-->

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

<!--
* we compile the binary like this
-->

---
layout: full
---

<div class="full-center">

```sh
llvm-objdump-14 hello.bpf.o -d
```

</div>

<!--
* we call llvm-objdump to get bytecode
* behold the byte code
-->

---
layout: full
---

<div class="full-center code-small-font">

```plain {all|4}{lines:true}
hello.bpf.o:    file format elf64-bpf
Disassembly of section tracepoint/sched_process_fork:
0000000000000000 <hello>:
       0:       85 00 00 00 0e 00 00 00 call 14
       1:       18 01 00 00 00 00 00 00 00 00 00 00 ff ff ff ff r1 = -4294967296 ll
       3:       5f 10 00 00 00 00 00 00 r0 &= r1
       4:       18 01 00 00 00 00 00 00 00 00 00 00 0d 00 00 00 r1 = 55834574848 ll
       6:       5d 10 0b 00 00 00 00 00 if r0 != r1 goto +11 <LBB0_2>
       7:       b7 01 00 00 64 00 00 00 r1 = 100
       8:       6b 1a fc ff 00 00 00 00 *(u16 *)(r10 - 4) = r1
       9:       b7 01 00 00 65 63 74 65 r1 = 1702126437
      10:       63 1a f8 ff 00 00 00 00 *(u32 *)(r10 - 8) = r1
      11:       18 01 00 00 66 6f 72 6b 00 00 00 00 20 64 65 74 r1 = 8387219971451809638 ll
      13:       7b 1a f0 ff 00 00 00 00 *(u64 *)(r10 - 16) = r1
      14:       bf a1 00 00 00 00 00 00 r1 = r10
      15:       07 01 00 00 f0 ff ff ff r1 += -16
      16:       b7 02 00 00 0e 00 00 00 r2 = 14
      17:       85 00 00 00 06 00 00 00 call 6
0000000000000090 <LBB0_2>:
      18:       b7 00 00 00 00 00 00 00 r0 = 0
      19:       95 00 00 00 00 00 00 00 exit
```

</div>

<!--
* let's go over it line by line
* first we call helper 14
* to figure out what helper 14 is, we need to check huge macro table in bpf header file
-->

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

<!--
* it is defining all helper fucntions
* fairly readable, first param of FN will be name, second number
* we number 14 maps to get_current_pid_tgid
-->

---
layout: full
---

<div class="full-center code-small-font">

```plain {5|6|5}{lines:true}
hello.bpf.o:    file format elf64-bpf
Disassembly of section tracepoint/sched_process_fork:
0000000000000000 <hello>:
       0:       85 00 00 00 0e 00 00 00 call 14
       1:       18 01 00 00 00 00 00 00 00 00 00 00 ff ff ff ff r1 = -4294967296 ll
       3:       5f 10 00 00 00 00 00 00 r0 &= r1
       4:       18 01 00 00 00 00 00 00 00 00 00 00 0d 00 00 00 r1 = 55834574848 ll
       6:       5d 10 0b 00 00 00 00 00 if r0 != r1 goto +11 <LBB0_2>
       7:       b7 01 00 00 64 00 00 00 r1 = 100
       8:       6b 1a fc ff 00 00 00 00 *(u16 *)(r10 - 4) = r1
       9:       b7 01 00 00 65 63 74 65 r1 = 1702126437
      10:       63 1a f8 ff 00 00 00 00 *(u32 *)(r10 - 8) = r1
      11:       18 01 00 00 66 6f 72 6b 00 00 00 00 20 64 65 74 r1 = 8387219971451809638 ll
      13:       7b 1a f0 ff 00 00 00 00 *(u64 *)(r10 - 16) = r1
      14:       bf a1 00 00 00 00 00 00 r1 = r10
      15:       07 01 00 00 f0 ff ff ff r1 += -16
      16:       b7 02 00 00 0e 00 00 00 r2 = 14
      17:       85 00 00 00 06 00 00 00 call 6
0000000000000090 <LBB0_2>:
      18:       b7 00 00 00 00 00 00 00 r0 = 0
      19:       95 00 00 00 00 00 00 00 exit
```

</div>

<!--
* R1 is set to bit mask of upper 32 bits to be set
* bit mask used to clear lower value stored in R0
* as we learned before R0 stores the return values of function calls, in our case the call to bpf_get_current_pid_tgid
* it might be confusing, as it looks lower 32 bit are set to high
* this is caused by my architecture using big endian
-->

---
layout: image
image: /endianess.png
backgroundSize: 80%
---

<div class="attribution">
    By <a href="//commons.wikimedia.org/wiki/User:Aeroid" title="User:Aeroid">Aeroid</a> - <span class="int-own-work" lang="en">Own work</span>, <a href="https://creativecommons.org/licenses/by-sa/4.0" title="Creative Commons Attribution-Share Alike 4.0">CC BY-SA 4.0</a>, <a href="https://commons.wikimedia.org/w/index.php?curid=137790829">Link</a>
</div>

<!--
* left most bit on each line => least significant
-->

---
layout: full
---

<div class="full-center code-small-font">

```plain {7|8|9-18|9-14}{lines:true}
hello.bpf.o:    file format elf64-bpf
Disassembly of section tracepoint/sched_process_fork:
0000000000000000 <hello>:
       0:       85 00 00 00 0e 00 00 00 call 14
       1:       18 01 00 00 00 00 00 00 00 00 00 00 ff ff ff ff r1 = -4294967296 ll
       3:       5f 10 00 00 00 00 00 00 r0 &= r1
       4:       18 01 00 00 00 00 00 00 00 00 00 00 0d 00 00 00 r1 = 55834574848 ll
       6:       5d 10 0b 00 00 00 00 00 if r0 != r1 goto +11 <LBB0_2>
       7:       b7 01 00 00 64 00 00 00 r1 = 100
       8:       6b 1a fc ff 00 00 00 00 *(u16 *)(r10 - 4) = r1
       9:       b7 01 00 00 65 63 74 65 r1 = 1702126437
      10:       63 1a f8 ff 00 00 00 00 *(u32 *)(r10 - 8) = r1
      11:       18 01 00 00 66 6f 72 6b 00 00 00 00 20 64 65 74 r1 = 8387219971451809638 ll
      13:       7b 1a f0 ff 00 00 00 00 *(u64 *)(r10 - 16) = r1
      14:       bf a1 00 00 00 00 00 00 r1 = r10
      15:       07 01 00 00 f0 ff ff ff r1 += -16
      16:       b7 02 00 00 0e 00 00 00 r2 = 14
      17:       85 00 00 00 06 00 00 00 call 6
0000000000000090 <LBB0_2>:
      18:       b7 00 00 00 00 00 00 00 r0 = 0
      19:       95 00 00 00 00 00 00 00 exit
```

</div>

<!--
* R1 is set to funny value, on closer look it is just number 13 in big endian notation, left shifted by 32
* all this is done to compare R0 to R1
* if do not match, jump over the next 11 instructions
* otherwise something strange looking is going on
* in reality those are simply stack allocations, since R10 is stack pointer
* the values assigned to stack variables are our ASCII encoded characters
-->

---
layout: full
---

<div class="full-center code-small-font">

```plain
66 6f 72 6b 20 64 65 74 65 63 74 65 64 00 00 00
f  o  r  k     d  e  t  e  c  t  e  d
```

</div>

---
layout: full
---

<div class="full-center code-small-font">
<v-switch>
<template #0>

```plain
11:       18 01 00 00 66 6f 72 6b 00 00 00 00 20 64 65 74 r1 = 8387219971451809638 ll
```

</template>
<template #1>

```plain
11:       18 01 00 00 66 6f 72 6b 00 00 00 00 20 64 65 74 r1 = 8387219971451809638 ll
          op s  d  of --- imm --- op s  d  of --- imm ---

op  = opcode
s   = source
d   = destination
of  = offset
imm = immediate
```

</template>
</v-switch>

</div>

<!--
* in case you were wondering what those zeroes in the middle of the load operation, caused by it being a wide instruction
* meaning each field, besides immediate value is set to zero
-->

---
layout: full
---

<div class="full-center code-small-font">

```plain {15-16}{lines:true}
hello.bpf.o:    file format elf64-bpf
Disassembly of section tracepoint/sched_process_fork:
0000000000000000 <hello>:
       0:       85 00 00 00 0e 00 00 00 call 14
       1:       18 01 00 00 00 00 00 00 00 00 00 00 ff ff ff ff r1 = -4294967296 ll
       3:       5f 10 00 00 00 00 00 00 r0 &= r1
       4:       18 01 00 00 00 00 00 00 00 00 00 00 0d 00 00 00 r1 = 55834574848 ll
       6:       5d 10 0b 00 00 00 00 00 if r0 != r1 goto +11 <LBB0_2>
       7:       b7 01 00 00 64 00 00 00 r1 = 100
       8:       6b 1a fc ff 00 00 00 00 *(u16 *)(r10 - 4) = r1
       9:       b7 01 00 00 65 63 74 65 r1 = 1702126437
      10:       63 1a f8 ff 00 00 00 00 *(u32 *)(r10 - 8) = r1
      11:       18 01 00 00 66 6f 72 6b 00 00 00 00 20 64 65 74 r1 = 8387219971451809638 ll
      13:       7b 1a f0 ff 00 00 00 00 *(u64 *)(r10 - 16) = r1
      14:       bf a1 00 00 00 00 00 00 r1 = r10
      15:       07 01 00 00 f0 ff ff ff r1 += -16
      16:       b7 02 00 00 0e 00 00 00 r2 = 14
      17:       85 00 00 00 06 00 00 00 call 6
0000000000000090 <LBB0_2>:
      18:       b7 00 00 00 00 00 00 00 r0 = 0
      19:       95 00 00 00 00 00 00 00 exit
```

</div>

<!--
* more fun is happening
* R1 is set to R10
* R1 subtracts -16
* this points to the start of our string
* why 16 though, this is caused by padding added to the end of the string
-->

---
layout: full
---

<div class="full-center code-small-font">

```plain
66 6f 72 6b 20 64 65 74 65 63 74 65 64 00 00 00
f  o  r  k     d  e  t  e  c  t  e  d
                                       |   |_|
                        \0 of string ---    |
                                  padding ---
```

</div>

<!--
* last two zeroes are padding
* as c strings are terminated with \0, the zero before the padding is part of the string
-->

---
layout: full
---

<div class="full-center code-small-font">

```plain {17|18|20-21}{lines:true}
hello.bpf.o:    file format elf64-bpf
Disassembly of section tracepoint/sched_process_fork:
0000000000000000 <hello>:
       0:       85 00 00 00 0e 00 00 00 call 14
       1:       18 01 00 00 00 00 00 00 00 00 00 00 ff ff ff ff r1 = -4294967296 ll
       3:       5f 10 00 00 00 00 00 00 r0 &= r1
       4:       18 01 00 00 00 00 00 00 00 00 00 00 0d 00 00 00 r1 = 55834574848 ll
       6:       5d 10 0b 00 00 00 00 00 if r0 != r1 goto +11 <LBB0_2>
       7:       b7 01 00 00 64 00 00 00 r1 = 100
       8:       6b 1a fc ff 00 00 00 00 *(u16 *)(r10 - 4) = r1
       9:       b7 01 00 00 65 63 74 65 r1 = 1702126437
      10:       63 1a f8 ff 00 00 00 00 *(u32 *)(r10 - 8) = r1
      11:       18 01 00 00 66 6f 72 6b 00 00 00 00 20 64 65 74 r1 = 8387219971451809638 ll
      13:       7b 1a f0 ff 00 00 00 00 *(u64 *)(r10 - 16) = r1
      14:       bf a1 00 00 00 00 00 00 r1 = r10
      15:       07 01 00 00 f0 ff ff ff r1 += -16
      16:       b7 02 00 00 0e 00 00 00 r2 = 14
      17:       85 00 00 00 06 00 00 00 call 6
0000000000000090 <LBB0_2>:
      18:       b7 00 00 00 00 00 00 00 r0 = 0
      19:       95 00 00 00 00 00 00 00 exit
```

</div>

<!--
* R2 is set to 14, which is the length of the string we want to print
* calling helper 6, which is bpf_trace_printk
* in reality we are setting up the parameters that are passed to bpf_trace_printk
* first parameter is pointer to string, second is length
* last but not least, return value is set to 0 through R0
* exit is called
* thats it! byte code not to hard to read
* next up, we have component that keeps ebpf safe
-->

---
layout: section
---

# Verifier

<!--
* each time you try to load ebpf into kernel, verifier checks if prog is safe and doesn't crash the kernel
* one of the pillars of ebpf
* to achieve this, each ebpf prog goes through formal verification
-->

---
layout: image
image: /verifier.png
backgroundSize: 90%
---

<!--
* one important thing: verifier works on bytecode, meaning it has no notion of your C/Rust/Zig source code
* this can lead to funny hard to understand verifier errors, as compilers shuffle things around
* e.g. verifier rejects dead code, but compiler will probably purge dead code
* byte code != source code
* verifier works in two stages
-->

---
layout: section
---

# Stage 1

<!--
* turns the byte code into directed acyclic graph
-->

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

<!--
* perform control flow validations, such as disallowing unbounded loops
* you heard it right, unbounded loops are not allowed
* verifier also checks that all instructions are reachable
-->

---
layout: section
---

# Stage 2

<!--
* verifier steps down all possible paths starting from first instruction
-->

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

<!--
* simulates each instruction and observes state changes
* this is where verifier magic comes in, checking each instruction is expensive
* sadly not going into more details, more than enough for its own talk
* checkout verifier docs, there are also excellent videos from last ebpf summit
-->

---
layout: image
image: /verifier-docs.svg
backgroundSize: 40%
---

<div style="display: flex; align-items: end; height: 100%; justify-content: center">
<span style="color: black; font-size: 2em;">
<a href="https://www.kernel.org/doc/html/latest/bpf/verifier.html">
eBPF verifier documentation
</a>
</span>
</div>

---
layout: fact
---

<e>Verifier is reason for program instruction limit</e>

<!--
* reason why unbounded loops are not allowed, verifier needs to ensure program halts at one point
* same for instruction limit, as infinite instructions, would take infinit time to check
-->

---
layout: fact
---

Learn to read verifier errors!

<!--
* word of advise: get familiar with verifier error messages
* sometimes straightforward
-->

---
layout: full
---

<div class="full-center">

```plain
unreachable insn 1
```

</div>

<!--
* sometimes quite confusing and hard to read
-->

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

<!--
* verifier can sometimes thing value could be NULL even though it was checked for NULL
* in such cases, learn how to dump ebpf bytecode and read it
-->

---
layout: section
---

# eBPF in the wild

<!--
* with verifier out of the way, do 10000 feet look at applications leveraging power of ebpf
-->

---
layout: section
---

# Katran

<!--
* first up katran
-->

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

<!--
* central component of facebooks network infrastructure
* achieving high performance through power of XDP, to forward packets right on network interface card, before it hits the kernels network stack
* makes it incredibly fast
* nice side effect: low CPU usage, meaning other apps can also run on same server
* all thanks to ebpf
-->

---
layout: section
---

# Cilium

<!--
* when speaking about ebpf and networking, cilium needs to get mentioned
-->

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

<!--
* in case you do not know it: cilium = networking/observability/security solution for kubernetes cluster
* whole dataplane base don ebpf
* routes traffic through xdp, replacing complicated iptable chains for routing
* can even run in mode replacing kube-proxy

* ebpf is not just for networking though
* popular use case for tech is also in monitoring
* big players in the industry are using it as well
* any dynatracers here? if yes, cover your eyes and ears, because we are going to talk about the datadog agent
-->

---
layout: section
---

# Datadog Agent

<!--
* source code for agent is up on github
* poking around, you see it uses ebpf across various places
-->

---
layout: section
---

<div class="items">

* Tracing network packets

<v-clicks>

* Killing processes violating policies

</v-clicks>

</div>

<!--
* from hooking network related kernel methods to trace network packets
* to hooking syscalls and killing processes that violates policies
* when speaking of security focused products in the cloud native space, you need to mention tetragon
-->

---
layout: section
---

# Tetragon

<!--
* from the same folks as cilium
* allows you to hook any kernel function/tracepoint by simply creating a policy via a custom resource object in kubernetes cluster
-->

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

<!--
* policies pack a punch, as they can kill processes in flight if they match defined policy
* much like. datadog agent, but without paying a small fortune for a monitoring product
* as you can see, ebpf is used across the industry
* lets dig little deeper
* next section we are going to look at concrete detection implementation in cast.ai kvisor
-->

---
layout: section
---

# CAST.AI kvisor

<!--

-->

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

<!--
* in case you do not know cast.ai, main product helps you getting more bang for your buck by optimising your k8s cluster to the max, by automatically adjusting the resource requirements of your deployments and accordingly scale your node pools.
* not too long ago ventured into the space of cloud native security, leveraging the power of ebpf
-->

---
layout: image
image: /kvisor.png
backgroundSize: 90%
---

<!--
* resulting in kvisor
* not too long ago, discussions with colleagues came up with the nice idea trying to detect container drift, by leveraging the way container are implemented
-->

---
layout: section
---

# Detecting container drift with eBPF

<!--
* approach is not completely novel, as falco is doing something similar
-->

---
layout: fact
---

Kudos to Falco!

<!--
* first, lets have a quick overview of kvisors architecture
-->

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

<!--
* the code we are going to look at lives in the kernel space, as ebpf tracepoint program
* ebpf events are emitted to perf buffer, consumed by userspace
* ingested into signature engine, to detect anomalies in high volume events too expensive to export
* signature findings and some raw events are exported to the cast ai backend, where run through anomaly detection engine
* if you want more details, feel free to approach me afterwards/consider applying to one of the open jobs
-->

---
layout: image
image: /detecting-containerdrift.svg
backgroundSize: contain
---

<!--
* idea is containers are implemented on top of overlayfs
* overlayfs points to bunch of dirs called lower layers, that are read only and reference image layers
* there is also upper layer, where all file modifications go
* to understand when a file is in the upper layer, we need to first understand what an inode is
-->

---
layout: section
---

# Inode

<!--
* by definition inode is an index node, that acts a a unique identifier for specific piece of metadata on a give fs
-->

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
<a href="https://elixir.bootlin.com/linux/v6.9.6/source/include/linux/fs.h#L632">include/linux/fs.h</a>
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
<a href="https://elixir.bootlin.com/linux/v6.9.6/source/fs/overlayfs/ovl_entry.h#L162">fs/overlayfs/ovl_entry.h</a>
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

<!--
* in case of overlayfs, it adds additional details to inodes it creates
* you cannot simply extend kernel data structures (unless they pack a void pointer)
* overlayfs goes around this by simply embedding indoe struct and returning pointer to field
* meaning we can get the container struct by simple pointer magic
* this is what we are doing in ebpf code
* instead of getting the container, we simply add the size of inode to pointer, to get the next field, which is the dentry we are interested in
-->

---
layout: section
---

<div class="items">

* `ovl_inode` has `__upperdentry != NULL`

<v-clicks>

* `__upperdentry->d_fsdata` has `OVL__UPPER_ALIAS` set

</v-clicks>

</div>

<!--
* to detect if inode is in upper layer, we need to test if ovl_inode has __uperdentry pointing to not NULL and has OVL_E_UPPER_ALIAS flag set
* if flag set, binary was not present in original layer, as flag is set for files that are either copied or written
* flag also filters out symlinks
-->

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

<!--
* in practice we are going to peek into small 7k file tracee.bpf.c
* yeah kvisor is fork of aquas tracee
* there exists function tracepoint__sched__sched_process_exec
* hooks sched_process_exe tracepoint, gets called for each process is launched
* we skip over most parts of function, if you want to know more, reach out to me
-->

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

<!--
* focus on part close to the end
* we call function called get_exe_upper_layer
* is doing exactly what we described
* function takes dentry + superblock
-->

---
layout: full
---

<div class="full-center">
<div>
<div class="filepath">
<a href="https://elixir.bootlin.com/linux/v6.9.6/source/include/linux/fs.h#L1207">include/linux/fs.h</a>
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

<!--
* superblock is part of inode containing meta info
* we only care about s_magic field
* field tells us which FS is used
-->

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

<!--
* dentry acts as a way to translate between inodes and names
-->

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

<!--
* we get both structs from linux_binprm struct, that is passed to function as second argument
* in a nutshell, struct contains all data required to execute a program, such as virtual memory area, filename, FDs, arguments and so on
-->

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

<!--
* long story short, to know if file is in upper layer, we probe magic field to match overlayfs, use pointer magic to extract __upperdentry field
* afterwards we check if __upperdentry is non NULL and has OVL_E_UPPER_ALIAS flag set
-->

---
layout: fact
---

And that is about it!

<!--
* congrats, we just implemented basic container drift detection
-->

---
layout: section
---

<div class="items">

* eBPF is to the kernel what JS is to the browser

<v-clicks>

* Wide array of use-cases
    * Monitoring (tracepoints)
    * Networking (XDP)
    * Security (LSM)
* More exiting things on the horizon
    * E.g. sched-ext

</v-clicks>

</div>

<!--
* recap
* what js is to the browser to the kernel
* due to flexibility can be used for large array of use-cases: such as tracing, networking, security
* more things to come: such as sched-ext
* if you interested in ebpf, check out source code for tool such as tracee
* also consider joining the ebpf channel on the cilium slack server
* quite a lot of interesting discussions
-->

---
layout: fact
---

Check out <a href="https://patrickpichler.dev">patrickpichler.dev</a>

<!--
* also check out my personal blog
* still quite empty
* BUT THE TIME IS NOW
-->

---
layout: image
image: /blog.png
backgroundSize: contain
---

<!--
* Also if you like to talk more about ebpf or any other tech topic, feel free to reach out to me
-->

---
layout: image
image: /cast-hiring.svg
backgroundSize: 40%
---

<div style="display: flex; align-items: end; height: 100%; justify-content: center">
<span style="color: black; font-size: 2em;">
<a href="https://castai.teamtailor.com/jobs/4480547-senior-software-engineer-security-product-team">
Senior Software Engineer - Security Product Team
</a>
</span>
</div>

<!--
* in case you are interested in ebpf and kubernetes security + want to do it for a living, checkout cast.ai career page
* hiring for the security team, which i am also part of
-->

---
layout: fact
---

Thanks!
