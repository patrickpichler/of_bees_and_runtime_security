Hello there!

Welcome everyone! Let's get started!

First things first, my name is Patrick Pichler and I am currently employed at CAST.AI as a senior
software engineer, working on a Kubernetes security product.

Originally I started my career as a Java Software Developer, but everything changed when I stumbled
upon Linux and the cloud. This definitely transformed me into a full-on Linux nerd. Do not question
why I am currently on a Macbook though.

With this out of the way, who of you has heard about eBPF before? Has anyone of you consciously used
eBPF?

Nice! Now, the main goal of this talk is to give you a good idea, why eBPF is considered this next
level technology and what makes it so powerful. To achieve this, we are going to dive deep into the
low level details of eBPF and figure out how it is actually working. We are also going to checkout
how it is used in today's Cloud native landscape.

<!-- show https://ebpf.io/static/e293240ecccb9d506587571007c36739/f2674/overview.png -->

For those of you who do not know eBPF, it can be compared to what JavaScript is for the Browser,
but for the Linux kernel. Sounds strange, but is incredibly useful. Before eBPF it was incredibly
hard to extend the Linux kernel. eBPF changed this, by offering a secure way of doing exactly this.
We are going to learn about the exact details a bit later. This power is used today in a lot of
different tools and products across various use cases. Sounds not only amazing, but it is amazing.
As you can see in the overview, there are quite a few components on various layers involved. To give
you a better feel about eBPF, we are going to have a closer look at the lower levels.

<!-- History of eBPF -->

But fist, let me give you a quick history lesson.

I will not turn this into lengthy lecture. All I am going to tell you is, that eBPF was introduced
into kernel version 3.18 back in 2014, after a lot of hard work of its original creator Alexei
Strarovoitov. Even though it original it was an abbreviation for `extended Berkley Package Filters`,
it nowadays has little to do with `Berkley Package Filters` and should be thought of as its
own term. The original use case was focused around network virtualization and software defined
networking, but has since then evolved to cater other use cases as well.

If you want to learn more about the origin story of eBPF, there is a whole 30-minutes documentary
including all the key people. It is pretty interesting to watch.

Now lets get technical!

<!-- overview of how eBPF is used -->

eBPF programs are event driven and are run, when the kernel passes certain hook points. These hook
points can be predefined or, as we later hear, just arbitrary functions within the Linux kernel.

<!-- https://ebpf.io/static/b4f7d64d4d04806a1de60126926d5f3a/12151/syscall-hook.png -->

<!-- eBPF Virtual machine -->

The code defined for the hook is first compiled down to eBPF bytecode. When an the program is
now first loaded, the Virtual Machine will compile down the byte code to native machine code.
Earlier versions of the eBPF VM interpreted the bytecode instead. The bytecode consists of a
set of instructions, which act on virtual registers. It is designed to map neatly to common CPU
architectures, greatly reducing the complexity to compile to native code.

The virtual machine uses 10 general-purpose 64-bit registers, numbered 0 to 9. It is important
to note, that those registers are purely virtual and implemented in software. REG-0 holds the
return value of a function. REG-1 to REG-5 are used to pass in arguments to functions called in the
program. REG-6 to REG-9 do not have any other special meaning. There is also a special Register 10
which is used as a read-only stack frame pointer.

eBPF instructions are represented inside the kernel via the `bpf_insn` struct, defined in the BPF
header file. It looks like the following

```c
struct bpf_insn {
	__u8	code;		/* opcode */
	__u8	dst_reg:4;	/* dest register */
	__u8	src_reg:4;	/* source register */
	__s16	off;		/* signed offset */
	__s32	imm;		/* signed immediate constant */
};
```

The `bpf_insn` structure is 8 bytes long. Sometimes one needs more space than those 8 bytes,
for example when trying to set a register to a 64-bit value. This is where the so called `wide
instruction encoding` comes into play, extending a single instruction to 16 bytes instead of 8. When
your eBPF program is loaded into the kernel, the byte code gets internally represented by a series
of these `bpf_insn` structs.

Here we can see some examples of this op codes. The opcodes follow a special encoding scheme, that I
sadly will not elaborate more on in this talk. If you like to learn more, checkout the Instruction
Set Architecture documentation over at the kernel docs.

In order to store state and share data, eBPF introduced the concept of maps. Maps are data
structures, which can be access from both eBPF and user space. They also allow for data being shared
across different eBPF programs. Typical use cases of maps include sharing events such as certain
syscalls being triggered with user space, writing configuration from the user space program to eBPF
or storing context from different programs to further enhance collected data.

Maps come in different types and shapes. There are map types for particular operations, such as
first-in-first-out queues, LRU data storage or simple arrays. Some map types offer a per-CPU
variant, which instructs the kernel to allocate different blocks of memory for each CPU core's
version of that map. This comes in handy, since different eBPF programs can in parallel.

Now TailCall maps are pretty interesting. One thing to note about eBPF is, that programs do have an
upper instruction limit of 1 Million as per Linux 6.0. What TailCalls allow you, can be compared to the
`execve()` syscall. When called, it is going to replace the context of the current running program
with a different one. Even though the same stack frame is shared, you can not access any variables.
Thus, to share state between tailcalled programs, you have to use a map.

<!-- eBPF program types -->

As already mentioned before, there are a few different places, we can hook our eBPF programs into
the kernel. There are currently around 30 program types listed in the kernels BPF header file.

Since probably nobody is interested in seeing me babble around for the next 2 days about different
eBPF program types, we are of course not going to go through the whole list, but instead just focus
on some pretty common ones.

<!-- eBPF program types important things to consider -->

First up, we have Tracepoints. A Tracepoint is a marked location in the kernel code. They are
considered an API of the kernel and hence have some stability guarantees around them, meaning
that they will not randomly change from one kernel version to the next. Tracepoints are by no
mean eBPF specific. They use the so called perf subsystem for hooking, that is also used by
tools such as `SystemTap` or `Dtrace`. You can find a list of all available Tracepoints in
the `/sys/kernel/traceing/available_events` file. As with Linux 5.15 there are more than 1400
Tracepoints defined in that list. Here is a short excerpt

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

Next, there are `Kprobe` and `Kretprobe`. Unlike Tracepoints, you can hook pretty much **any**
function within the kernel. While `Kretprobe`, as the name imply, hook the exit of the function,
`Kprobe` can attach to any instruction at a specific offset within the function. A big word of
warning though, unlike Tracepoints, there are no safety guarantees that an internal kernel function
will not change it signature, or simply being inlined between kernel versions. This means that while
your program works fine on lets say kernel 5.15, it might be completely broken on 6.4.

There also exists the possibility to hook up eBPF programs to LSM hooks. This can be achieved via
the `BPF_PROG_TYPE_LSM` program type. LSM stands for Linux Security Modules and allow you to decline
certain actions such as syscalls to users. Overall the programs do not differ too much from lets
say Tracepoints. One very important difference though is that the return value of the eBPF program
controls, how the kernel behaves. If the program returns a value not equal to zero, the security
check is seen as not passed, meaning the kernel will not proceed with whatever operation it was ask
to complete.

Last, but not least, we have the XDP programs. XDP, or Express Data Path programs, allow you to
filter and edit network packets directly on the NIC. Here, as with the LSM program types, the return
value of the program is used to decide what to do with a given packet. There are 5 different return
codes, namely `XDP_ABORTED`, `XDB_DROP`, `XDB_PASS`, `XDB_TX` and `XDB_REDIRECT`. We will not go
into details what exactly each one of those does, but `XDB_DROP` will drop the given packet and
`XDB_PASS` will allow the packet to continue up the network stack. The program has full access to
the complete packet and is free to modify it, which makes this program type very useful for e.g.
load balancers, such as Facebook's Katran.

Of course there are many more program types available, but this should give you an good enough
overview for now. Here is one honorable and fascinating mention though. Starting with kernel version
6.11, it will be possible to write custom CPU schedulers using eBPF. How cool is that?

<!-- Helper Functions -->

You cannot just call any kernel function from an eBPF program, as this would not only couple your
program to an exact kernel version, but would also be making hard to guarantee compatibility and
stability of your program. To work around this eBPF has the notion of so called helper functions.

In a nutshell, eBPF helper functions allow you to retrieve data and interact with the kernel. The
helpers you have at your disposal are coupled to the program type that you are using. There is a
wide array of these helper functions, offering functionality from reading data directly from
memory to updating the VLAN information on an network packet. eBPF programs can directly call these
helper functions without the need of a foreign function interface, meaning that there is no
overhead by calling these.

Helper functions are represented as `bpf_func_proto` struct values in the kernel. Each helper that
is available in your program has a corresponding `bpf_func_proto` definition.

The struct roughly looks like this

```c
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

As you can see, the struct has a function pointer, that will point to the underlying function, as
well as some info about the return type, as well as the argument types. Those are used by the
eBPF verifier to ensure program safety. We will learn more about the verifier a bit later.

Here we can see it in action:

```c
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

One interesting field on this struct is `gpl_only`. A large amount of helpers defined in the Linux
kernel expect your program to be released under a `GPL` compatible license, or the kernel refuses to
accept your eBPF program that uses them.

Lets take a few minutes to have a look at some commonly used helpers.

We start of with `long bpf_probe_read_kernel(void *dst, u32 size, const void *unsafe_ptr)`. This
helper allows us to safely read data from the `unsafe_ptr` kernel space address and store them into
`dst`. This means you can pretty much read any kernel data you want. The only downside of this,
you need to know how the memory layout of the kernel looks like. It is not uncommon for internal
kernel structs to change from one version to the other. Given that we are in C land, there is no
type information attached to any of those memory addresses. We are literally interpreting a chunk
of memory as a certain type. To not run into this issue, there exists so called CO-RE, or compile
once - run everywhere, which leverages the BPF type format to adjust the offsets we want to read on
the fly to match the underlying kernel structure. I will not go into more detail here, but it is
definitely worth checking out.

Next up, we have the `void *bpf_map_lookup_elem(struct bpf_map *map, const void *key)` helper. It
allows us to retrieve a pointer to the element stored for `key` in the map, or `NULL` if it does not
exists. Since it returns a pointer, any modification to the memory region, will also update the map,
so be careful.

To add keys to the map, we can use the `long bpf_map_update_elem(struct bpf_map *map, const void
*key, const void *value, u64 flags)` helper. You can tweak how the method should behave by passing
in one of the following values to flag: `BPF_NOEXIST`, `BPF_EXIST`, `BPF_ANY`. The names are pretty
self explanatory if you ask me. `BPF_NOEXIST` will fail if the given key already exists, meaning it
is an insert only. `BPF_EXISTS`, surprise surprise, will fail if the key does not exist, making it
an update. Last, but not least `BPF_ANY` doesn't care and will happily update or insert the given
value.

<!-- eBPF bytecode in action -->
With helpers out of the way, let's dig deeper and see the eBPF byte code in action.

Today's sample is a simple tracepoint program, that will print a message to the trace log, if
the process with PID `13` is forked. We are going to compile the program and inspect the resulting
bytecode, but first lets understand what the C code is doing.

```c
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "GPL";

SEC("tracepoint/sched_process_fork")
int hello(void *ctx) {
    __u64 val = bpf_get_current_pid_tgid();
    __u32 pid = val >> 32;

    if (pid == 13) {
        bpf_printk("fork detected");
    }
    return 0;
}
```

We kick it off, by setting the `LICENSE` constant to `GPL`. There is a good reason for that, as we
have learned while looking at helpers, as some of them only work with `GPL` licensing. You might
also be wondering what exactly these `SEC` things are doing. It is actually quite easy, as it just
instructs the compiler to put the resulting code under the section specified as the string passed to
the macro. So the `LICENSE` constant goes into the `license` section and the byte code for `hello`
goes under the `tracepoint/sched_process_fork` section of the resulting ELF binary. If you want
to learn more about this, read up on ELF sections, as I am not going into any more details about
it.

The first bit of logic gets the current PID/TGID via the `bpf_get_current_pid_tgid` helper. It might
be a bit confusing, why we need to right shift the resulting value by 32 bits. Now, in Linux threads
also get PIDs. As we are not care about individual threads, but only for the process, we need to
retrieve a so called thread group id, which is the PID of the process. It is encoded into the higher
32 bits of the resulting number, hence the right shift. Next up, we simply compare the PID to `13`
and if it matches, we print a message with `bpf_printk`.

One note: `bpf_prinkt` is not a function call, but instead a macro. This will be important, when we
look at the generated byte code, as you can see, it allocates a variable for the format we pass to
it on the stack.
```c
#define bpf_printk(fmt, ...)				\
({							\
	char ____fmt[] = fmt;				\
	bpf_trace_printk(____fmt, sizeof(____fmt),	\
			 ##__VA_ARGS__);		\
})
```

Given you have all the required dependencies setup, we can compile the above code into eBPF byte
code using the following command

```sh
clang \
    -target bpf \
    -I/usr/include/aarch64-linux-gnu \
    -g \
    -O2 -o hello.bpf.o -c hello.bpf.c
```

This will leave us with a `hello.bpf.o` file. To look at the bytecode we can call `llvm-objdump`
with the following command

```sh
llvm-objdump-14 hello.bpf.o -d
```

Behold the eBPF byte code

```
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

Lets go over it line by line.

The first instructions is calling helper number `14`. To know what numbers translate to what helper
functions, checkout this huge macro table defined in the bpf header file. It is defining all
possible helper functions, but it should be fairly readable, since the first parameter of `FN` will
be the name and the second the number we are interested in. Here we see that helper number `14`
translate to `bpf_get_current_pid_tgid`, as we have specified in the source code.

Next up, `REG-1` is set to a bit mask, that causes the upper `32` bit to be set. This bit mask is
then used to clear the PID from the value stored in `REG-0`. As we have learned before `REG-0` holds
the value of the call to the `bpf_get_current_pid_tgid` helper. It might be a bit confusing, as
it looks like, the lower `32` bits are set to high. This is caused by my architecture using big
endian encoding of bit order, meaning the left most byte we see on each line, is in reality the
least significant byte in the number.

`REG-1` is now set to a strange looking number, but on close inspection, it is the number `13` once
again encoded in big endian, left shifted by 32.

All of this is done in order to compare the value of `REG-0`, to what is stored in `REG-1`. If the
two do not match, our program will jump over the next 11 instructions.

Otherwise, there is some strange looking subtractions going on. In reality, those are stack
allocations, since `REG-10` is our read only stack pointer. The values we assign here are simply the
ASCII encoded characters we want to print in our string.

```plain
66 6f 72 6b 20 64 65 74 65 63 74 65 64 00 00 00
f  o  r  k     d  e  t  e  c  t  e  d
```

In case you are wondering, why there a punch of zeroes in the middle of one of the load operations,
this is caused by it being a wide instruction. The second part of a wide instruction has every field
set to zero, besides the immediate value.

```plain
11:       18 01 00 00 66 6f 72 6b 00 00 00 00 20 64 65 74 r1 = 8387219971451809638 ll
          op s  d  of --- imm --- op s  d  of --- imm ---
```

Then some more fun things are happening. `REG-1` is set to `REG-10` and then `16` is subtracted.
What is happening here is, that we get the address of the start of our string. You might be
wondering why we subtract `16` though.

The reason for this is, that there is some padding added at the end of the string, to properly
align it with a power of two offset. As strings in C are terminated with `\0` then one additional
`NULl` byte indicates the end of string.

The value of `REG-2` is now set to `14`, which is the length of the string we want to print. We
then call helper `6`, which according to the helper table is `bpf_trace_printk`. So in reality, all
we are doing is passing the memory address of our string as the first argument and the length as
the second argument to the `bpf_trace_printk` function. Nice!

Last but not least, we set `REG-0` to `0` and exit our program.

And that is it! So eBPF byte code is not too hard to read! Nice!

Next up, we will have a look at the component responsible for ensuring our eBPF is safe. The eBPF
verifier.

<!-- eBPF verifier -->

Each time you try to load an eBPF program into the kernel, it needs to be ensured, that the program
is safe and doesn't crash the whole kernel. This is one of the pillars of eBPF. To achieve such
safety, each eBPF program goes through formal verification.

One important thing to remember is, that the verifier works on eBPF bytecode, not on your sources.
It does not understand any of your C/Rust/Zig or whatever code you used to write your eBPF programs.
In practice, this means that the output of the verifier can and will be somewhat confusing from time
to time, as compilers have the dependency to shuffle around and optimize your code.

For example, the verifier will reject any program, that has unreachable instructions. Now,
compilers are the real heroes and turn most of our poorly written code into somewhat optimized
native code, meaning they will also happily go ahead and purge those unreachable instructions. This
of course means, that the byte code we get does not match our source code, which is also exactly
why our program will pass the verifier.

But how does it work?

The safety of any program we try to load is determined in two steps.

First, the verifier turns all of the byte code into an directed acyclic graph, or DAG for short, to
perform some control flow validations, such as disallowing unbounded loops. You heard that right,
unbounded loops are generally not allowed in eBPF programs. In this step, the verifier also ensures
that all instructions in the program are reachable.

The second step then starts from the first instruction and descends down all possible path. It
simulates the execution of every instruction and observes the state change of registers and stack.
This is also where the magic comes in, as verifying every instruction is not particularly cheap.
I am sadly not going to go into any details how exactly this works, as this is more than enough
for a talk on its own. All I can tell you is, that the verifier has some nice tricks up its sleeves.
You should definitely go and checkout the Linux verifier documentation, as it contains more
fascinating details about its inner workings. There are also some very good talks about this matter
from last eBPF summit.

One thing though, this is also the reason the verifier disallows unbounded loops, as it cannot
verify that the eBPF program will halt at some point. Another fun fact, since verifying larger
programs takes more time, it would still mean an infinitely large program would take forever. This
of course is also not feasible, hence an instruction limit was slapped on and the verifier simply
rejects eBPF programs with more then `1 000 000` instructions.

A word of advise, get familiar with the verifier error messages. Even though they are sometimes
somewhat straight forward, they are often not easy to understand and can be quite confusing from
time to time. For example, it can happen that the verifier thinks that a certain pointer can be
NULL, even though there was an if testing this conditions a few lines above. In such cases being
able to dump the eBPF bytecode and look at it directly has proofed to be very helpful.

Cool now that we grasp the verifier, lets take a 10000 look at applications leveraging the power
of eBPF.

<!-- Start case study -->

By looking at the eBPF website, we can see, that there are quite a lot of companies and tools using
the power of eBPF. Lets look into some examples of what exactly eBPF is used for.

First up, we have Katran. We already learned that it acts as a central component of Facebook's
network infrastructure and it is achieving its high performance, through the power of eBPF.
Specifically, it leverages the power of XDP to forward packets right on the network interface card,
before it even hits the kernels network stack. This makes it incredibly fast. One nice side effect
of this, the CPU impact of Katran is relatively low, compared to other technologies. This means,
it should be possible to run any other application on the same server without any performance
penalties. All of this thanks to eBPF.

When speaking of eBPF and networking, Cilium needs to be mentioned as well. Cilium, in case you
never heard of it, is a networking, observability and security solution for you Kubernetes cluster.
Its whole dataplane is based on eBPF. As you would have probably guessed by now, it also routes the
network packets directly via XDP, replacing the need to configure complicated iptables chains for
routing. It even goes as far as offering a way to get rid of kube-proxy. How cool is that?

eBPF is not just used for networking though. One popular use case for the technology is also in
monitoring. So of course the bigger players in that space are using it at well. Are there any
Dynatracers present? Good, you probably want to cover your eyes and ears for the next minute or so,
as we are going to talk about Datadog. The source code of their agents is available on Github. By
poking around it, you can quickly see, that eBPF is used across a variety of places. From hooking
network related kernel methods to trace network packets, to hooking syscalls and killing processes
that violate policies. They do quite a bit.

Speaking of security focused products in the cloud native space, how can I do a talk about this
topic and not mention Tetragon. Like Cilium, it is brought to us by the bright minds of Isovalent.
With Tetragon, you can hook pretty much any kernel function/Tracepoint you want, with the simplicity
of a single custom resource deployed to your Kubernetes cluster. Those policies really pack a punch,
as they allow you to kill processes in flight if they match whatever conditions you gave them. It is
much like the Datadog agent, but without the need to pay a small fortune for a monitoring product.

As you can see eBPF is used all across the industry. Lets dig a little deeper. For the next section
we are going to have a look at a concrete detection implemented in CAST.AIs kvisor product. Full
disclaimer, I not only work for CAST.AI, I am also one of the main contributors to kvisor.

<!-- Concrete example -->

In case you do not know CAST.AI, its main product helps you getting more bang for the buck by
optimizing your Kubernetes clusters to the maximum, by automatically adjusting the resource
requirements of your deployments and accordingly scale your node pools. Not too long ago
CAST.AI broaden its horizon and is now also offering a Kubernetes runtime monitoring solution
leveraging the insane powers of eBPF.

Recently during a discussion with some of my colleagues, we came up with the nice idea trying to
detect container drift, by leveraging the way containers are usually implemented. The idea is sadly
not entirely original, since Falco, the cloud security tool from sysdig, not the famous Austrian
singer, is doing something similar.

Let's have a quick high level view of the architecture of kvisor. The code we are going to look at
lives in kernel space, as a eBPF tracepoint program. From eBPF, events are emitted to a perf buffer,
that is read from the userspace component of kvisor. Here the events are ingested into the signature
detection engine, that is responsible for detecting anomalies in high bandwidth events, such as file
read/writes. Signature findings and some raw events from the tracer are then queued for export to
the CAST.AI backend, where they will be run through an anomaly detection engine. If you are curious
what else is going on in the backend, feel free to approach me after this talk, or consider applying
at one of CAST.AIs open job positions.

Anyway, the idea is, that containers are implemented on top of OverlayFS. The gist of it is, that
with OverlayFS, you can point to a bunch of directories called lower layer, that are pretty much
read only and an upper layer, where all the file modification go into. To understand how we can
detect if a file is in the upper layer, we first need to understand what an inode is. By definition,
an inode is an index node. It acts as a unique identifier for a specific piece of metadata on a
given filesystem. In the case of OverlayFS, it adds additional details to inodes it creates. This
is done in a rather smart way. Since you cannot simply extend kernel data structures (unless they
of course feature a `void*` field letting you point to whatever), OverlayFS defines a special
`ovl_inode` struct, that simply embeds the `inode` struct. It then returns the pointer to the field
in the `ovl_inode` struct back to the kernel. This means, that by using pointer magic, you can
simply get the wrapping `ovl_inode` container, by just subtracting the offset of the field in the
struct from the inode pointer. This is exactly what we are doing in the eBPF code. More precisely we
are not getting the full container, but we are simply reading the field after the inode. To achieve
this, we add the size of the inode struct to the pointer and voila, we get the next field. Long
story short, if we detect that the `__upperdentry` is pointing to anything other than `NULL` and its
flags has `OVL_E_UPPER_ALIAS` set, we know that the binary was not present in the original container
image. `OVL_E_UPPER_ALIAS` is set for files that are either copied or written, meaning we should not
alert for symlinks.

That covers the theory, but how does it look in practice?

Now we are going to take a peek into the small 7k lines `tracee.bpf.c` file. Before you ask, yeah,
kvisor is pretty much a fork of Tracee from Aqua, which we extended to fit our needs. Anyway, in
the file, there exists a function called `tracepoint__sched__sched_process_exec`, which hooks the
`sched_process_exe` tracepoint. This tracepoint gets called every time a process is launched. I am
going to skip over most parts of the hook, since it is mostly bookkeeping to construct an event
that is being sent to userspace for further processing. If you would like to know more, feel free
to approach me afterwards and we can have a chat. I am more than happy to explain how it is working
in details. The part we are focusing in is close to the end of the function. A function called
`get_exe_upper_layer` is being called, that is exactly doing what we described before. The function
takes a `dentry` and a `super_block` structs. A `super_block` is part of the inode, containing meta
information. The part we are interested in is the so called `s_magic` field, which is a unsigned
long value, that marks the underlying filesystem used for the inode. The `dentry` on the other
hand acts as a way to translate between names and inodes. We retrieve both the dentry and inode
from the `linux_binprm` struct, that is passed in to the tracepoint as the second argument. In a
nutshell, this struct contains all the data required to execute a program, meaning virtual memory
area, filename, file descriptors, arguments and so on.

Long story short, to know if a file was in the base layer of a container, we simply probe the magic
field of the super block to match that of OverlayFS, plus use some pointer magic to access the
`__upperdentry` field, located after the inode in the `ovl_inode` struct. All that is left to do
is to probe if the `__upperdentry` is pointing to something and if the `OVL_E_UPPER_ALIAS` flag is
set on the dentry.

And that is pretty much it! Congratulations, we just implemented basic detection for container
drift.

<!-- Closing -->
This brings me to the end of this talk. I hope you learned a thing or two about eBPF and got a
better understanding what all the hype is about.

To recap, eBPF can be thought as what JS is to the browser for the kernel. It provides us with a easy and secure way to
extend the kernel. Due to its flexibility, it can be used for a large range of use-cases, such as
tracing, networking (XDP) and security (LSM). There are also more exiting things on the horizon for
eBPF, such as `sched-ext`.

If you are interested in this topic, I highly encourage you to check out the source code for
projects such as tracee, as they give you pretty nice glimpse into what is possible with eBPF. I can
also highly recommend joining the eBPF slack channel, on the cilium slack server. There are quite a
lot of interesting discussions and also they are very welcoming to new members.

I would also encourage you to check out my personal blog at patrickpichler.dev. Currently it looks
a bit empty, but I hopefully get around to transform all research I have done from past talks into
articles and put them up there. So stay tuned, hopefully.

If you like to discuss more about eBPF, feel free to approach me and talk to me. I am more than
happy to talk about it!

In case you are interested in eBPF and kubernetes security and want to do it also in your day job,
the CAST.AI security team, which I am also part of, is hiring!

Thanks!
