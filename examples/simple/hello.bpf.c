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
