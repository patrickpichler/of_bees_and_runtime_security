#include <linux/bpf.h>

#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "GPL";

SEC("xdp")
int hello(void *ctx) {
  __u64 val = bpf_get_current_pid_tgid();
  __u32 pid = val >> 32;

  if (pid == 32) {
    return XDP_DROP;
  }

  return XDP_PASS;
}
