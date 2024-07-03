profile.c
=========
// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2022 Facebook */
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <sys/syscall.h>
#include <sys/sysinfo.h>
#include <linux/perf_event.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "profile.skel.h"
#include "profile.h"
#include "blazesym.h"

/*
 * This function is from libbpf, but it is not a public API and can only be
 * used for demonstration. We can use this here because we statically link
 * against the libbpf built from submodule during build.
 */
extern int parse_cpu_mask_file(const char *fcpu, bool **mask, int *mask_sz);

static struct blaze_symbolizer *symbolizer;

static void print_frame(const char *name, uintptr_t input_addr, uintptr_t addr, uint64_t offset, const blaze_symbolize_code_info* code_info)
{
    // If we have an input address  we have a new symbol.
    if (input_addr != 0) {
      printf("%016lx: %s @ 0x%lx+0x%lx", input_addr, name, addr, offset);
                        if (code_info != NULL && code_info->dir != NULL && code_info->file != NULL) {
                                printf(" %s/%s:%u\n", code_info->dir, code_info->file, code_info->line);
      } else if (code_info != NULL && code_info->file != NULL) {
                                printf(" %s:%u\n", code_info->file, code_info->line);
      } else {
                                printf("\n");
      }
    } else {
      printf("%16s  %s", "", name);
                        if (code_info != NULL && code_info->dir != NULL && code_info->file != NULL) {
                                printf("@ %s/%s:%u [inlined]\n", code_info->dir, code_info->file, code_info->line);
      } else if (code_info != NULL && code_info->file != NULL) {
                                printf("@ %s:%u [inlined]\n", code_info->file, code_info->line);
      } else {
                                printf("[inlined]\n");
      }
    }
}

static void show_stack_trace(__u64 *stack, int stack_sz, pid_t pid)
{
  const struct blaze_symbolize_inlined_fn* inlined;
        const struct blaze_result *result;
        const struct blaze_sym *sym;
        int i, j;

        assert(sizeof(uintptr_t) == sizeof(uint64_t));

        if (pid) {
                struct blaze_symbolize_src_process src = {
                        .type_size = sizeof(src),
                        .pid = pid,
                };
                result = blaze_symbolize_process_abs_addrs(symbolizer, &src, (const uintptr_t *)stack, stack_sz);
        } else {
                struct blaze_symbolize_src_kernel src = {
                        .type_size = sizeof(src),
                };
                result = blaze_symbolize_kernel_abs_addrs(symbolizer, &src, (const uintptr_t *)stack, stack_sz);
        }


        for (i = 0; i < stack_sz; i++) {
                if (!result || result->cnt <= i || result->syms[i].name == NULL) {
                        printf("%016llx: <no-symbol>\n", stack[i]);
                        continue;
                }

    sym = &result->syms[i];
    print_frame(sym->name, stack[i], sym->addr, sym->offset, &sym->code_info);

    for (j = 0; j < sym->inlined_cnt; j++) {
      inlined = &sym->inlined[j];
      print_frame(sym->name, 0, 0, 0, &inlined->code_info);
    }
        }

        blaze_result_free(result);
}

/* Receive events from the ring buffer. */
static int event_handler(void *_ctx, void *data, size_t size)
{
        struct stacktrace_event *event = data;

        if (event->kstack_sz <= 0 && event->ustack_sz <= 0)
                return 1;

        printf("COMM: %s (pid=%d) @ CPU %d\n", event->comm, event->pid, event->cpu_id);

        if (event->kstack_sz > 0) {
                printf("Kernel:\n");
                show_stack_trace(event->kstack, event->kstack_sz / sizeof(__u64), 0);
        } else {
                printf("No Kernel Stack\n");
        }

        if (event->ustack_sz > 0) {
                printf("Userspace:\n");
                show_stack_trace(event->ustack, event->ustack_sz / sizeof(__u64), event->pid);
        } else {
                printf("No Userspace Stack\n");
        }

        printf("\n");
        return 0;
}

static void show_help(const char *progname)
{
        printf("Usage: %s [-f <frequency>] [-h]\n", progname);
}

int main(int argc, char *const argv[])
{
        const char *online_cpus_file = "/sys/devices/system/cpu/online";
        int freq = 1, pid = -1, cpu;
        struct profile_bpf *skel = NULL;
        struct perf_event_attr attr;
        struct bpf_link **links = NULL;
        struct ring_buffer *ring_buf = NULL;
        int num_cpus, num_online_cpus;
        int *pefds = NULL, pefd;
        int argp, i, err = 0;
        bool *online_mask = NULL;

        while ((argp = getopt(argc, argv, "hf:")) != -1) {
                switch (argp) {
                case 'f':
                        freq = atoi(optarg);
                        if (freq < 1)
                                freq = 1;
                        break;

                case 'h':
                default:
                        show_help(argv[0]);
                        return 1;
                }
        }

        skel = profile_bpf__open_and_load();
        if (!skel) {
                fprintf(stderr, "Fail to open and load BPF skeleton\n");
                err = -1;
                goto cleanup;
        }

        err = profile_bpf__attach(skel);
        if (err) {
                fprintf(stderr, "Failed to attach BPF skeleton err: %d\n", err);
                goto cleanup;
        }

        symbolizer = blaze_symbolizer_new();
        if (!symbolizer) {
                fprintf(stderr, "Fail to create a symbolizer\n");
                err = -1;
                goto cleanup;
        }

        /* Prepare ring buffer to receive events from the BPF program. */
        ring_buf = ring_buffer__new(bpf_map__fd(skel->maps.events), event_handler, NULL, NULL);
        if (!ring_buf) {
                err = -1;
                goto cleanup;
        }


        /* Wait and receive stack traces */
        while (ring_buffer__poll(ring_buf, -1) >= 0) {
        }

cleanup:
        if (links) {
                for (cpu = 0; cpu < num_cpus; cpu++)
                        bpf_link__destroy(links[cpu]);
                free(links);
        }
        if (pefds) {
                for (i = 0; i < num_cpus; i++) {
                        if (pefds[i] >= 0)
                                close(pefds[i]);
                }
                free(pefds);
        }
        ring_buffer__free(ring_buf);
        profile_bpf__destroy(skel);
        blaze_symbolizer_free(symbolizer);
        free(online_mask);
        return -err;
}

profile.bpf.c:
=============
// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2022 Meta Platforms, Inc. */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "profile.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
        __uint(type, BPF_MAP_TYPE_RINGBUF);
        __uint(max_entries, 256 * 1024);
} events SEC(".maps");

SEC("perf_event")
int profile(void *ctx)
{
        int pid = bpf_get_current_pid_tgid() >> 32;
        int cpu_id = bpf_get_smp_processor_id();
        struct stacktrace_event *event;
        int cp;

        event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
        if (!event)
                return 1;

        event->pid = pid;
        event->cpu_id = cpu_id;

        if (bpf_get_current_comm(event->comm, sizeof(event->comm)))
                event->comm[0] = 0;

        event->kstack_sz = bpf_get_stack(ctx, event->kstack, sizeof(event->kstack), 0);

        event->ustack_sz =
                bpf_get_stack(ctx, event->ustack, sizeof(event->ustack), BPF_F_USER_STACK);

        bpf_ringbuf_submit(event, 0);

        return 0;
}
