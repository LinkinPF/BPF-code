#include <uapi/linux/ptrace.h>
#include <linux/irq.h>
#include <linux/irqdesc.h>
#include <linux/interrupt.h>

typedef struct irq_key {
    char name[32];
    u64 slot;
} hardirq_key_t;


typedef struct data {
    u64 total_hardirq;          //key: 5   value： 保存softirq时间
} data_t;


BPF_HASH(start_hardirq, u32);
BPF_HASH(irqdesc, u32, struct irq_desc *);
//BPF_HISTOGRAM(dist, irq_key_t);

//向用户空间返回数据
BPF_HASH(output, u64, u64);
BPF_PERF_OUTPUT(result);



// time IRQ
int trace_start(struct pt_regs *ctx, struct irq_desc *desc)
{
    u32 pid = bpf_get_current_pid_tgid();
    u64 ts = bpf_ktime_get_ns();
    start_hardirq.update(&pid, &ts);
    irqdesc.update(&pid, &desc);
    return 0;
}

int trace_completion(struct pt_regs *ctx)
{
    u64 key_total_hardirq = 6;
    u64 zero = 0;
    u64 *tsp, delta;
    struct irq_desc **descp;
    u32 pid = bpf_get_current_pid_tgid();

    // fetch timestamp and calculate delta
    tsp = start_hardirq.lookup(&pid);
    descp = irqdesc.lookup(&pid);
    if (tsp == 0 || descp == 0) {
        return 0;   // missed start
    }
    struct irq_desc *desc = *descp;
    struct irqaction *action = desc->action;
    char *name = (char *)action->name;
    delta = bpf_ktime_get_ns() - *tsp;

    // store as sum or histogram
    irq_key_t key = {.slot = 0 /* ignore */};
    bpf_probe_read(&key.name, sizeof(key.name), name);
    //dist.increment(key, delta);

    //把所有的值加到一起，
    u64 * kts = output.lookup_or_init(&key_total_hardirq,&zero);
    if (kts == NULL) {
        return 0;
    }
    delta += *kts;
    output.update(&key_total_hardirq, &delta);
    start_hardirq.delete(&pid);
    irqdesc.delete(&pid);
    return 0;
}




int trace(struct pt_regs *ctx, struct task_struct *prev)
{
    u64 key_time = 2;       //存储时间（1s）
    u64 zero = 0;
    u64 key_total_hardirq = 6;

    //获取上一次的时间
    u64 cur = bpf_ktime_get_ns();
    u64 * time_old = output.lookup_or_init(&key_time,&cur);
    if (time_old == NULL) {
        return 0;
    }

    if (cur-*time_old >= 1000000000) {
        data_t data = {};
        //先更新时间
        output.update(&key_time,&cur);

        u64 * kts = output.lookup(&key_total_hardirq);
        if (kts == NULL) {
            return 0;
        }
        data.total_hardirq = *kts / 1000;
        
        result.perf_submit(ctx, &data, sizeof(data));
        //把已经提取的数据清零
        output.update(&key_total_hardirq,&zero);

    }

    return 0;
}

