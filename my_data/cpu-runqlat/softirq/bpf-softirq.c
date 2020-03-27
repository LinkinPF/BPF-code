#include <uapi/linux/ptrace.h>

typedef struct irq_key {
    u32 vec;
    u64 slot;
} irq_key_t;

typedef struct account_val {
    u64 ts;
    u32 vec;
} account_val_t;


typedef struct data {
    u64 total_softirq;          //key: 5   value： 保存softirq时间
} data_t;

BPF_HASH(output, u64, u64);

BPF_PERF_OUTPUT(result);
//BPF_HASH(iptr, u32);
//BPF_HISTOGRAM(dist, irq_key_t);


BPF_HASH(start_softirq, u32, account_val_t);
BPF_HASH(iptr, u32);
//BPF_HISTOGRAM(dist, irq_key_t);

TRACEPOINT_PROBE(irq, softirq_entry)
{
    u64 key_total_softirq = 5;
    u64 zero = 0;

    u32 pid = bpf_get_current_pid_tgid();
    account_val_t val = {};
    val.ts = bpf_ktime_get_ns();
    val.vec = args->vec;
    start_softirq.update(&pid, &val);
    // u64 * o = output.lookup_or_init(&key_total_softirq,&zero);
    // if (o == NULL) {
    //     return 0;
    // }
    return 0;
}



TRACEPOINT_PROBE(irq, softirq_exit)
{
    u64 key_total_softirq = 5;
    u64 zero = 0;
    u64 delta;
    u32 vec;
    u32 pid = bpf_get_current_pid_tgid();
    account_val_t *valp;
    irq_key_t key = {0};

    // fetch timestamp and calculate delta
    valp = start_softirq.lookup(&pid);
    if (valp == 0) {
        return 0;   
    }
    delta = bpf_ktime_get_ns() - valp->ts;
    vec = valp->vec;

    // store as sum or histogram
    key.vec = valp->vec; //dist.increment(key, delta);

    //把所有的值加到一起，
    u64 * kts = output.lookup_or_init(&key_total_softirq,&zero);
    if (kts == NULL) {
        return 0;
    }
    delta += *kts;
    output.update(&key_total_softirq, &delta);

    start_softirq.delete(&pid);
    return 0;
}


int trace(struct pt_regs *ctx, struct task_struct *prev)
{
    u64 key_time = 2;       //存储时间（1s）
    u64 zero = 0;
    u64 key_total_softirq = 5;

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

        u64 * kts = output.lookup(&key_total_softirq);
        if (kts == NULL) {
            return 0;
        }
        data.total_softirq = *kts / 1000;
        
        result.perf_submit(ctx, &data, sizeof(data));
        //把已经提取的数据清零
        output.update(&key_total_softirq,&zero);

    }

    return 0;
}










































