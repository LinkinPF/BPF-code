#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#define ONCPU

// 自定义的数据结构，用于向用户空间传输数据
typedef struct data {
    u64 total_oncpu_time;     //key: 1   value： 这段时间内的总的延迟时间
} data_t;


BPF_HASH(start_oncpu, u32, u64);      //记录每一次的oncpu时间

//key: 2   value： 间隔时间
BPF_HASH(output, u64, u64);     

BPF_PERF_OUTPUT(result);

static inline void store_start(u32 tgid, u32 pid, u64 ts)
{
    if (tgid != 30058)
        return;

    start_oncpu.update(&pid, &ts);
}

static inline void update_hist(u32 tgid, u32 pid, u64 ts, struct pt_regs *ctx)
{
    if (tgid != 30058)
        return;
    u64 key_oncpu = 4;      //存储总的oncpu时间

    u64 *tsp = start_oncpu.lookup(&pid);
    if (tsp == 0)
        return;

    if (ts < *tsp) {
        // Probably a clock issue where the recorded on-CPU event had a
        // timestamp later than the recorded off-CPU event, or vice versa.
        return;
    }
    u64 delta = ts - *tsp;
    delta /= 1000;

    //获取当前的delta,加上这次的延迟时间
    u64 * o = output.lookup(&key_oncpu);
    if (o == 0) {
        return;
    }
    delta += *o;
    output.update(&key_oncpu,&delta);

    
}

int sched_switch(struct pt_regs *ctx, struct task_struct *prev)
{
    u64 key_time = 2;       //存储时间（1s）
    u64 key_oncpu = 4;      //存储总的oncpu时间

    u64 zero = 0;

    u64 ts = bpf_ktime_get_ns();
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 tgid = pid_tgid >> 32, pid = pid_tgid;

    if (prev->state == TASK_RUNNING) {
        u32 prev_pid = prev->pid;
        u32 prev_tgid = prev->tgid;
        update_hist(prev_tgid, prev_pid, ts, ctx);
    }

    u64 * o = output.lookup_or_init(&key_oncpu,&zero);
    if (o == 0) {
        return 0;
    }

    //获取上一次的时间
    u64 cur = bpf_ktime_get_ns();
    u64 * time_old = output.lookup_or_init(&key_time,&cur);
    if (time_old == NULL) {
        return 0;
    }

    //1秒时间到
    if (cur-*time_old >= 1000000000) {
        //先更新时间
        output.update(&key_time,&cur);
        //传送数据到用户空间

        data_t data = {};
        u64 * o = output.lookup(&key_oncpu);
        if (o == NULL) {
            return 0;
        }
        data.total_oncpu_time = *o;
        result.perf_submit(ctx, &data, sizeof(data));
        output.update(&key_oncpu,&zero);
    }

BAIL:
    store_start(tgid, pid, ts);

    return 0;
}
