#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#define ONCPU

//发送给用户空间的数据
typedef struct data {
    u64 each_oncpu;
    u64 total_oncpu;
} data_t;


BPF_HASH(start, u64, u64);
//BPF_HISTOGRAM(dist);
//用来输出数据
BPF_PERF_OUTPUT(result);


// 存储on-cpu时间，仅仅保存指定的pid
static inline void update_hist(u32 tgid, u32 pid, u64 ts, struct pt_regs *ctx)
{ 
    u64 key_each_oncpu_time = 4;
    u64 key_oncpu_time = 5;
    if (tgid != 16679)
        return;
    // 获取key为pid的value值
    u64 *tsp = start.lookup(&key_each_oncpu_time);
    if (tsp == 0)
        return;

    if (ts < *tsp) {
        // Probably a clock issue where the recorded on-CPU event had a
        // timestamp later than the recorded off-CPU event, or vice versa.
        return;
    }
    u64 delta = ts - *tsp;
    //这的delta是每一次的oncpu时间
    delta /= 1000;
    //累加delta的值,如果还没有，就初始化
    u64 * o = start.lookup(&key_oncpu_time);
    if (o == NULL) {
        return;
    }
    // delta += *o; 
    // start.update(&key_oncpu_time, &delta);


    data_t data = {};


    data.each_oncpu = delta;
    data.total_oncpu = delta;

    start.update(&key_each_oncpu_time, &ts);
    // 保存on-cpu时间
    //dist.increment(bpf_log2l(delta));
    result.perf_submit(ctx, &data, sizeof(data));
}

int sched_switch(struct pt_regs *ctx, struct task_struct *prev)
{
    u64 key_oncpu_time = 5;     //存放每一次oncpu的时间  
    u64 key_each_oncpu_time = 4;
    u64 zero = 0;   //用于数据清零
    //u64 key_oncpu_time = 5;                 
    //获取当前时间
    u64 ts = bpf_ktime_get_ns();
    //
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 tgid = pid_tgid >> 32, pid = pid_tgid;

    if (tgid == 16679) {
        //初始化该tgid的时间
        u64 * each = start.lookup_or_init(&key_each_oncpu_time,&ts);
        if (each == NULL) {
            return 0;
        }
        u64 * oncpu = start.lookup_or_init(&key_oncpu_time,&zero);
        if (oncpu == NULL) {
            return 0;
        }
    }


    if (prev->state == TASK_RUNNING) {
        u32 prev_pid = prev->pid;
        u32 prev_tgid = prev->tgid;
        update_hist(prev_tgid, prev_pid, ts, ctx);
    }

    


    return 0;
}




