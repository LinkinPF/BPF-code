#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/nsproxy.h>
#include <linux/pid_namespace.h>

// typedef struct pid_key {
//     u64 id;    // work around
//     u64 slot;
// } pid_key_t;

// typedef struct pidns_key {
//     u64 id;    // work around
//     u64 slot;
// } pidns_key_t;

typedef struct data {
	u64 time;
	//u32 count;
} data_t;

//这个哈系保存BPF程序执行过程的数据
BPF_HASH(start, u32);
//这个哈系存储传输给用户空间的数据
//key: 1  value： 这段时间内的总的延迟时间
//key: 2   value： 间隔时间
BPF_HASH(output, u64, u64);
BPF_PERF_OUTPUT(result);

struct rq;

// record enqueue timestamp
static int trace_enqueue(u32 tgid, u32 pid)
{
    if (0 || pid == 0)
        return 0;
    u64 ts = bpf_ktime_get_ns();
    start.update(&pid, &ts);
    return 0;
}

// 记录新创建的进程刚被调度到运行队列上的时间。
int trace_wake_up_new_task(struct pt_regs *ctx, struct task_struct *p)
{
    return trace_enqueue(p->tgid, p->pid);
}

// 记录自愿上下文切换的进程，实时进程的。
int trace_ttwu_do_wakeup(struct pt_regs *ctx, struct rq *rq, struct task_struct *p,
    int wake_flags)
{
    return trace_enqueue(p->tgid, p->pid);
}

// calculate latency
int trace_run(struct pt_regs *ctx, struct task_struct *prev)
{
    u32 pid, tgid;

    //用于回传给用户空间
    u64 i = 1;		//存储总的延迟时间
    u64 j = 2;		//存储时间
    u64 zero = 0;	//用于重置delta

    // ivcsw: treat like an enqueue event and store timestamp
    // 记录非自愿上下文切换的时间
    if (prev->state == TASK_RUNNING) {
        tgid = prev->tgid;
        pid = prev->pid;
        if (!(0 || pid == 0)) {
            u64 ts = bpf_ktime_get_ns();
            start.update(&pid, &ts);
        }
    }

    tgid = bpf_get_current_pid_tgid() >> 32;
    pid = bpf_get_current_pid_tgid();
    if (0 || pid == 0)
        return 0;
    u64 *tsp, delta;

    // fetch timestamp and calculate delta
    // 计算当前这个进程和上一次调度的时间差
    tsp = start.lookup(&pid);
    if (tsp == 0) {
        return 0;   // missed enqueue
    }
    delta = bpf_ktime_get_ns() - *tsp;
    delta /= 1000;
//------------------------------------------------

	//获取当前的delta,加上这次的延迟时间
    u64 * o = output.lookup_or_init(&i,&delta);
    if (o == NULL) {
    	return 0;
    }
    u64 now_delta = *o + delta;
    output.update(&i,&now_delta);


    //获取上一次的时间
    u64 cur = bpf_ktime_get_ns();
	u64 * time_old = output.lookup_or_init(&j,&cur);
	if (time_old == NULL) {
		return 0;
	}

	//1秒时间到
	if (cur-*time_old >= 1000000000) {
		data_t data = {};
		//先更新时间
		output.update(&j,&cur);
    	//传送给用户空间
    	u64 *k = output.lookup(&i);
    	if (k == NULL) {
    		return 0;
    	}
		data.time = *k;
    	result.perf_submit(ctx, &data, sizeof(data));
    	output.update(&i,&zero);
	}


    // output.update(&i,&delta);
    // output.update(&j,&cur);

    //传送给用户空间
    // u64 * k = output.lookup(&i);
    return 0;
}


