#include <uapi/linux/ptrace.h>
#include <linux/sched.h>


//发送给用户空间的数据
typedef struct data {
    u64 total_len;
    //u32 count;
} data_t;


// Declare enough of cfs_rq to find nr_running, since we can't #import the
// header. This will need maintenance. It is from kernel/sched/sched.h:
struct cfs_rq_partial {
    struct load_weight load;
    unsigned long runnable_weight;
    unsigned int nr_running, h_nr_running;
};

//BPF_HISTOGRAM(dist, unsigned int);
//key:1   value:保存runqlen的长度和
//key:2   value:间隔时间
BPF_HASH(output, u64);

//用来输出数据
BPF_PERF_OUTPUT(result);

int do_perf_event(struct pt_regs *ctx)
{
	//用于回传给用户空间
    u64 key_len = 1;		//存储排队进程总数
    u64 j = 2;		//存储时间
    u64 zero = 0;	//用于重置delta

    u64 len = 0;
    pid_t pid = 0;
    struct task_struct *task = NULL;
    struct cfs_rq_partial *my_q = NULL;

    // Fetch the run queue length from task->se.cfs_rq->nr_running. This is an
    // unstable interface and may need maintenance. Perhaps a future version
    // of BPF will support task_rq(p) or something similar as a more reliable
    // interface.
    task = (struct task_struct *)bpf_get_current_task();
    my_q = (struct cfs_rq_partial *)task->se.cfs_rq;
    len = my_q->nr_running;

    // Calculate run queue length by subtracting the currently running task,
    // if present. len 0 == idle, len 1 == one running task.
    if (len > 0)
        len--;
    //在这里进行长度的累加。
    u64 * o = output.lookup_or_init(&key_len,&len);
    if (o == NULL) {
    	return 0;
    }
    u64 now_len = *o + len;
    output.update(&key_len,&now_len);

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
    	u64 *k = output.lookup(&key_len);
    	if (k == NULL) {
    		return 0;
    	}
		data.total_len = *k;
    	result.perf_submit(ctx, &data, sizeof(data));
    	output.update(&key_len,&zero);
	}

    return 0;
}