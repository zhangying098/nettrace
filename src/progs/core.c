#define KBUILD_MODNAME ""
#include <kheaders.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_tracing.h>

#include "shared.h"
#include <skb_parse.h>

#include "kprobe_trace.h"
#include "core.h"

#ifdef KERN_VER
__u32 kern_ver SEC("version") = KERN_VER;
#endif

// 该 bpf map 针对 entry 和 exit 的计数
struct
{
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(key_size, sizeof(int));
	__uint(value_size, sizeof(int));
	__uint(max_entries, TRACE_MAX);
} m_ret SEC(".maps");

#ifdef BPF_FEAT_STACK_TRACE
// 传递调用栈信息
struct
{
	__uint(type, BPF_MAP_TYPE_STACK_TRACE);
	__uint(max_entries, 16384);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(stack_trace_t));
} m_stack SEC(".maps");
#endif

struct
{
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 102400);
	__uint(key_size, sizeof(u64));
	__uint(value_size, sizeof(u8));
} m_matched SEC(".maps");

#ifdef BPF_FEAT_STACK_TRACE
static try_inline void try_trace_stack(context_t *ctx)
{
	int i = 0, key;
	u16 *funcs;

	if (!ctx->args->stack)
		return;

	funcs = ctx->args->stack_funs;

#pragma unroll
	for (; i < MAX_FUNC_STACK; i++)
	{
		if (!funcs[i])
			break;
		if (funcs[i] == ctx->func)
			goto do_stack;
	}
	return;

do_stack:
	key = bpf_get_stackid(ctx->regs, &m_stack, 0);
	ctx->e->stack_id = key;
}
#else
static try_inline void try_trace_stack(context_t *ctx) {}
#endif

/*
	判断当前数据包是否符合用户设置的 net namespace inode 过滤条件
*/
static try_inline int filter_by_netns(context_t *ctx)
{
	struct sk_buff *skb = ctx->skb;
	/*
		struct net_device 表示网络设备的各种状态和属性用于描述网络设备的信息，比如设备的名称、MAC 地址、MTU 大小、操作函数等
	*/
	struct net_device *dev;
	u32 inode, netns;
	// 网络设备的状态信息, 如网络协议栈、路由表、ARP缓存等
	struct net *ns;

	/*
		bpf helper 函数：
			查询内核struct possible_net_t 结构体中是否包含 net 成员
	*/
	if (!bpf_core_field_exists(possible_net_t, net))
		return 0;

	netns = ctx->args->netns;
	// 如果用户没有设置 net namespace inode 且没有设置 detail 则退出
	if (!netns && !ctx->args->detail)
		return 0;

	// _C 宏函数功能：调BPF_CORE_READ，查询 skb->dev 值
	dev = _C(skb, dev);
	if (!dev)
	{
		struct sock *sk = _C(skb, sk);
		if (!sk)
			goto no_ns;
		ns = _C(sk, __sk_common.skc_net.net);
	}
	else
	{
		ns = _C(dev, nd_net.net);
	}

	if (!ns)
		goto no_ns;

	inode = _C(ns, ns.inum);
	if (ctx->args->detail)
		((detail_event_t *)ctx->e)->netns = inode;

	// 判断当前无网络是否符合用户设置的 net namespace inode 条件，不符合则跳过
	return netns ? netns != inode : 0;
no_ns:
	return !!netns;
}

// 函数功能：采集数据包信息，根据用户设置进行过滤，并将数据传输到用户态
static try_inline int handle_entry(context_t *ctx)
{
	// 状态控制条件 网络包过滤 + 数据采集
	bpf_args_t *args = (void *)ctx->args;
	/*
		skb 数据包是在操作系统内核中处理网络数据传输的数据结构，
		packet 数据包是网络通信中实际传输的数据单元。在 Linux
		系统中，skb 数据包通常会包含一个或多个 packet 数据包
	*/
	// skb 数据包
	struct sk_buff *skb = ctx->skb;
	bool *matched, skip_life;
	event_t *e = ctx->e;
	// packet 数据包
	packet_t *pkt;
	u32 pid;

	if (!args->ready)
		goto err;

	/*
		在 BPF_DEBUG 模式下，使用 bpf_printk 输出调试信息
	*/
	pr_debug_skb("begin to handle, func=%d", ctx->func);
	/*
		args->pkt_fixed：
			如果不是 NET 模式，可以跳过针对 NET 的包过滤，提高处理效率
	*/
	skip_life = (args->trace_mode & MODE_SKIP_LIFE_MASK) ||
				args->pkt_fixed;
	pid = (u32)bpf_get_current_pid_tgid();
	pkt = &e->pkt;

	// 在非 NET 情况，进入内部处理
	if (!skip_life)
	{
		matched = bpf_map_lookup_elem(&m_matched, &skb);
		if (matched && *matched)
		{
			// 解析数据包，根据数据包类型提取相关的数据信息
			probe_parse_skb_always(skb, pkt);
			// 判断当前数据包是否符合用户设置的 net namespace inode 过滤条件
			filter_by_netns(ctx);
			goto skip_filter;
		}
	}

	/*
		ARGS_CHECK 宏函数功能
			用户是否指定 PID 监控
		filter_by_netns 函数功能
			用户是否指定 net namespace inode 监控
	*/
	if (ARGS_CHECK(args, pid, pid) || filter_by_netns(ctx))
		goto err;

	if (args->trace_mode == TRACE_MODE_SOCK_MASK)
	{
		// 进一步解析数据包，采集 TCP 和 UDP 相关数据
		if (probe_parse_sk(ctx->sk, &e->ske))
			goto err;
	}
	else
	{
		// 数据信息的采集
		if (probe_parse_skb(skb, pkt))
			goto err;
	}

	if (!skip_life)
	{
		bool _matched = true;
		bpf_map_update_elem(&m_matched, &skb, &_matched, 0);
	}

skip_filter:
	if (!args->detail)
		goto out;

	/* store more (detail) information about net or task. */
	struct net_device *dev = _C(skb, dev);
	detail_event_t *detail = (void *)e;

	bpf_get_current_comm(detail->task, sizeof(detail->task));
	detail->pid = pid;
	if (dev)
	{
		bpf_probe_read_str(detail->ifname, sizeof(detail->ifname) - 1,
						   dev->name);
		detail->ifindex = _C(dev, ifindex);
	}
	else
	{
		detail->ifindex = _C(skb, skb_iif);
	}

out:
	pr_debug_skb("pkt matched");
	// 打印栈信息
	try_trace_stack(ctx);
	pkt->ts = bpf_ktime_get_ns();
	e->key = (u64)(void *)skb;
	e->func = ctx->func;

	// 将采集到的数据通过 bpf_perf_event_output 传递到用户态
	if (ctx->size)
		EVENT_OUTPUT_PTR(ctx->regs, ctx->e, ctx->size);

#ifdef BPF_FEAT_TRACING
	e->retval = ctx->retval;
#endif

	if (!skip_life)
		get_ret(ctx->func);
	return 0;
err:
	return -1;
}

static try_inline int handle_destroy(context_t *ctx)
{
	if (!(ctx->args->trace_mode & MODE_SKIP_LIFE_MASK))
		bpf_map_delete_elem(&m_matched, &ctx->skb);
	return 0;
}

static try_inline int default_handle_entry(context_t *ctx)
{
#ifdef COMPAT_MODE
	if (ctx->args->detail)
	{
		detail_event_t e = {};
		ctx_event(ctx, e);
		handle_entry(ctx);
	}
	else
	{
		event_t e = {};
		ctx_event(ctx, e);
		handle_entry(ctx);
	}
#else
	/*
		DECLARE_EVENT宏函数展开后的结果：

		{
			/// __attribute__((__unused__)) 是 GCC 的一个属性，用于告诉编译器该变量是未使用的，
			/// 避免编译器产生未使用变量的警告
			pure_event_t __attribute__((__unused__)) *e;
			if (ctx->args->detail)
				goto basic_detail;

			/// event_t 为 ebpf prog hook 点被触发后的事件信息，采集默认事件信息
			event_t _e = {0};

			/// ctx_event 宏函数展开为
			///		ctx->e = (void *)&(_e);
			///  	ctx->size = sizeof(_e);
			ctx_event(ctx, _e);

			/// 功能：将结构体 event_t 中 __event_filed 字段的地址存储在指针 e 中
			/// (void *)ctx->e  获取 ctx 中  event_t 的地址
			/// offsetof 为 event_t 中 __event_filed 的偏移量
			/// 上述 event_t 地址 + 偏移量 = __event_filed 地址，不过此处的功能不太清楚
			e = (void *)ctx->e + offsetof(event_t, __event_filed);
			goto basic_handle;
		basic_detail:;
			/// event_t 为 ebpf prog hook 点被触发后的事件信息，采集冗余事件信息
			detail_event_t __e = {0};
			ctx_event(ctx, __e);
			e = (void *)ctx->e + offsetof(detail_event_t, __event_filed);
		basic_handle:;
		}
	*/
	// 此处宏函数功能： 初始化 ctx->e，根据 ctx->args->detail 判断初始化 event_t 类型（默认 or 复杂）
	DECLARE_EVENT(event_t, e)
	handle_entry(ctx);
#endif

	/*
		针对 consume_skb 和 kfree_skb hook 函数
		进行数据的清理操作
	*/
	switch (ctx->func)
	{
	case INDEX_consume_skb:
	case INDEX___kfree_skb:
		handle_destroy(ctx);
		break;
	default:
		break;
	}

	return 0;
}

/**********************************************************************
 *
 * Following is the definntion of all kind of BPF program.
 *
 * DEFINE_ALL_PROBES() will define all the default implement of BPF
 * program, and the customize handle of kernel function or tracepoint
 * is defined following.
 *
 **********************************************************************/
// 宏函数在 src/progs/kprobe_trace.h 中定义
/*
	针对 kprobe 和 tracepoint 类型  hook 函数（函数由 yaml 解析）
	进行函数实现。
*/
DEFINE_ALL_PROBES(KPROBE_DEFAULT, TP_DEFAULT, FNC)

#ifndef BPF_FEAT_TRACING
struct kfree_skb_args
{
	u64 pad;
	void *skb;
	void *location;
	unsigned short protocol;
	int reason;
};
#else
struct kfree_skb_args
{
	void *skb;
	void *location;
	u64 reason;
};
#endif

DEFINE_TP_INIT(kfree_skb, skb, kfree_skb)
{
	struct kfree_skb_args *args = ctx->regs;
	int reason = 0;

	if (bpf_core_type_exists(enum skb_drop_reason))
		reason = (int)args->reason;
	else if (ARGS_GET_CONFIG(drop_reason))
		reason = (int)_(args->reason);

	DECLARE_EVENT(drop_event_t, e)

	e->location = (unsigned long)args->location;
	e->reason = reason;
	ctx->skb = args->skb;

	handle_entry(ctx);
	handle_destroy(ctx);
	return 0;
}

DEFINE_KPROBE_INIT(__netif_receive_skb_core_pskb,
				   __netif_receive_skb_core,
				   .skb = _(*(void **)(nt_regs(regs, 1))))
{
	return default_handle_entry(ctx);
}

static try_inline int bpf_ipt_do_table(context_t *ctx, struct xt_table *table,
									   struct nf_hook_state *state)
{
	char *table_name;
	DECLARE_EVENT(nf_event_t, e, .hook = _C(state, hook))

	if (bpf_core_type_exists(struct xt_table))
		table_name = _C(table, name);
	else
		table_name = _(table->name);

	bpf_probe_read(e->table, sizeof(e->table) - 1, table_name);
	return handle_entry(ctx);
}

DEFINE_KPROBE_SKB_TARGET(ipt_do_table_legacy, ipt_do_table, 1)
{
	struct nf_hook_state *state = nt_regs_ctx(ctx, 2);
	struct xt_table *table = nt_regs_ctx(ctx, 3);

	bpf_ipt_do_table(ctx, table, state);
	return 0;
}

DEFINE_KPROBE_SKB(ipt_do_table, 2)
{
	struct nf_hook_state *state = nt_regs_ctx(ctx, 3);
	struct xt_table *table = nt_regs_ctx(ctx, 1);

	bpf_ipt_do_table(ctx, table, state);
	return 0;
}

DEFINE_KPROBE_SKB(nf_hook_slow, 1)
{
	struct nf_hook_state *state;
	size_t size;
	int num;

	state = nt_regs_ctx(ctx, 2);
	if (ctx->args->hooks)
		goto on_hooks;

	DECLARE_EVENT(nf_event_t, e)

	size = ctx->size;
	ctx->size = 0;
	if (handle_entry(ctx))
		return 0;

	e->hook = _C(state, hook);
	e->pf = _C(state, pf);
	EVENT_OUTPUT_PTR(ctx->regs, ctx->e, size);
	return 0;

on_hooks:;
	struct nf_hook_entries *entries = nt_regs_ctx(ctx, 3);
	__DECLARE_EVENT(hooks, nf_hooks_event_t, hooks_event)

	size = ctx->size;
	ctx->size = 0;
	if (handle_entry(ctx))
		return 0;

	hooks_event->hook = _C(state, hook);
	hooks_event->pf = _C(state, pf);
	num = _(entries->num_hook_entries);

#define COPY_HOOK(i)                                            \
	do                                                          \
	{                                                           \
		if (i >= num)                                           \
			goto out;                                           \
		hooks_event->hooks[i] = (u64)_(entries->hooks[i].hook); \
	} while (0)

	COPY_HOOK(0);
	COPY_HOOK(1);
	COPY_HOOK(2);
	COPY_HOOK(3);
	COPY_HOOK(4);
	COPY_HOOK(5);

	/* following code can't unroll, don't know why......:
	 *
	 * #pragma clang loop unroll(full)
	 * 	for (i = 0; i < 8; i++)
	 * 		COPY_HOOK(i);
	 */
out:
	EVENT_OUTPUT_PTR(ctx->regs, ctx->e, size);
	return 0;
}

static __always_inline int
bpf_qdisc_handle(context_t *ctx, struct Qdisc *q)
{
	struct netdev_queue *txq;
	unsigned long start;
	DECLARE_EVENT(qdisc_event_t, e)

	txq = _C(q, dev_queue);

	if (bpf_core_helper_exist(jiffies64))
	{
		start = _C(txq, trans_start);
		if (start)
			e->last_update = bpf_jiffies64() - start;
	}

	e->qlen = _C(&(q->q), qlen);
	e->state = _C(txq, state);
	e->flags = _C(q, flags);

	return handle_entry(ctx);
}

DEFINE_KPROBE_SKB(sch_direct_xmit, 1)
{
	struct Qdisc *q = nt_regs_ctx(ctx, 2);
	bpf_qdisc_handle(ctx, q);

	return 0;
}

DEFINE_KPROBE_SKB(pfifo_enqueue, 1)
{
	struct Qdisc *q = nt_regs_ctx(ctx, 2);
	bpf_qdisc_handle(ctx, q);

	return 0;
}

DEFINE_KPROBE_SKB(pfifo_fast_enqueue, 1)
{
	struct Qdisc *q = nt_regs_ctx(ctx, 2);
	bpf_qdisc_handle(ctx, q);

	return 0;
}

#ifndef NT_DISABLE_NFT

/* use the 'ignored suffix rule' feature of CO-RE, as described in:
 * https://nakryiko.com/posts/bpf-core-reference-guide/#handling-incompatible-field-and-type-changes
 */
struct nft_pktinfo___new
{
	struct sk_buff *skb;
	const struct nf_hook_state *state;
	u8 flags;
	u8 tprot;
	u16 fragoff;
	u16 thoff;
	u16 inneroff;
};

/**
 * This function is used to the kernel version that don't support
 * kernel module BTF.
 */
DEFINE_KPROBE_INIT(nft_do_chain, nft_do_chain, .arg_count = 2)
{
	struct nft_pktinfo *pkt = nt_regs_ctx(ctx, 1);
	void *chain_name, *table_name;
	struct nf_hook_state *state;
	struct nft_chain *chain;
	struct nft_table *table;
	size_t size;
	DECLARE_EVENT(nf_event_t, e)

	ctx->skb = (struct sk_buff *)_(pkt->skb);
	size = ctx->size;
	ctx->size = 0;
	// 采集到数据则直接返回
	if (handle_entry(ctx))
		return 0;

	if (bpf_core_type_exists(struct nft_pktinfo))
	{
		if (!bpf_core_field_exists(pkt->xt))
			state = _C((struct nft_pktinfo___new *)pkt, state);
		else
			state = _C(pkt, xt.state);
	}
	else
	{
		/* don't use CO-RE, as nft may be a module */
		state = _(pkt->xt.state);
	}

	chain = nt_regs_ctx(ctx, 2);
	if (bpf_core_type_exists(struct nft_chain))
	{
		table = _C(chain, table);
		chain_name = _C(chain, name);
		table_name = _C(table, name);
	}
	else
	{
		table = _(chain->table);
		chain_name = _(chain->name);
		table_name = _(table->name);
	}
	e->hook = _C(state, hook);
	e->pf = _C(state, pf);

	bpf_probe_read_kernel_str(e->chain, sizeof(e->chain), chain_name);
	bpf_probe_read_kernel_str(e->table, sizeof(e->table), table_name);

	EVENT_OUTPUT_PTR(ctx->regs, ctx->e, size);
	return 0;
}
#endif

/*******************************************************************
 *
 * Following is socket related custom BPF program.
 *
 *******************************************************************/

DEFINE_KPROBE_INIT(inet_listen, inet_listen,
				   .sk = _C((struct socket *)nt_regs(regs, 1), sk))
{
	return default_handle_entry(ctx);
}

char _license[] SEC("license") = "GPL";
