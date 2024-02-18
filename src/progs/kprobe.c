#define KBUILD_MODNAME ""
#include <kheaders.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_tracing.h>

#include "shared.h"
#include <skb_parse.h>

#include "kprobe_trace.h"

#define nt_regs(regs, index) (void *)PT_REGS_PARM##index((struct pt_regs *)regs)
#define nt_regs_ctx(ctx, index) nt_regs(ctx->regs, index)

/*
	使用宏定义虚函数：
	static try_inline int name(context_t *ctx, struct sk_buff *skb)
		name 根据用户传参定义
*/
#define __DECLARE_FAKE_FUNC(name, args...) \
	static try_inline int name(args)
#define DECLARE_FAKE_FUNC(name) \
	__DECLARE_FAKE_FUNC(name, context_t *ctx, struct sk_buff *skb)

/* one trace may have more than one implement */
/*
	宏函数实现 kprobe 和 kretprobe 函数，可针对入参定定义各种实现

	以  DEFINE_KPROBE_INIT(nft_do_chain, nft_do_chain, .arg_count = 2) 宏展开为例：

		static try_inline int fake__nft_do_chain(context_t *ctx, struct sk_buff *skb);
		SEC("kretprobe/nft_do_chain")
		int ret__trace_nft_do_chain(struct pt_regs *regs)
		{
			return handle_exit(regs, INDEX_nft_do_chain);
		}

		SEC("kprobe/nft_do_chain")
		int __trace_nft_do_chain(struct pt_regs *regs)
		{
			context_t ctx = {
				.func = INDEX_nft_do_chain,
				.regs = regs,
				.args = .arg_count = 2,
			};
			return fake__nft_do_chain(&ctx, ctx.skb);
		}
		// 此处用户可自定义虚函数的实现，在 kprobe 的 entry 实现自定义操作
		static try_inline int fake__nft_do_chain(context_t *ctx, struct sk_buff *skb)
		{

		}
*/
#define __DEFINE_KPROBE_INIT(name, target, ctx_init...) \
	DECLARE_FAKE_FUNC(fake__##name);                    \
	SEC("kretprobe/" #target)                           \
	int TRACE_RET_NAME(name)(struct pt_regs * regs)     \
	{                                                   \
		return handle_exit(regs, INDEX_##name);         \
	}                                                   \
	SEC("kprobe/" #target)                              \
	int TRACE_NAME(name)(struct pt_regs * regs)         \
	{                                                   \
		context_t ctx = {                               \
			.func = INDEX_##name,                       \
			.regs = regs,                               \
			.args = CONFIG(),                           \
			ctx_init};                                  \
		return fake__##name(&ctx, ctx.skb);             \
	}                                                   \
	DECLARE_FAKE_FUNC(fake__##name)

/* expand name and target sufficiently */
#define DEFINE_KPROBE_INIT(name, target, ctx_init...) \
	__DEFINE_KPROBE_INIT(name, target, ctx_init)

// DEFINE_KPROBE_SKB_SK 在 src/progs/core.h 中定义
#define KPROBE_DEFAULT(name, skb_index, sk_index, dummy) \
	DEFINE_KPROBE_SKB_SK(name, skb_index, sk_index)      \
	{                                                    \
		return default_handle_entry(ctx);                \
	}

#define DEFINE_TP_INIT(name, cata, tp, ctx_init...) \
	DECLARE_FAKE_FUNC(fake__##name);                \
	SEC("tp/" #cata "/" #tp)                        \
	int TRACE_NAME(name)(void *regs)                \
	{                                               \
		context_t ctx = {                           \
			.func = INDEX_##name,                   \
			.regs = regs,                           \
			.args = CONFIG(),                       \
			ctx_init};                              \
		return fake__##name(&ctx, ctx.skb);         \
	}                                               \
	DECLARE_FAKE_FUNC(fake__##name)
#define DEFINE_TP(name, cata, tp, offset) \
	DEFINE_TP_INIT(name, cata, tp,        \
				   .skb = *(void **)(regs + offset))
#define TP_DEFAULT(name, cata, tp, offset) \
	DEFINE_TP(name, cata, tp, offset)      \
	{                                      \
		return default_handle_entry(ctx);  \
	}
#define FNC(name)

static try_inline int handle_exit(struct pt_regs *regs, int func);
static try_inline void get_ret(int func);

#include "core.c"

/*
	针对 hook 点函数的 entry 计数
*/
static try_inline void get_ret(int func)
{
	int *ref = bpf_map_lookup_elem(&m_ret, &func);
	if (!ref)
		return;
	(*ref)++;
}

/*
	针对 hook 点函数的 exit 计数
*/
static try_inline int put_ret(int func)
{
	int *ref = bpf_map_lookup_elem(&m_ret, &func);
	if (!ref || *ref <= 0)
		return 1;
	(*ref)--;
	return 0;
}

static try_inline int handle_exit(struct pt_regs *regs, int func)
{
	retevent_t event = {
		.ts = bpf_ktime_get_ns(),
		.func = func,
		// PT_REGS_RC 获取 pt_regs rax 寄存器值，存放函数的返回值
		.val = PT_REGS_RC(regs),
	};

	// 查看 bpf_args_t 中 ready 值
	if (!ARGS_GET_CONFIG(ready) || put_ret(func))
		return 0;

	/*
		skb_clone 函数的作用是复制一个 sk_buff 结构，让新的 sk_buff
		对象与原对象共享相同的数据内容，但不共享结构，且新的对象的引用计数被设置为1
	*/
	if (func == INDEX_skb_clone)
	{
		bool matched = true;
		bpf_map_update_elem(&m_matched, &event.val, &matched, 0);
	}

	// bpf_perf_event_output 对数据进行输出
	EVENT_OUTPUT(regs, event);
	return 0;
}
