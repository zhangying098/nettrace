/*
 * The common part of parse skb and filter skb by specified condition.
 *
 * NOTE: This file can only be used in BPF program, can't be used in user
 * space code.
 */
#ifndef _H_BPF_SKB_UTILS
#define _H_BPF_SKB_UTILS

#ifndef COMPAT_MODE
#include <bpf/bpf_core_read.h>
#endif

#include "skb_macro.h"
#include "skb_shared.h"

// 控制条件 - 网络包 + 用户
typedef struct
{
	// 网络包过滤条件
	pkt_args_t pkt;
#ifdef BPF_DEBUG
	bool bpf_debug;
#endif
#ifdef DEFINE_BPF_ARGS
	// 数据采集行为控制条件
	DEFINE_BPF_ARGS();
#endif
} bpf_args_t;

#define MAX_ENTRIES 256

struct
{
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(int));
	__uint(value_size, sizeof(u32));
	__uint(max_entries, MAX_ENTRIES);
} m_event SEC(".maps");

struct
{
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(key_size, sizeof(int));
	__uint(value_size, sizeof(bpf_args_t));
	__uint(max_entries, 1);
} m_config SEC(".maps");

#ifndef BPF_NO_GLOBAL_DATA
const volatile bool bpf_func_exist[BPF_LOCAL_FUNC_MAX] = {0};
#define bpf_core_helper_exist(name) bpf_func_exist[BPF_LOCAL_FUNC_##name]
#else
#define bpf_core_helper_exist(name) false
#endif

/*
	获取控制条件 - 网络包 + 用户
*/
#define CONFIG() ({                                   \
	int _key = 0;                                     \
	void *_v = bpf_map_lookup_elem(&m_config, &_key); \
	if (!_v)                                          \
		return 0; /* this can't happen */             \
	(bpf_args_t *)_v;                                 \
})

#define EVENT_OUTPUT_PTR(ctx, data, size)                   \
	bpf_perf_event_output(ctx, &m_event, BPF_F_CURRENT_CPU, \
						  data, size)
#define EVENT_OUTPUT(ctx, data) \
	EVENT_OUTPUT_PTR(ctx, &data, sizeof(data))

#define _(src)                                            \
	({                                                    \
		typeof(src) tmp;                                  \
		bpf_probe_read_kernel(&tmp, sizeof(src), &(src)); \
		tmp;                                              \
	})

#undef _C
#ifdef COMPAT_MODE
// 使用 bpf_probe_read_kernel 读取变量值
#define _C(src, a) _((src)->a)
#else
// 使用 BPF_CORE_READ 读取变量值
#define _C(src, a, ...) BPF_CORE_READ(src, a, ##__VA_ARGS__)
#endif

#ifdef COMPAT_MODE
#define try_inline __always_inline
#else
#define try_inline inline
#endif

#ifdef BPF_DEBUG
#define pr_bpf_debug(fmt, args...)                     \
	{                                                  \
		if (ARGS_GET_CONFIG(bpf_debug))                \
			bpf_printk("nettrace: " fmt "\n", ##args); \
	}
#else
#define pr_bpf_debug(fmt, ...)
#endif
#define pr_debug_skb(fmt, ...) \
	pr_bpf_debug("skb=%llx, " fmt, (u64)(void *)skb, ##__VA_ARGS__)

/*
	CONFIG() 获取控制条件 - 网络包 + 用户侧
	ARGS_GET_CONFIG 功能
		根据 name 获取 bpf_args_t 中的对应成员的值
*/
#define ARGS_GET_CONFIG(name) ((bpf_args_t *)CONFIG())->name

typedef struct
{
	u64 pad;
	u64 skb;
	u64 location;
	u16 prot;
	u32 reason;
} kfree_skb_t;

typedef struct
{
	void *data;
	pkt_args_t *args;
	union
	{
		struct sk_buff *skb;
		struct sock *sk;
	};
	union
	{
		packet_t *pkt;
		sock_t *ske;
	};
	u16 mac_header;
	u16 network_header;
	u16 trans_header;
	bool filter;
} parse_ctx_t;

#define TCP_H_LEN (sizeof(struct tcphdr))
#define UDP_H_LEN (sizeof(struct udphdr))
#define IP_H_LEN (sizeof(struct iphdr))
#define ICMP_H_LEN (sizeof(struct icmphdr))

#define ETH_TOTAL_H_LEN (sizeof(struct ethhdr))
#define IP_TOTAL_H_LEN (ETH_TOTAL_H_LEN + IP_H_LEN)
#define TCP_TOTAL_H_LEN (IP_TOTAL_H_LEN + TCP_H_LEN)
#define UDP_TOTAL_H_LEN (IP_TOTAL_H_LEN + UDP_H_LEN)
#define ICMP_TOTAL_H_LEN (IP_TOTAL_H_LEN + ICMP_H_LEN)

#define IP_CSUM_OFFSET (ETH_TOTAL_H_LEN + offsetof(struct iphdr, check))

#define SKB_END(skb) ((void *)(long)skb->data_end)
#define SKB_DATA(skb) ((void *)(long)skb->data)
#define SKB_CHECK_IP(skb) \
	(SKB_DATA(skb) + IP_TOTAL_H_LEN > SKB_END(skb))
#define SKB_CHECK_TCP(skb) \
	(SKB_DATA(skb) + TCP_TOTAL_H_LEN > SKB_END(skb))
#define SKB_CHECK_UDP(skb) \
	(SKB_DATA(skb) + UDP_TOTAL_H_LEN > SKB_END(skb))
#define SKB_CHECK_ICMP(skb) \
	(SKB_DATA(skb) + ICMP_TOTAL_H_LEN > SKB_END(skb))
#define SKB_HDR_IP(skb) \
	(SKB_DATA(skb) + ETH_TOTAL_H_LEN)

#define IS_PSEUDO 0x10

static try_inline u8 get_ip_header_len(u8 h)
{
	u8 len = (h & 0x0F) * 4;
	return len > IP_H_LEN ? len : IP_H_LEN;
}

static try_inline void *load_l4_hdr(struct __sk_buff *skb, struct iphdr *ip, void *dst,
									__u32 len)
{
	__u32 offset, iplen;
	void *l4;

	iplen = get_ip_header_len(((u8 *)ip)[0]);
	offset = ETH_TOTAL_H_LEN + (iplen > IP_H_LEN ? iplen : IP_H_LEN);
	l4 = SKB_DATA(skb) + offset;

	if (l4 + len > SKB_END(skb))
	{
		if (bpf_skb_load_bytes(skb, offset, dst, len))
			return NULL;
		return dst;
	}
	return l4;
}

/* check if the skb contains L2 head (mac head) */
// 检查一个 skb 是否包含 L2 头（mac 头）
static try_inline bool skb_l2_check(u16 header)
{
	return !header || header == (u16)~0U;
}

static try_inline bool skb_l4_check(u16 l4, u16 l3)
{
	return l4 == 0xFFFF || l4 <= l3;
}

/* used to iter some filter args, such as saddr/daddr/addr and
 * sport/dport/port
 */
#define FILTER_ITER_OPS(args, attr, svalue, dvalue, ops) \
	((ops(args, attr, (dvalue)) && ops(args, attr,       \
									   (svalue))) ||     \
	 ops(args, s##attr, (svalue)) ||                     \
	 ops(args, d##attr, (dvalue)))
#define FILTER_OPS_ENABLED(args, name, value) \
	ARGS_ENABLED(args, name)
#define FILTER_ITER_ENABLED(ctx, attr) \
	(ctx->filter && FILTER_ITER_OPS(ctx->args, attr, , , FILTER_OPS_ENABLED))
#define FILTER_ITER_CHECK(ctx, attr, svalue, dvalue) \
	(ctx->filter && FILTER_ITER_OPS(ctx->args, attr, svalue, dvalue, ARGS_CHECK))
#define FILTER_OPS_IPV6_EQUEL(args, name, value) ({         \
	int rc = 0;                                             \
	if (ARGS_ENABLED(args, name))                           \
	{                                                       \
		u8 *__src = args->name;                             \
		u8 *__target = value;                               \
		rc = *(u64 *)__src != *(u64 *)__target ||           \
			 *(u64 *)(__src + 8) != *(u64 *)(__target + 8); \
	}                                                       \
	rc;                                                     \
})
#define FILTER_ITER_IPV6(ctx, svalue, dvalue)                   \
	(ctx->filter && FILTER_ITER_OPS(ctx->args, addr_v6, svalue, \
									dvalue, FILTER_OPS_IPV6_EQUEL))
#define FILTER_CHECK(ctx, attr, value) \
	(ctx->filter && ARGS_CHECK(ctx->args, attr, value))
#define FILTER_ENABLED(ctx, attr) \
	(ctx->filter && ARGS_ENABLED(ctx->args, attr))

/*
	对输入的 IP 数据包进行解析，提取其中的关键信息，并根据用户设置过滤条件进行判断和处理。
	函数的结构比较复杂，包括了对 IPv4 和 IPv6 协议的处理，以及对不同传输层协议（如 TCP
	、UDP、ICMP、ESP）的解析和过滤
*/
static try_inline int probe_parse_ip(void *ip, parse_ctx_t *ctx)
{
	packet_t *pkt = ctx->pkt;
	void *l4 = NULL;

	if (!skb_l4_check(ctx->trans_header, ctx->network_header))
		l4 = ctx->data + ctx->trans_header;

	if (pkt->proto_l3 == ETH_P_IPV6)
	{
		struct ipv6hdr *ipv6 = ip;

		/* ipv4 address is set, skip ipv6 */
		if (FILTER_ITER_ENABLED(ctx, addr))
			goto err;

		// 读取原地址和目的地址
		bpf_probe_read_kernel(pkt->l3.ipv6.saddr,
							  sizeof(ipv6->saddr),
							  &ipv6->saddr);
		bpf_probe_read_kernel(pkt->l3.ipv6.daddr,
							  sizeof(ipv6->daddr),
							  &ipv6->daddr);

		// 根据用户条件过滤原地址和目的地址过滤
		if (FILTER_ITER_IPV6(ctx, pkt->l3.ipv6.saddr,
							 pkt->l3.ipv6.daddr))
			goto err;

		pkt->proto_l4 = _(ipv6->nexthdr);
		l4 = l4 ?: ip + sizeof(*ipv6);
	}
	else
	{
		struct iphdr *ipv4 = ip;
		u32 saddr, daddr, len;

		// 根据用户设置的报文长度进行过滤
		len = bpf_ntohs(_C(ipv4, tot_len));
		if (FILTER_ENABLED(ctx, pkt_len_1))
		{
			if (len < ARGS_GET(ctx->args, pkt_len_1) ||
				len > ARGS_GET(ctx->args, pkt_len_2))
				goto err;
		}

		/* skip ipv4 if ipv6 is set */
		if (FILTER_ITER_ENABLED(ctx, addr_v6))
			goto err;

		l4 = l4 ?: ip + get_ip_header_len(_(((u8 *)ip)[0]));
		saddr = _(ipv4->saddr);
		daddr = _(ipv4->daddr);

		if (FILTER_ITER_CHECK(ctx, addr, saddr, daddr))
			goto err;

		pkt->proto_l4 = _(ipv4->protocol);
		pkt->l3.ipv4.saddr = saddr;
		pkt->l3.ipv4.daddr = daddr;
	}

	if (FILTER_CHECK(ctx, l4_proto, pkt->proto_l4))
		goto err;

	// 根据传输层协议进行信息采集
	/*
		tcp udp icmp
		ESP协议：
			IP Encapsulating Security Payload（ESP）协议
				是一种网络层安全协议，通常用于在 IP 数据包中提供加密和认证服务。
				ESP 协议通常与 IPsec（IP Security）协议套件一起使用，用于保护
				数据包的隐私性、完整性和身份验证。
	*/
	switch (pkt->proto_l4)
	{
	case IPPROTO_TCP:
	{
		struct tcphdr *tcp = l4;
		u16 sport = _(tcp->source);
		u16 dport = _(tcp->dest);
		u8 flags;

		if (FILTER_ITER_CHECK(ctx, port, sport, dport))
			goto err;

		flags = _(((u8 *)tcp)[13]);
		if (FILTER_ENABLED(ctx, tcp_flags) &&
			!(flags & ARGS_GET(ctx->args, tcp_flags)))
			goto err;

		pkt->l4.tcp.sport = sport;
		pkt->l4.tcp.dport = dport;
		pkt->l4.tcp.flags = flags;
		pkt->l4.tcp.seq = _(tcp->seq);
		pkt->l4.tcp.ack = _(tcp->ack_seq);
		break;
	}
	case IPPROTO_UDP:
	{
		struct udphdr *udp = l4;
		u16 sport = _(udp->source);
		u16 dport = _(udp->dest);

		if (FILTER_ITER_CHECK(ctx, port, sport, dport))
			goto err;

		pkt->l4.udp.sport = sport;
		pkt->l4.udp.dport = dport;
		break;
	}
	case IPPROTO_ICMPV6:
	case IPPROTO_ICMP:
	{
		struct icmphdr *icmp = l4;

		if (FILTER_ITER_ENABLED(ctx, port))
			goto err;
		pkt->l4.icmp.code = _(icmp->code);
		pkt->l4.icmp.type = _(icmp->type);
		pkt->l4.icmp.seq = _(icmp->un.echo.sequence);
		pkt->l4.icmp.id = _(icmp->un.echo.id);
		break;
	}
	case IPPROTO_ESP:
	{
		struct ip_esp_hdr *esp_hdr = l4;
		if (FILTER_ITER_ENABLED(ctx, port))
			goto err;
		pkt->l4.espheader.seq = _(esp_hdr->seq_no);
		pkt->l4.espheader.spi = _(esp_hdr->spi);
		break;
	}
	default:
		// 用户设置的端口校验
		if (FILTER_ITER_ENABLED(ctx, port))
			goto err;
	}
	return 0;
err:
	return -1;
}

#if !defined(COMPAT_MODE) || defined(BPF_FEAT_SK_PRPTOCOL_LEGACY)
static __always_inline u8 sk_get_protocol(struct sock *sk)
{
	u32 flags = _(((u32 *)(&sk->__sk_flags_offset))[0]);
	u8 l4_proto;

#ifdef CONFIG_CPU_BIG_ENDIAN
	l4_proto = (flags << 8) >> 24;
#else
	l4_proto = (flags << 16) >> 24;
#endif
	return l4_proto;
}
#endif

static try_inline int __probe_parse_sk(parse_ctx_t *ctx)
{
	struct inet_connection_sock *icsk;
	struct sock *sk = ctx->sk;
	struct sock_common *skc;
	sock_t *ske = ctx->ske;
	u16 l3_proto;
	u8 l4_proto;

	skc = (struct sock_common *)sk;
	/*
		struct sock_common 中的 skc_family 字段表示套接字（socket）的地址族（address family）。
		地址族是指套接字所使用的协议族，用于指示套接字地址的格式和含义。常见的地址族包括 AF_INET
		（IPv4 地址族）和 AF_INET6（IPv6 地址族）
	*/
	switch (_C(skc, skc_family))
	{
	case AF_INET:
		l3_proto = ETH_P_IP;
		ske->l3.ipv4.saddr = _C(skc, skc_rcv_saddr);
		ske->l3.ipv4.daddr = _C(skc, skc_daddr);
		if (FILTER_ITER_CHECK(ctx, addr, ske->l3.ipv4.saddr,
							  ske->l3.ipv4.daddr))
			goto err;
		break;
	case AF_INET6:
		l3_proto = ETH_P_IPV6;
		break;
	default:
		/* shouldn't happen, as we only use sk for IP and
		 * IPv6
		 */
		goto err;
	}
	if (FILTER_CHECK(ctx, l3_proto, l3_proto))
		goto err;

#ifdef COMPAT_MODE
#ifdef BPF_FEAT_SK_PRPTOCOL_LEGACY
	l4_proto = sk_get_protocol(sk);
#else
	l4_proto = _C(sk, sk_protocol);
#endif
#else
	// bpf_core_field_size 计算该字段占用空间字节数
	if (bpf_core_field_size(sk->sk_protocol) == 2)
		l4_proto = _C(sk, sk_protocol);
	else
		l4_proto = sk_get_protocol(sk);
#endif

	if (l4_proto == IPPROTO_IP)
		l4_proto = IPPROTO_TCP;

	if (FILTER_CHECK(ctx, l4_proto, l4_proto))
		goto err;

	// 针对 TCP 和 UDP 协议信息的进一步捕获
	switch (l4_proto)
	{
	case IPPROTO_TCP:
	{
		struct tcp_sock *tp = (void *)sk;

		if (bpf_core_type_exists(struct tcp_sock))
		{
			ske->l4.tcp.packets_out = _C(tp, packets_out);
			ske->l4.tcp.retrans_out = _C(tp, retrans_out);
		}
	}
	case IPPROTO_UDP:
		ske->l4.min.sport = bpf_htons(_C(skc, skc_num));
		ske->l4.min.dport = _C(skc, skc_dport);
		break;
	default:
		break;
	}

	if (FILTER_ITER_CHECK(ctx, port, ske->l4.tcp.sport,
						  ske->l4.tcp.dport))
		goto err;

	ske->rqlen = _C(sk, sk_receive_queue.qlen);
	ske->wqlen = _C(sk, sk_write_queue.qlen);

	ske->proto_l3 = l3_proto;
	ske->proto_l4 = l4_proto;
	ske->state = _C(skc, skc_state);

	if (!bpf_core_type_exists(struct inet_connection_sock))
		return 0;

	icsk = (void *)sk;
	bpf_probe_read_kernel(&ske->ca_state, sizeof(u8),
						  (u8 *)icsk +
							  bpf_core_field_offset(struct inet_connection_sock,
													icsk_retransmits) -
							  1);

	if (bpf_core_helper_exist(jiffies64))
		ske->timer_out = _C(icsk, icsk_timeout) - (unsigned long)bpf_jiffies64();

	ske->timer_pending = _C(icsk, icsk_pending);

	return 0;
err:
	return -1;
}

/*
	解析 skb 数据包，提取包类型，并根据包类型进行数据包信息提取
*/
static try_inline int __probe_parse_skb(parse_ctx_t *ctx)
{
	struct sk_buff *skb = ctx->skb;
	packet_t *pkt = ctx->pkt;
	u16 l3_proto;
	void *l3;

	// 获取网络层头部数据
	ctx->network_header = _C(skb, network_header);
	// 获取链路层头部数据
	ctx->mac_header = _C(skb, mac_header);
	// 获取缓冲区头部数据
	ctx->data = _C(skb, head);

	pr_debug_skb("begin to parse, nh=%d mh=%d", ctx->network_header,
				 ctx->mac_header);
	pr_debug_skb("th=%d", _C(skb, transport_header));

	/*
		检查数据链路层头部是否存在，如果不存在则进行处理

		数据链路层头部不存在的情况主要包括以下几种情形:
			虚拟网卡设备（如 TUN/TAP 设备）：
				对于一些虚拟网卡设备，可能在数据包中并不包含真实的数据链路层头部信息，
				而是直接从网络层开始传输数据。网络数据包通过虚拟网卡设备从一个端点传
				输到另一个端点，而不需要经过物理网络接口。因此，数据包直接从网络层开
				始传输，绕过了数据链路层。对于接收方，虚拟网卡设备可以根据网络层协议
				类型（如 IPv4 或 IPv6）和网络层头部的信息，将数据包重新封装到相应的
				数据链路层协议中，以便正确地传递给应用程序或其他网络设备。
			隧道（Tunneling）技术：
				在网络通信中，隧道技术会在原始数据包的基础上封装新的数据包，这个过程
				可能会导致数据链路层头部被隐藏或替换
			特殊网络环境下的数据封装：
				在某些特殊的网络环境中，可能会对数据包进行特殊的封装处理，导致数据链
				路层头部信息不可见或被修改。
	*/
	if (skb_l2_check(ctx->mac_header))
	{
		/*
		 * try to parse skb for send path, which means that
		 * ether header doesn't exist in skb.
		 */
		// bpf_ntohs 函数将网络字节序，转为主机字节序， skb->protocol 数据链路层协议类型, 例如以太网帧、IPV4 数据包、ARP 数据包等
		l3_proto = bpf_ntohs(_C(skb, protocol));
		if (!l3_proto)
			goto err;
		/*
			如果网络层头部偏移量为 0，则跳转到错误处理逻辑
				可能是因为数据包损坏、格式错误或者不符合预期的数据包结构导致的
		*/
		if (!ctx->network_header)
			goto err;
		// 计算指向网络层头部数据的指针
		l3 = ctx->data + ctx->network_header;
	}
	// 如果链路层头部与网络层头部相同，则表示数据包是 IP 数据包
	else if (ctx->mac_header == ctx->network_header)
	{
		/* to tun device, mac header is the same to network header.
		 * For this case, we assume that this is a IP packet.
		 */
		// 指向网络层头部数据的指针为头部数据的偏移量
		l3 = ctx->data + ctx->network_header;
		// 标识为 IP 协议
		l3_proto = ETH_P_IP;
	}
	else
	{
		/* mac header is set properly, we can use it directly. */
		// 指向以太网帧头部的指针
		struct ethhdr *eth = ctx->data + ctx->mac_header;

		l3 = (void *)eth + ETH_HLEN;
		// 确认以太网上层协议类型
		l3_proto = bpf_ntohs(_(eth->h_proto));
	}

	// 用户设置过滤条件校验
	if (FILTER_CHECK(ctx, l3_proto, l3_proto))
		goto err;

	// 获取传输层头部数据
	ctx->trans_header = _C(skb, transport_header);
	// 设置协议类型
	pkt->proto_l3 = l3_proto;
	pr_debug_skb("l3=%d", l3_proto);

	// 根据协议类型进行相关处理
	switch (l3_proto)
	{
	case ETH_P_IPV6:
	case ETH_P_IP:
		return probe_parse_ip(l3, ctx);
	default:
		if (FILTER_ENABLED(ctx, l4_proto))
			goto err;
		return 0;
	}
err:
	return -1;
}

static try_inline int probe_parse_skb(struct sk_buff *skb, packet_t *pkt)
{
	parse_ctx_t ctx = {
		.args = (void *)CONFIG(),
		.filter = true,
		.skb = skb,
		.pkt = pkt,
	};
	return __probe_parse_skb(&ctx);
}

static try_inline int probe_parse_sk(struct sock *sk, sock_t *ske)
{
	parse_ctx_t ctx = {
		.args = (void *)CONFIG(),
		.filter = true,
		.ske = ske,
		.sk = sk,
	};
	return __probe_parse_sk(&ctx);
}

/*
	解析数据包，根据数据包类型提取相关的数据信息
*/
static try_inline int probe_parse_skb_always(struct sk_buff *skb,
											 packet_t *pkt)
{
	// 封装 skb 和 pkt，初始化包过滤条件 args，设置过滤不使能
	parse_ctx_t ctx = {
		.args = (void *)CONFIG(),
		.filter = false,
		.skb = skb,
		.pkt = pkt,
	};
	return __probe_parse_skb(&ctx);
}

static try_inline int direct_parse_skb(struct __sk_buff *skb, packet_t *pkt,
									   pkt_args_t *bpf_args)
{
	struct ethhdr *eth = SKB_DATA(skb);
	struct iphdr *ip = (void *)(eth + 1);

	if ((void *)ip > SKB_END(skb))
		goto err;

	if (bpf_args && (ARGS_CHECK(bpf_args, l3_proto, eth->h_proto)))
		goto err;

	pkt->proto_l3 = bpf_ntohs(eth->h_proto);
	if (SKB_CHECK_IP(skb))
		goto err;

	if (bpf_args && (ARGS_CHECK(bpf_args, l4_proto, ip->protocol) ||
					 ARGS_CHECK(bpf_args, saddr, ip->saddr) ||
					 ARGS_CHECK(bpf_args, daddr, ip->daddr)))
		goto err;

	l4_min_t *l4_p = (void *)(ip + 1);
	struct tcphdr *tcp = (void *)l4_p;

	switch (ip->protocol)
	{
	case IPPROTO_UDP:
		if (SKB_CHECK_UDP(skb))
			goto err;
		goto fill_port;
	case IPPROTO_TCP:
		if (SKB_CHECK_TCP(skb))
			goto err;

		pkt->l4.tcp.flags = ((u8 *)tcp)[13];
		pkt->l4.tcp.ack = tcp->ack_seq;
		pkt->l4.tcp.seq = tcp->seq;
	fill_port:
		pkt->l4.min = *l4_p;
		break;
	case IPPROTO_ICMP:
	{
		struct icmphdr *icmp = (void *)l4_p;
		if (SKB_CHECK_ICMP(skb))
			goto err;

		pkt->l4.icmp.code = icmp->code;
		pkt->l4.icmp.type = icmp->type;
		pkt->l4.icmp.seq = icmp->un.echo.sequence;
		pkt->l4.icmp.id = icmp->un.echo.id;
	}
	default:
		goto out;
	}

	if (bpf_args && (ARGS_CHECK(bpf_args, sport, l4_p->sport) ||
					 ARGS_CHECK(bpf_args, dport, l4_p->dport)))
		return 1;

	pkt->l3.ipv4.saddr = ip->saddr;
	pkt->l3.ipv4.daddr = ip->daddr;
	pkt->proto_l4 = ip->protocol;
	pkt->proto_l3 = ETH_P_IP;
	pkt->ts = bpf_ktime_get_ns();

out:
	return 0;
err:
	return 1;
}

#endif
