/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2022 Ginzado Co., Ltd.
 */

#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <inttypes.h>
#include <getopt.h>
#include <signal.h>

#include <sys/time.h>
#include <sys/un.h>

#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_cycles.h>
#include <rte_lcore.h>
#include <rte_mbuf.h>

#define RX_RING_SIZE 1024
#define TX_RING_SIZE 1024

#define NUM_MBUFS 8191
#define MBUF_CACHE_SIZE 250
#define BURST_SIZE 32

#define OPTION_CONFIG "config"

#define GPW_ETHTYPE 0x96fc
#define GPW_PROTO 0xfc

#define GPW_FRAGSIZE 1280

struct rte_mempool *mbuf_pool = NULL;

char *config = NULL;

unsigned lcoreid_main = LCORE_ID_ANY;
unsigned lcoreid_ul = LCORE_ID_ANY;
unsigned lcoreid_dl = LCORE_ID_ANY;

#define GPW_PORT_UL 1
#define GPW_PORT_DL 0

struct rte_ether_addr ethaddr_ul;
struct rte_ether_addr ethaddr_dl;

#define GPW_MODE_ETH 1
#define GPW_MODE_IP6 2

int gpw_mode = -1;

struct rte_ether_addr eth_dstaddr;

struct rte_ether_addr ip6_dstmac;
uint8_t ip6_dstaddr[16];
uint8_t ip6_srcaddr[16];

#define INTERNAL_RING_SIZE 256

struct rte_ring *ring_ul2main;
struct rte_ring *ring_dl2main;

struct gpw_eth_hdr {
	struct rte_ether_hdr eth_hdr;
	uint16_t id;
} __attribute__((__packed__));

struct gpw_eth_hdr eth_hdr_cork;

struct gpw_ip6_hdr {
	struct rte_ether_hdr eth_hdr;
	struct rte_ipv6_hdr ip6_hdr;
	uint16_t id;
} __attribute__((__packed__));

struct gpw_ip6_hdr ip6_hdr_cork;

int ip6_ready = false;

#define GPWSTATS_UNIX_SOCKET_PATH "/run/gpwstats.socket"

#define GPW_CLIENT_MAX 4
int serverfd = -1;
int clientfds[GPW_CLIENT_MAX] = { -1, -1, -1, -1, };
struct sockaddr_un serversa;

struct gpwstats {
	uint64_t ul_rx_packets;
	uint64_t ul_rx_bytes;
	uint64_t ul_rx_bpdus;
	uint64_t ul_tx_packets;
	uint64_t ul_tx_bytes;
	uint64_t ul_tx_errors;
	uint64_t dl_rx_packets;
	uint64_t dl_rx_bytes;
	uint64_t dl_rx_bpdus;
	uint64_t dl_tx_packets;
	uint64_t dl_tx_bytes;
	uint64_t dl_tx_errors;
} gpwstats = {
	.ul_rx_packets = 0,
	.ul_rx_bytes = 0,
	.ul_rx_bpdus = 0,
	.ul_tx_packets = 0,
	.ul_tx_bytes = 0,
	.ul_tx_errors = 0,
	.dl_rx_packets = 0,
	.dl_rx_bytes = 0,
	.dl_rx_bpdus = 0,
	.dl_tx_packets = 0,
	.dl_tx_bytes = 0,
	.dl_tx_errors = 0,
};

#define PROTO_ICMP6 58

struct icmp6_hdr {
	uint8_t type;
	uint8_t code;
	uint16_t cksum;
} __attribute__((__packed__));

#define ICMP6_RA 134
#define ICMP6_NS 135
#define ICMP6_NA 136

#define OPT_SOURCE_LINKADDR 1
#define OPT_TARGET_LINKADDR 2
#define OPT_PREFIX_INFORMATION 3

struct icmp6_opt_hdr {
	uint8_t opt_type;
	uint8_t opt_len;
} __attribute__((__packed__));

struct icmp6_ns {
	struct icmp6_hdr icmp6_hdr;
	uint32_t reserved;
	uint8_t target[16];
} __attribute__((__packed__));

struct icmp6_na {
	struct icmp6_hdr icmp6_hdr;
	uint32_t flags_reserved;
	uint8_t target[16];
} __attribute__((__packed__));

#define NA_FLAG_SOLICITED 0x40000000
#define NA_FLAG_OVERRIDE 0x20000000

struct icmp6_ra {
	struct icmp6_hdr icmp6_hdr;
	uint8_t curhoplimit;
	uint8_t flags;
	uint16_t reserved;
	uint32_t reachable;
	uint32_t retransmit;
} __attribute__((__packed__));

struct icmp6_opt_source_linkaddr {
	struct icmp6_opt_hdr icmp6_opt_hdr;
	uint8_t source_linkaddr[6];
} __attribute__((__packed__));

struct icmp6_opt_target_linkaddr {
	struct icmp6_opt_hdr icmp6_opt_hdr;
	uint8_t target_linkaddr[6];
} __attribute__((__packed__));

struct icmp6_opt_prefix_info {
	struct icmp6_opt_hdr icmp6_opt_hdr;
	uint8_t prefix_len;
	uint8_t flags_reserved;
	uint32_t valid_time;
	uint32_t preferred_time;
	uint32_t reserved2;
	uint8_t prefix[16];
} __attribute__((__packed__));

static int
is_icmp6(struct rte_mbuf *buf)
{
	struct rte_ether_hdr *eth_hdr;
	struct rte_ipv6_hdr *ip6_hdr;
	eth_hdr = (struct rte_ether_hdr *)((char *)buf->buf_addr + buf->data_off);
	if (eth_hdr->ether_type != rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV6))
		return false;
	ip6_hdr = (struct rte_ipv6_hdr *)(eth_hdr + 1);
	if (ip6_hdr->proto != PROTO_ICMP6)
		return false;
	printf("********** ipv6-icmp ************\n");
	return true;
}

static void
handle_icmp6_ra(struct rte_mbuf *buf)
{
	struct rte_ether_hdr *eth_hdr = (struct rte_ether_hdr *)((char *)buf->buf_addr + buf->data_off);
	struct rte_ipv6_hdr *ip6_hdr = (struct rte_ipv6_hdr *)(eth_hdr + 1);
	struct icmp6_ra *icmp6_ra = (struct icmp6_ra *)(ip6_hdr + 1);
	struct icmp6_opt_hdr *opt_hdr = (struct icmp6_opt_hdr *)(icmp6_ra + 1);
	printf("**** type = %d code = %d cksum = 0x%04x\n",
			icmp6_ra->icmp6_hdr.type, icmp6_ra->icmp6_hdr.code, icmp6_ra->icmp6_hdr.cksum);
	printf("**** curhoplimit = %d flags = %02x\n",
			icmp6_ra->curhoplimit, icmp6_ra->flags);
	printf("**** reachable = %d retransmit = %d\n", icmp6_ra->reachable, icmp6_ra->retransmit);
	printf("**** pkt_len = %d data_len = %d\n", buf->pkt_len, buf->data_len);
	printf("**** remaining = %ld\n", buf->data_len - sizeof(struct rte_ether_hdr) - sizeof(struct rte_ipv6_hdr)
			- sizeof(struct icmp6_ra));
	long remaining = buf->data_len
		- sizeof(struct rte_ether_hdr) - sizeof(struct rte_ipv6_hdr) - sizeof(struct icmp6_ra);
	struct icmp6_opt_source_linkaddr *source_linkaddr = NULL;
	struct icmp6_opt_prefix_info *prefix_info = NULL;
	while (remaining > 0) {
		switch (opt_hdr->opt_type) {
		case OPT_SOURCE_LINKADDR:
			source_linkaddr = (struct icmp6_opt_source_linkaddr *)opt_hdr;
			break;
		case OPT_PREFIX_INFORMATION:
			prefix_info = (struct icmp6_opt_prefix_info *)opt_hdr;
			break;
		}
		remaining -= opt_hdr->opt_len * 8;
		opt_hdr = (struct icmp6_opt_hdr *)((char *)opt_hdr + (opt_hdr->opt_len * 8));
	}
	if (source_linkaddr == NULL || prefix_info == NULL)
		return;
	if (memcmp(ip6_dstmac.addr_bytes, source_linkaddr->source_linkaddr, 6) == 0)
		return;
	if (memcmp(ip6_srcaddr, prefix_info->prefix, 8) != 0)
		return;
	memcpy(ip6_dstmac.addr_bytes, source_linkaddr->source_linkaddr, 6);
	memcpy(&ip6_hdr_cork.eth_hdr.dst_addr, &ip6_dstmac, sizeof(struct rte_ether_addr));
	ip6_ready = true;
	printf("#### ip6_ready ####\n");
}

static void
handle_icmp6_ns(struct rte_mbuf *buf)
{
	struct rte_ether_hdr *eth_hdr = (struct rte_ether_hdr *)((char *)buf->buf_addr + buf->data_off);
	struct rte_ipv6_hdr *ip6_hdr = (struct rte_ipv6_hdr *)(eth_hdr + 1);
	struct icmp6_ns *icmp6_ns = (struct icmp6_ns *)(ip6_hdr + 1);
	struct icmp6_opt_hdr *opt_hdr = (struct icmp6_opt_hdr *)(icmp6_ns + 1);
	long remaining = buf->data_len
		- sizeof(struct rte_ether_hdr) - sizeof(struct rte_ipv6_hdr) - sizeof(struct icmp6_ns);
	struct icmp6_opt_source_linkaddr *source_linkaddr = NULL;
	while (remaining > 0) {
		switch (opt_hdr->opt_type) {
		case OPT_SOURCE_LINKADDR:
			source_linkaddr = (struct icmp6_opt_source_linkaddr *)opt_hdr;
			break;
		}
		remaining -= opt_hdr->opt_len * 8;
		opt_hdr = (struct icmp6_opt_hdr *)((char *)opt_hdr + (opt_hdr->opt_len * 8));
	}

	if (source_linkaddr == NULL)
		return;
	if (memcmp(icmp6_ns->target, ip6_srcaddr, 16) != 0)
		return;

	struct rte_mbuf *na_buf = rte_pktmbuf_alloc(mbuf_pool);
	if (unlikely(na_buf == NULL))
		return;
	struct rte_ether_hdr *na_eth_hdr = (struct rte_ether_hdr *)rte_pktmbuf_prepend(na_buf,
			sizeof(struct rte_ether_hdr));
	if (unlikely(na_eth_hdr == NULL)) {
		rte_pktmbuf_free(na_buf);
		return;
	}
	memcpy(na_eth_hdr->dst_addr.addr_bytes, source_linkaddr->source_linkaddr, 6);
	memcpy(&na_eth_hdr->src_addr, &ethaddr_ul, sizeof(struct rte_ether_addr));
	na_eth_hdr->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV6);
	struct rte_ipv6_hdr *na_ip6_hdr = (struct rte_ipv6_hdr *)rte_pktmbuf_append(na_buf,
			sizeof(struct rte_ipv6_hdr));
	if (unlikely(na_ip6_hdr == NULL)) {
		rte_pktmbuf_free(na_buf);
		return;
	}
	na_ip6_hdr->vtc_flow = rte_cpu_to_be_32(0x60000000);
	na_ip6_hdr->payload_len = rte_cpu_to_be_16(sizeof(struct icmp6_na) + sizeof(struct icmp6_opt_target_linkaddr));
	na_ip6_hdr->proto = PROTO_ICMP6;
	na_ip6_hdr->hop_limits = 255;
	memcpy(na_ip6_hdr->src_addr, ip6_srcaddr, 16);
	memcpy(na_ip6_hdr->dst_addr, ip6_hdr->src_addr, 16);
	struct icmp6_na *icmp6_na = (struct icmp6_na *)rte_pktmbuf_append(na_buf, sizeof(struct icmp6_na));
	if (unlikely(icmp6_na == NULL)) {
		rte_pktmbuf_free(na_buf);
		return;
	}
	icmp6_na->icmp6_hdr.type = ICMP6_NA;
	icmp6_na->icmp6_hdr.code = 0;
	icmp6_na->icmp6_hdr.cksum = 0;
	icmp6_na->flags_reserved = rte_cpu_to_be_32(NA_FLAG_SOLICITED|NA_FLAG_OVERRIDE);
	memcpy(icmp6_na->target, ip6_srcaddr, 16);
	struct icmp6_opt_target_linkaddr *na_target_linkaddr = (struct icmp6_opt_target_linkaddr *)
		rte_pktmbuf_append(na_buf, sizeof(struct icmp6_opt_target_linkaddr));
	if (unlikely(na_target_linkaddr == NULL)) {
		rte_pktmbuf_free(na_buf);
		return;
	}
	na_target_linkaddr->icmp6_opt_hdr.opt_type = OPT_TARGET_LINKADDR;
	na_target_linkaddr->icmp6_opt_hdr.opt_len = 1;
	memcpy(na_target_linkaddr->target_linkaddr, ethaddr_ul.addr_bytes, 6);
	icmp6_na->icmp6_hdr.cksum = rte_ipv6_udptcp_cksum(na_ip6_hdr, icmp6_na);
	const uint16_t nb_tx = rte_eth_tx_burst(GPW_PORT_UL, 1, &na_buf, 1);
	if (unlikely(nb_tx == 0))
		rte_pktmbuf_free(na_buf);
}

static void
handle_icmp6(struct rte_mbuf *buf)
{
	struct rte_ether_hdr *eth_hdr = (struct rte_ether_hdr *)((char *)buf->buf_addr + buf->data_off);
	struct rte_ipv6_hdr *ip6_hdr = (struct rte_ipv6_hdr *)(eth_hdr + 1);
	struct icmp6_hdr *icmp6_hdr = (struct icmp6_hdr *)(ip6_hdr + 1);
	switch (icmp6_hdr->type) {
	case ICMP6_RA:
		handle_icmp6_ra(buf);
		break;
	case ICMP6_NS:
		handle_icmp6_ns(buf);
		break;
	}
}

static inline int
port_init(uint16_t port)
{
	struct rte_eth_conf port_conf;
	const uint16_t rx_rings = 1, tx_rings = 2;
	uint16_t nb_rxd = RX_RING_SIZE;
	uint16_t nb_txd = TX_RING_SIZE;
	int retval;
	uint16_t q;
	struct rte_eth_dev_info dev_info;
	struct rte_eth_txconf txconf;

	if (!rte_eth_dev_is_valid_port(port))
		return -1;

	memset(&port_conf, 0, sizeof(struct rte_eth_conf));

	retval = rte_eth_dev_info_get(port, &dev_info);
	if (retval != 0) {
		printf("Error during getting device (port %u) info: %s\n", port, strerror(-retval));
		return retval;
	}

	if (dev_info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE)
		port_conf.txmode.offloads |= RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE;

	retval = rte_eth_dev_configure(port, rx_rings, tx_rings, &port_conf);
	if (retval != 0)
		return retval;

	retval = rte_eth_dev_adjust_nb_rx_tx_desc(port, &nb_rxd, &nb_txd);
	if (retval != 0)
		return retval;

	for (q = 0; q < rx_rings; q++) {
		retval = rte_eth_rx_queue_setup(port, q, nb_rxd, rte_eth_dev_socket_id(port), NULL, mbuf_pool);
		if (retval < 0)
			return retval;
	}

	txconf = dev_info.default_txconf;
	txconf.offloads = port_conf.txmode.offloads;
	for (q = 0; q < tx_rings; q++) {
		retval = rte_eth_tx_queue_setup(port, q, nb_txd, rte_eth_dev_socket_id(port), &txconf);
		if (retval < 0)
			return retval;
	}

	retval = rte_eth_dev_start(port);
	if (retval < 0)
		return retval;

	if (port == GPW_PORT_DL) {
		retval = rte_eth_macaddr_get(GPW_PORT_DL, &ethaddr_dl);
		if (retval != 0)
			return retval;
	}
	if (port == GPW_PORT_UL) {
		retval = rte_eth_macaddr_get(GPW_PORT_UL, &ethaddr_ul);
		if (retval != 0)
			return retval;
	}

	retval = rte_eth_promiscuous_enable(port);
	if (retval != 0)
		return retval;

	return 0;
}

static __rte_noreturn int
lcore_ul(__rte_unused void *arg)
{
	struct rte_mbuf *prev = NULL;
	for (;;) {
		int ret;
		int id;
		size_t sizeof_hdr;
		struct gpw_eth_hdr *eth_hdr;
		struct gpw_ip6_hdr *ip6_hdr;
		struct rte_mbuf *bufs[1];

		/* UL ポートからパケットを 1 つ取り出す。 */
		const uint16_t nb_rx = rte_eth_rx_burst(GPW_PORT_UL, 0, bufs, 1);
		/* もし取り出せたパケット数が 0 だったらループの最初に戻る。 */
		if (unlikely(nb_rx == 0))
			continue;
		gpwstats.ul_rx_packets += 1;
		gpwstats.ul_rx_bytes += bufs[0]->pkt_len;

		if (likely(gpw_mode == GPW_MODE_ETH)) {
			/* 動作モードが Ethernet over Ethernet の場合: */
			sizeof_hdr = sizeof(struct gpw_eth_hdr);
			eth_hdr = (struct gpw_eth_hdr *)((char *)bufs[0]->buf_addr + bufs[0]->data_off);
			/* もし受信パケットの送信元 MAC アドレスが対向機器の MAC アドレスではなかったら破棄。 */
			ret = memcmp(&eth_hdr->eth_hdr.src_addr, &eth_dstaddr, sizeof(struct rte_ether_addr));
			if (unlikely(ret != 0))
				goto free;
			/* EtherType が ginzado-pseudowire ではなかったら破棄。 */
			if (unlikely(eth_hdr->eth_hdr.ether_type != rte_cpu_to_be_16(GPW_ETHTYPE)))
				goto free;
			id = eth_hdr->id;
		} else {
			/* 動作モードが Ethernet over IPv6 の場合: */
			sizeof_hdr = sizeof(struct gpw_ip6_hdr);
			ip6_hdr = (struct gpw_ip6_hdr *)((char *)bufs[0]->buf_addr + bufs[0]->data_off);
			/* もし受信パケットの送信元 IPv6 アドレスが対向機器の IPv6 アドレスではなかったら破棄。 */
			ret = memcmp(&ip6_hdr->ip6_hdr.src_addr, &ip6_dstaddr, 16);
			if (unlikely(ret != 0))
				goto free;
			/* プロトコル番号が ginzado-pseudowire ではなかったら破棄。 */
			if (unlikely(ip6_hdr->ip6_hdr.proto != GPW_PROTO))
				goto free;
			id = ip6_hdr->id;
		}

		if (id != 0) {
			/* リアセンブルが必要な場合: */
			/*
			 *  +--------------------------------+
			 *  | 前半パケット:                  |
			 *  |              +---------------+ |
			 *  |              | Outer Eth Hdr | |
			 *  |              +---------------+ |
			 *  |              | IPv6 Hdr(注1) | |
			 *  |              +---------------+ |
			 *  |              | ID            | |
			 *  |   data_off ->+---------------+ |
			 *  |              | Inner Eth Hdr | |
			 *  |              +---------------+ |
			 *  |              | Inner DATA    | |
			 *  |              |  (前半部分)   | |
			 *  |   data_len ->+---------------+ |
			 *  |   next ---------------------------+
			 *  +--------------------------------+  |
			 *                                      |
			 *  +--------------------------------+<-+
			 *  | 後半パケット:                  |
			 *  |              +---------------+ |
			 *  |              | Outer Eth Hdr | |
			 *  |              +---------------+ |
			 *  |              | IPv6 Hdr(注1) | |
			 *  |              +---------------+ |
			 *  |              | ID            | |
			 *  |   data_off ->+---------------+ |
			 *  |              | Inner DATA    | |
			 *  |              |  (後半部分)   | |
			 *  |   data_len ->+---------------+ |
			 *  |   next                         |
			 *  +--------------------------------+
			 *
			 *  注1) IPv6 Hdr は動作モードが Ehternet over IPv6 の場合のみ。
			 *  注2) 前半パケットの pkt_len は前半パケットと後半パケットの data_len の合計。
			 */
			if (id & 0x4000) {
				/* 後半パケットだった場合: */
				int prev_id;
				struct gpw_eth_hdr *prev_eth_hdr;
				struct gpw_ip6_hdr *prev_ip6_hdr;
				/* 保管された前半パケットが存在しない場合はリアセンブルできないので破棄。 */
				if (unlikely(prev == NULL))
					goto free;
				if (likely(gpw_mode == GPW_MODE_ETH)) {
					/* 動作モードが Ethernet over Ethernet の場合: */
					prev_eth_hdr = (struct gpw_eth_hdr *)((char *)prev->buf_addr + prev->data_off);
					prev_id = prev_eth_hdr->id;
				} else {
					/* 動作モードが Ethernet over IPv6 の場合: */
					prev_ip6_hdr = (struct gpw_ip6_hdr *)((char *)prev->buf_addr + prev->data_off);
					prev_id = prev_ip6_hdr->id;
				}
				/* 前半パケットと後半パケットの ID 部分が一致しない場合は両方破棄。 */
				if (unlikely((prev_id & 0x3fff) != (id & 0x3fff)))
					goto free_prev;
				/* 前半パケットを ginzado-pseudowire ヘッダ分縮め失敗したら前半後半両方破棄。 */
				void *retp1 = rte_pktmbuf_adj(prev, sizeof_hdr);
				if (unlikely(retp1 == NULL))
					goto free_prev;
				/* 後半パケットを ginzado-pseudowire ヘッダ分縮め失敗したら前半後半両方破棄。 */
				void *retp2 = rte_pktmbuf_adj(bufs[0], sizeof_hdr);
				if (unlikely(retp2 == NULL))
					goto free_prev;
				/* 前半パケットの次に後半パケットが続くよう連結する。 */
				rte_pktmbuf_chain(prev, bufs[0]);
				/* 受信パケットを指す bufs[0] を前半パケットに差し替える。 */
				bufs[0] = prev;
				/* 後半パケットを指す prev を NULL にする。 */
				prev = NULL;
			} else {
				/* 前半パケットだった場合: */
				/* すでに保管された前半パケットが存在する場合はそれを破棄する。 */
				if (unlikely(prev != NULL)) {
					ret = rte_ring_enqueue(ring_ul2main, prev);
					if (unlikely(ret != 0))
						rte_pktmbuf_free(prev);
				}
				/* 前半パケットを指す prev を受信した buf[0] に設定する。 */
				prev = bufs[0];
				/* 前半パケットを受信しただけなので送信処理はせずループの最初に戻る。 */
				continue;
			}
		} else {
			/* リアセンブルが不要な場合: */
			/* UL ポートの BPDU 受信カウンタ更新。 */
			uint8_t *headp = (uint8_t *)((char *)bufs[0]->buf_addr + bufs[0]->data_off);
			if (unlikely(headp[sizeof_hdr + 14] == 0x42 && headp[sizeof_hdr + 15] == 0x42))
					gpwstats.ul_rx_bpdus += 1;
			/* パケットを ginzado-pseudowire ヘッダ分縮め失敗したら破棄。 */
			void *retp = rte_pktmbuf_adj(bufs[0], sizeof_hdr);
			if (unlikely(retp == NULL))
				goto free;
		}
		const uint64_t txbytes = bufs[0]->pkt_len;
		/* DL ポートからパケットを 1 つ送り出す。 */
		const uint16_t nb_tx = rte_eth_tx_burst(GPW_PORT_DL, 0, bufs, 1);
		/* もし送り出せたパケット数が 0 だったらパケットを破棄する。 */
		if (unlikely(nb_tx == 0)) {
			gpwstats.dl_tx_errors += 1;
			goto free;
		}
		gpwstats.dl_tx_packets += 1;
		gpwstats.dl_tx_bytes += txbytes;
		continue;
free_prev:
		ret = rte_ring_enqueue(ring_ul2main, prev);
		if (unlikely(ret != 0))
			rte_pktmbuf_free(prev);
		prev = NULL;
free:
		ret = rte_ring_enqueue(ring_ul2main, bufs[0]);
		if (unlikely(ret != 0))
			rte_pktmbuf_free(bufs[0]);
	}
}

static __rte_noreturn int
lcore_dl(__rte_unused void *arg)
{
	uint16_t id = 1;
	for (;;) {
		int ret;
		uint32_t frag_threshold;
		struct rte_mbuf *bufs[1];
		struct rte_mbuf *pkt1out = NULL;
		struct rte_mbuf *pkt1in = NULL;
		struct rte_mbuf *pkt2out = NULL;
		struct rte_mbuf *pkt2in = NULL;

		/* DL ポートからパケットを 1 つ取り出す。 */
		const uint16_t nb_rx = rte_eth_rx_burst(GPW_PORT_DL, 0, bufs, 1);
		/* もし取り出せたパケット数が 0 だったらループの最初に戻る。 */
		if (unlikely(nb_rx == 0))
			continue;
		gpwstats.dl_rx_packets += 1;
		gpwstats.dl_rx_bytes += bufs[0]->pkt_len;

		/* もし動作モードが Ethernet over IPv6 で準備がまだだったら受信パケットを破棄する。 */
		if (unlikely(gpw_mode == GPW_MODE_IP6 && ip6_ready == false))
			goto free;

		/* DL ポートの BPDU 受信カウンタ更新。 */
		uint8_t *headp = (uint8_t *)((char *)bufs[0]->buf_addr + bufs[0]->data_off);
		if (unlikely(headp[14] == 0x42 && headp[15] == 0x42))
			gpwstats.dl_rx_bpdus += 1;

		if (likely(gpw_mode == GPW_MODE_ETH)) {
			/* 動作モードが Ethernet over Ethernet の場合: */
			frag_threshold = 1514 - sizeof(struct gpw_eth_hdr);
		} else {
			/* 動作モードが Ethernet over IPv6 の場合: */
			frag_threshold = 1514 - sizeof(struct gpw_ip6_hdr);
		}
		if (bufs[0]->pkt_len > frag_threshold) {
			/* フラグメントが必要な場合: */
			/*
			 *  +--------------------------------+     +-------------+     +----------------------+
			 *  | pkt1out:                       |  +->| pkt1in:     |     | bufs[0]:             |
			 *  |   data_off ->+---------------+ |  |  |   data_off ---------->+----------------+ |
			 *  |              | Outer Eth Hdr | |  |  |             |     |   | Inner Eth Hdr  | |
			 *  |              +---------------+ |  |  |             |     |   +----------------+ |
			 *  |              | IPv6 Hdr(注1) | |  |  |             |     |   |                | |
			 *  |              +---------------+ |  |  |             |     |   | Inner DATA     | |
			 *  |              | ID            | |  |  |             |     |   |                | |
			 *  |   data_len ->+---------------+ |  |  |   data_len ----+  |   |                | |
			 *  |   next ---------------------------+  |             |  |  |   |                | |
			 *  +--------------------------------+     +-------------+  |  |   |                | |
			 *                                                          +----->| (GPW_FRAGSIZE) | |
			 *  +--------------------------------+     +-------------+  |  |   |                | |
			 *  | pkt2out:                       |  +->| pkt2in:     |  |  |   |                | |
			 *  |   data_off ->+---------------+ |  |  |   data_off ----+  |   |                | |
			 *  |              | Outer Eth Hdr | |  |  |             |     |   |                | |
			 *  |              +---------------+ |  |  |             |     |   |                | |
			 *  |              | IPv6 Hdr(注1) | |  |  |             |  +----->+----------------+ |
			 *  |              +---------------+ |  |  |             |  |  |                      |
			 *  |              | ID            | |  |  |             |  |  +----------------------+
			 *  |   data_len ->+---------------+ |  |  |   data_len ----+
			 *  |   next ---------------------------+  |             |
			 *  +--------------------------------+     +-------------+
			 *
			 *  注1) IPv6 Hdr は動作モードが Ehternet over IPv6 の場合のみ。
			 *  注2) pkt1out の pkt_len は pkt1out と pkt1in の data_len の合計。
			 *  注3) pkt2out の pkt_len は pkt2out と pkt2in の data_len の合計。
			 */
			struct gpw_eth_hdr *eth_hdr1;
			struct gpw_ip6_hdr *ip6_hdr1;
			struct gpw_eth_hdr *eth_hdr2;
			struct gpw_ip6_hdr *ip6_hdr2;
			pkt1out = rte_pktmbuf_alloc(mbuf_pool);
			if (unlikely(pkt1out == NULL))
				goto free;
			pkt1in = rte_pktmbuf_alloc(mbuf_pool);
			if (unlikely(pkt1in == NULL))
				goto free_pkt1out;
			pkt2out = rte_pktmbuf_alloc(mbuf_pool);
			if (unlikely(pkt2out == NULL))
				goto free_pkt1in;
			pkt2in = rte_pktmbuf_alloc(mbuf_pool);
			if (unlikely(pkt2in == NULL))
				goto free_pkt2out;
			id++;
			/* 前半パケットの処理: */
			rte_pktmbuf_attach(pkt1in, bufs[0]);
			pkt1in->data_off = bufs[0]->data_off;
			pkt1in->data_len = GPW_FRAGSIZE;
			pkt1in->pkt_len = pkt1in->data_len;
			if (likely(gpw_mode == GPW_MODE_ETH)) {
				/* 動作モードが Ethernet over Ethernet の場合: */
				/* pkt1out の先頭に ginzado-pseudowire ヘッダ分の領域を確保しできなかったら破棄。 */
				eth_hdr1 = (struct gpw_eth_hdr *)rte_pktmbuf_prepend(pkt1out,
						sizeof(struct gpw_eth_hdr));
				if (unlikely(eth_hdr1 == NULL))
					goto free_pkt2in;
				/* ginzado-pseudowire ヘッダを書き込む。 */
				memcpy(eth_hdr1, &eth_hdr_cork, sizeof(struct gpw_eth_hdr) - 2);
				/* ID に現在の ID 値の 14 ビット分とフラグメントビット(16 ビット目)を入れる。 */
				eth_hdr1->id = (0x3fff & id) | 0x8000;
			} else {
				/* 動作モードが Ethernet over IPv6 の場合: */
				/* pkt1out の先頭に ginzado-pseudowire ヘッダ分の領域を確保しできなかったら破棄。 */
				ip6_hdr1 = (struct gpw_ip6_hdr *)rte_pktmbuf_prepend(pkt1out,
						sizeof(struct gpw_ip6_hdr));
				if (unlikely(ip6_hdr1 == NULL))
					goto free_pkt2in;
				memcpy(ip6_hdr1, &ip6_hdr_cork, sizeof(struct gpw_ip6_hdr) - 2);
				/* Ethernet over IPv6 の場合は IPv6 ヘッダのペイロード長を埋める。 */
				ip6_hdr1->ip6_hdr.payload_len = rte_cpu_to_be_16(pkt1out->pkt_len + pkt1in->pkt_len
						- sizeof(struct rte_ether_hdr) - sizeof(struct rte_ipv6_hdr));
				/* ID に現在の ID 値の 14 ビット分とフラグメントビット(16 ビット目)を入れる。 */
				ip6_hdr1->id = (0x3fff & id) | 0x8000;
			}
			/* pkt1out の続きが pkt1in となるよう繋げる。 */
			rte_pktmbuf_chain(pkt1out, pkt1in);
			/* 後半パケットの処理: */
			rte_pktmbuf_attach(pkt2in, bufs[0]);
			pkt2in->data_off = bufs[0]->data_off + GPW_FRAGSIZE;
			pkt2in->data_len = bufs[0]->data_len - GPW_FRAGSIZE;
			pkt2in->pkt_len = pkt2in->data_len;
			if (likely(gpw_mode == GPW_MODE_ETH)) {
				/* 動作モードが Ethernet over Ethernet の場合: */
				/* pkt2out の先頭に ginzado-pseudowire ヘッダ分の領域を確保しできなかったら破棄。 */
				eth_hdr2 = (struct gpw_eth_hdr *)rte_pktmbuf_prepend(pkt2out,
						sizeof(struct gpw_eth_hdr));
				if (unlikely(eth_hdr2 == NULL))
					goto free_pkt2in;
				/* ginzado-pseudowire ヘッダを書き込む。 */
				memcpy(eth_hdr2, &eth_hdr_cork, sizeof(struct gpw_eth_hdr) - 2);
				/* ID に現在の ID 値の 14 ビット分とフラグメントビット(16 ビット目)と */
				/* 後半パケットビット(15 ビット目)を入れる。 */
				eth_hdr2->id = (0x3fff & id) | 0xc000;
			} else {
				/* 動作モードが Ethernet over IPv6 の場合: */
				/* pkt2out の先頭に ginzado-pseudowire ヘッダ分の領域を確保しできなかったら破棄。 */
				ip6_hdr2 = (struct gpw_ip6_hdr *)rte_pktmbuf_prepend(pkt2out,
						sizeof(struct gpw_ip6_hdr));
				if (unlikely(ip6_hdr2 == NULL))
					goto free_pkt2in;
				/* ginzado-pseudowire ヘッダを書き込む。 */
				memcpy(ip6_hdr2, &ip6_hdr_cork, sizeof(struct gpw_ip6_hdr) - 2);
				/* Ethernet over IPv6 の場合は IPv6 ヘッダのペイロード長を埋める。 */
				ip6_hdr2->ip6_hdr.payload_len = rte_cpu_to_be_16(pkt2out->pkt_len + pkt2in->pkt_len
						- sizeof(struct rte_ether_hdr) - sizeof(struct rte_ipv6_hdr));
				/* ID に現在の ID 値の 14 ビット分とフラグメントビット(16 ビット目)と */
				/* 後半パケットビット(15 ビット目)を入れる。 */
				ip6_hdr2->id = (0x3fff & id) | 0xc000;
			}
			/* pkt2out の続きが pkt2in となるよう繋げる。 */
			rte_pktmbuf_chain(pkt2out, pkt2in);
			/* 前半パケットと後半パケットの送信処理: */
			struct rte_mbuf *bufs2[2];
			bufs2[0] = pkt1out;
			bufs2[1] = pkt2out;
			const uint64_t txbytes[2] = { bufs2[0]->pkt_len, bufs2[1]->pkt_len, };
			/* UL ポートからパケットを 2 つ送り出す。 */
			const uint16_t nb_tx = rte_eth_tx_burst(GPW_PORT_UL, 0, bufs2, 2);
			/* もし送り出せたパケット数が 2 じゃなかったら失敗した分のパケットを破棄する。 */
			if (unlikely(nb_tx != 2)) {
				uint16_t buf;
				for (buf = nb_tx; buf < 2; buf++) {
					ret = rte_ring_enqueue(ring_dl2main, bufs2[buf]);
					if (unlikely(ret != 0))
						rte_pktmbuf_free(bufs2[buf]);
					gpwstats.ul_tx_errors += 1;
				}
				for (buf = 0; buf < nb_tx; buf++) {
					gpwstats.ul_tx_packets += 1;
					gpwstats.ul_tx_bytes += txbytes[buf];
				}
			} else {
				gpwstats.ul_tx_packets += 2;
				gpwstats.ul_tx_bytes += txbytes[0] + txbytes[1];
			}
			/* bufs[0] は直接送信しないので破棄する。 */
			/* pkt1in と pkt2in からデータを参照されているのでそれらが解放されるタイミングで解放される。 */
			goto free;
		} else {
			/* フラグメントが不要な場合: */
			struct gpw_eth_hdr *eth_hdr;
			struct gpw_ip6_hdr *ip6_hdr;
			if (likely(gpw_mode == GPW_MODE_ETH)) {
				/* 動作モードが Ethernet over Ethernet の場合: */
				/* bufs[0] の先頭に ginzado-pseudowire ヘッダ分の領域を確保しできなかったら破棄。 */
				eth_hdr = (struct gpw_eth_hdr *)rte_pktmbuf_prepend(bufs[0],
						sizeof(struct gpw_eth_hdr));
				if (unlikely(eth_hdr == NULL))
					goto free;
				/* ginzado-pseudowire ヘッダを書き込む。 */
				memcpy(eth_hdr, &eth_hdr_cork, sizeof(struct gpw_eth_hdr));
			} else {
				/* 動作モードが Ethernet over IPv6 の場合: */
				/* bufs[0] の先頭に ginzado-pseudowire ヘッダ分の領域を確保しできなかったら破棄。 */
				ip6_hdr = (struct gpw_ip6_hdr *)rte_pktmbuf_prepend(bufs[0],
						sizeof(struct gpw_ip6_hdr));
				if (unlikely(ip6_hdr == NULL))
					goto free;
				/* ginzado-pseudowire ヘッダを書き込む。 */
				memcpy(ip6_hdr, &ip6_hdr_cork, sizeof(struct gpw_ip6_hdr));
				/* Ethernet over IPv6 の場合は IPv6 ヘッダのペイロード長を埋める。 */
				ip6_hdr->ip6_hdr.payload_len = rte_cpu_to_be_16(bufs[0]->pkt_len
						- sizeof(struct rte_ether_hdr) - sizeof(struct rte_ipv6_hdr));
			}
			const uint64_t txbytes = bufs[0]->pkt_len;
			/* UL ポートからパケットを 1 つ送り出す。 */
			const uint16_t nb_tx = rte_eth_tx_burst(GPW_PORT_UL, 0, bufs, 1);
			/* もし送り出せたパケット数が 0 だったらパケットを破棄する。 */
			if (unlikely(nb_tx == 0)) {
				gpwstats.ul_tx_errors += 1;
				goto free;
			}
			gpwstats.ul_tx_packets += 1;
			gpwstats.ul_tx_bytes += txbytes;
		}
		continue;
free_pkt2in:
		ret = rte_ring_enqueue(ring_dl2main, pkt2in);
		if (unlikely(ret != 0))
			rte_pktmbuf_free(pkt2in);
free_pkt2out:
		ret = rte_ring_enqueue(ring_dl2main, pkt2out);
		if (unlikely(ret != 0))
			rte_pktmbuf_free(pkt2out);
free_pkt1in:
		ret = rte_ring_enqueue(ring_dl2main, pkt1in);
		if (unlikely(ret != 0))
			rte_pktmbuf_free(pkt1in);
free_pkt1out:
		ret = rte_ring_enqueue(ring_dl2main, pkt1out);
		if (unlikely(ret != 0))
			rte_pktmbuf_free(pkt1out);
free:
		ret = rte_ring_enqueue(ring_dl2main, bufs[0]);
		if (unlikely(ret != 0))
			rte_pktmbuf_free(bufs[0]);
	}
}

static __rte_noreturn void
lcore_main(void)
{
	uint32_t counter = 0;
	for (;;) {
		int ret;
		struct rte_mbuf *buf;
		ret = rte_ring_dequeue(ring_ul2main, (void **)&buf);
		if (likely(ret == 0)) {
			if (gpw_mode == GPW_MODE_IP6 && is_icmp6(buf))
				handle_icmp6(buf);
			rte_pktmbuf_free(buf);
		}
		ret = rte_ring_dequeue(ring_dl2main, (void **)&buf);
		if (likely(ret == 0)) {
			rte_pktmbuf_free(buf);
		}
		/* accept のビジーポーリングはコストがでかいので間引く。 */
		if (likely((counter++ & 0x03ffffff) != 0))
			continue;
		ret = accept(serverfd, NULL, NULL);
		if (ret > 0) {
			int i;
			for (i = 0; i < GPW_CLIENT_MAX; i++) {
				if (clientfds[i] == -1)
					break;
			}
			if (i == GPW_CLIENT_MAX) {
				printf("GPW_CLIENT_MAX reached\n");
				close(ret);
			} else {
				clientfds[i] = ret;
			}
		}
		for (int i = 0; i < GPW_CLIENT_MAX; i++) {
			int req;
			if (clientfds[i] == -1)
				continue;
			ret = recv(clientfds[i], &req, sizeof(req), MSG_DONTWAIT);
			if (ret == 0) {
				close(clientfds[i]);
				clientfds[i] = -1;
			}
			if (ret > 0) {
				send(clientfds[i], &gpwstats, sizeof(gpwstats), MSG_DONTWAIT);
			}
		}
	}
}

static void
dump_config(void)
{
	if (gpw_mode == GPW_MODE_ETH)
		printf("eth\n");
	else if (gpw_mode == GPW_MODE_IP6)
		printf("ip6\n");
	else
		printf("unknown\n");
	if (gpw_mode == GPW_MODE_ETH) {
		printf("%02" PRIx8 "%02" PRIx8 "%02" PRIx8 "%02" PRIx8 "%02" PRIx8 "%02" PRIx8 "\n",
				RTE_ETHER_ADDR_BYTES(&eth_dstaddr));
	}
	if (gpw_mode == GPW_MODE_IP6) {
		for (int i = 0; i < 16; i++) {
			printf("%02x", ip6_dstaddr[i]);
		}
		printf("\n");
		for (int i = 0; i < 16; i++) {
			printf("%02x", ip6_srcaddr[i]);
		}
		printf("\n");
	}
}

static int
load_config(const char *config)
{
	FILE *fh;
	char buff[LINE_MAX];
	char *retp;
	int ret = 0;

	int new_gpw_mode = -1;
	struct rte_ether_addr new_eth_dstaddr;
	uint8_t new_ip6_dstaddr[16];
	uint8_t new_ip6_srcaddr[16];

	fh = fopen(config, "rb");
	if (fh == NULL) {
		printf("[%s():%u] fopen %s failed\n", __func__, __LINE__, config);
		return -1;
	}

	ret = fseek(fh, 0, SEEK_SET);
	if (ret) {
		printf("[%s():%u] fseek %d failed\n", __func__, __LINE__, ret);
		goto exit;
	}

	retp = fgets(buff, LINE_MAX, fh);
	buff[3] = '\0';
	if (retp == NULL) {
		printf("[%s():%u] fgets failed\n", __func__, __LINE__);
		ret = -1;
		goto exit;
	} else if (strncmp("eth", buff, sizeof(buff)) == 0) {
		new_gpw_mode = GPW_MODE_ETH;
	} else if (strncmp("ip6", buff, sizeof(buff)) == 0) {
		new_gpw_mode = GPW_MODE_IP6;
	} else {
		printf("[%s():%u] mode invalid\n", __func__, __LINE__);
		ret = -1;
		goto exit;
	}

	if (new_gpw_mode == GPW_MODE_ETH) {
		retp = fgets(buff, LINE_MAX, fh);
		if (retp == NULL || strnlen(buff, LINE_MAX) < 12) {
			printf("[%s():%u] dst mac address invalid\n", __func__, __LINE__);
			ret = -1;
			goto exit;
		}
		char buff2[3] = { '\0', '\0', '\0', };
		for (int i = 0; i < 6; i++) {
			buff2[0] = buff[i*2];
			buff2[1] = buff[i*2+1];
			long octet = strtol(buff2, NULL, 16);
			new_eth_dstaddr.addr_bytes[i] = octet;
		}
	}

	if (new_gpw_mode == GPW_MODE_IP6) {
		char buff2[3] = { '\0', '\0', '\0', };
		retp = fgets(buff, LINE_MAX, fh);
		if (retp == NULL || strnlen(buff, LINE_MAX) < 32) {
			printf("[%s():%u] dst ip6 address invalid\n", __func__, __LINE__);
			ret = -1;
			goto exit;
		}
		for (int i = 0; i < 16; i++) {
			buff2[0] = buff[i*2];
			buff2[1] = buff[i*2+1];
			long octet = strtol(buff2, NULL, 16);
			new_ip6_dstaddr[i] = octet;
		}
		retp = fgets(buff, LINE_MAX, fh);
		if (retp == NULL || strnlen(buff, LINE_MAX) < 32) {
			printf("[%s():%u] src ip6 address invalid\n", __func__, __LINE__);
			ret = -1;
			goto exit;
		}
		for (int i = 0; i < 16; i++) {
			buff2[0] = buff[i*2];
			buff2[1] = buff[i*2+1];
			long octet = strtol(buff2, NULL, 16);
			new_ip6_srcaddr[i] = octet;
		}
	}

	gpw_mode = new_gpw_mode;
	eth_dstaddr = new_eth_dstaddr;
	memcpy(&ip6_dstaddr, new_ip6_dstaddr, 16);
	memcpy(&ip6_srcaddr, new_ip6_srcaddr, 16);

exit:
	fclose(fh);
	return ret;
}

static void
init_corks(void)
{
	/* eth */
	memcpy(&eth_hdr_cork.eth_hdr.dst_addr, &eth_dstaddr, sizeof(struct rte_ether_addr));
	memcpy(&eth_hdr_cork.eth_hdr.src_addr, &ethaddr_ul, sizeof(struct rte_ether_addr));
	eth_hdr_cork.eth_hdr.ether_type = rte_cpu_to_be_16(GPW_ETHTYPE);
	//eth_hdr_cork.id = 0;
	/* ip6 */
	memcpy(&ip6_hdr_cork.eth_hdr.dst_addr, &ip6_dstmac, sizeof(struct rte_ether_addr));
	memcpy(&ip6_hdr_cork.eth_hdr.src_addr, &ethaddr_ul, sizeof(struct rte_ether_addr));
	ip6_hdr_cork.eth_hdr.ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV6);
	ip6_hdr_cork.ip6_hdr.vtc_flow = rte_cpu_to_be_32(0x60000000);
	ip6_hdr_cork.ip6_hdr.payload_len = 0;
	ip6_hdr_cork.ip6_hdr.proto = GPW_PROTO;
	ip6_hdr_cork.ip6_hdr.hop_limits = 64;
	memcpy(&ip6_hdr_cork.ip6_hdr.src_addr, &ip6_srcaddr, 16);
	memcpy(&ip6_hdr_cork.ip6_hdr.dst_addr, &ip6_dstaddr, 16);
	//ip6_hdr_cork.id = 0;
}

static void
print_usage(const char *prgname)
{
	printf("%s usage:\n", prgname);
	printf("[EAL options] --  --"OPTION_CONFIG"=FILE: ");
	printf("specify the configuration file.\n");
}

static int
parse_args(int argc, char **argv)
{
	int opt, ret;
	char **argvopt;
	int option_index;
	char *prgname = argv[0];
	static struct option lgopts[] = {
		{OPTION_CONFIG, 1, 0, 0},
		{NULL, 0, 0, 0},
	};

	argvopt = argv;

	while ((opt = getopt_long(argc, argvopt, "", lgopts, &option_index)) != EOF) {
		switch (opt) {
		case 0:
			if (!strncmp(lgopts[option_index].name, OPTION_CONFIG, sizeof(OPTION_CONFIG)))
				config = optarg;
			break;
		default:
			print_usage(prgname);
			return -1;
		}
	}

	if (optind >= 0)
		argv[optind-1] = prgname;

	ret = optind-1;
	optind = 1;
	return ret;
}

static void
sighup_handler(int signum)
{
	if (signum != SIGHUP) {
		printf("Error: Unknown signal\n");
		return;
	}
	int ret = load_config(config);
	if (ret < 0) {
		printf("Error: Load config failed\n");
		return;
	}
	dump_config();
	init_corks();
}

int
main(int argc, char *argv[])
{
	unsigned nb_ports;
	uint16_t portid;
	unsigned lcoreid;

	signal(SIGHUP, sighup_handler);

	int ret = rte_eal_init(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");

	argc -= ret;
	argv += ret;

	ret = parse_args(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Invalid parameters\n");

	if (rte_lcore_count() != 3)
		rte_exit(EXIT_FAILURE, "Error: number of lcores must be 3\n");

	nb_ports = rte_eth_dev_count_avail();
	if (nb_ports != 2)
		rte_exit(EXIT_FAILURE, "Error: number of ports must be 2\n");

	ret = load_config(config);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Error: Load config failed\n");

	dump_config();

	ring_ul2main = rte_ring_create("UL2MAIN", INTERNAL_RING_SIZE, rte_socket_id(), RING_F_SP_ENQ|RING_F_SC_DEQ);
	if (ring_ul2main == NULL)
		rte_exit(EXIT_FAILURE, "Error: ul2main ring create failed\n");
	ring_dl2main = rte_ring_create("DL2MAIN", INTERNAL_RING_SIZE, rte_socket_id(), RING_F_SP_ENQ|RING_F_SC_DEQ);
	if (ring_dl2main == NULL)
		rte_exit(EXIT_FAILURE, "Error: dl2main ring create failed\n");

	mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL", NUM_MBUFS * nb_ports,
		MBUF_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
	if (mbuf_pool == NULL)
		rte_exit(EXIT_FAILURE, "Cannot create mbuf pool\n");

	RTE_ETH_FOREACH_DEV(portid)
		if (port_init(portid) != 0)
			rte_exit(EXIT_FAILURE, "Cannot init port %"PRIu16 "\n", portid);

	printf("Port UL MAC: %02" PRIx8 " %02" PRIx8 " %02" PRIx8 " %02" PRIx8 " %02" PRIx8 " %02" PRIx8 "\n",
			RTE_ETHER_ADDR_BYTES(&ethaddr_ul));
	printf("Port DL MAC: %02" PRIx8 " %02" PRIx8 " %02" PRIx8 " %02" PRIx8 " %02" PRIx8 " %02" PRIx8 "\n",
			RTE_ETHER_ADDR_BYTES(&ethaddr_dl));

	init_corks();

	/* gpwstats */
	remove(GPWSTATS_UNIX_SOCKET_PATH);
	memset(&serversa, 0, sizeof(serversa));
	serverfd = socket(AF_LOCAL, SOCK_STREAM, 0);
	if (serverfd < 0)
		rte_exit(EXIT_FAILURE, "Error: socket failed\n");
	int flags;
	if ((flags = fcntl(serverfd, F_GETFL, 0)) < 0)
		rte_exit(EXIT_FAILURE, "F_GETFL failed\n");
	flags |= O_NONBLOCK;
	if (fcntl(serverfd, F_SETFL, flags) < 0)
		rte_exit(EXIT_FAILURE, "F_SETFL failed\n");
	serversa.sun_family = AF_LOCAL;
	strcpy(serversa.sun_path, GPWSTATS_UNIX_SOCKET_PATH);
	ret = bind(serverfd, (const struct sockaddr *)&serversa, sizeof(serversa));
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Error: bind failed\n");
	ret = listen(serverfd, GPW_CLIENT_MAX);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Error: listen failed\n");

	lcoreid_main = rte_lcore_id();
	RTE_LCORE_FOREACH_WORKER(lcoreid) {
		if (lcoreid_ul == LCORE_ID_ANY) {
			lcoreid_ul = lcoreid;
			continue;
		}
		if (lcoreid_dl == LCORE_ID_ANY) {
			lcoreid_dl = lcoreid;
			continue;
		}
	}
	if (lcoreid_ul == LCORE_ID_ANY || lcoreid_dl == LCORE_ID_ANY)
		rte_exit(EXIT_FAILURE, "Error: lcores invalid\n");

	if (rte_eal_remote_launch(lcore_ul, mbuf_pool, lcoreid_ul))
		rte_exit(EXIT_FAILURE, "Error: ul remote launch failed\n");
	if (rte_eal_remote_launch(lcore_dl, mbuf_pool, lcoreid_dl))
		rte_exit(EXIT_FAILURE, "Error: dl remote launch failed\n");

	lcore_main();

	rte_eal_cleanup();

	return 0;
}
