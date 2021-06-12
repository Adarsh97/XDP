/* SPDX-License-Identifier: GPL-2.0 */

#include <linux/bpf.h>
#include<time.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
 #include <arpa/inet.h>
#include <string.h>





struct bpf_map_def SEC("maps") xsks_map = {
	.type = BPF_MAP_TYPE_XSKMAP,
	.key_size = sizeof(int),
	.value_size = sizeof(int),
	.max_entries = 1,  // Assume netdev has no more than 64 queues 
};

/*
struct bpf_map_def SEC("maps") xdp_stats_map = {
	.type        = BPF_MAP_TYPE_PERCPU_ARRAY,
	.key_size    = sizeof(int),
	.value_size  = sizeof(__u32),
	.max_entries = 64,
};
*/

struct bpf_map_def SEC("maps") xdp_stats_map = {
	.type        = BPF_MAP_TYPE_ARRAY,
	.key_size    = sizeof(int),
	.value_size  = sizeof(long int),
	.max_entries = 1024,
};


static __always_inline
int parse_ipv4(void *data, __u64 nh_off, void* data_end) {
	struct iphdr *iph = data+nh_off;
	
	if(iph+1 > data_end) {
		return 0;
	} 
	
	struct udphdr *udp = (void*)iph+sizeof(*iph);
	
	if((void*)udp+sizeof(*udp) <= data_end) {
		if(udp->dest == 12345) {
			return iph->protocol;;
		}
			return 0;
	}
	
	return 0;
}

/*
static __always_inline
int udpWithport(void *data, __u64 nh_off, void* data_end) {
	struct iphdr *iph = data+nh_off;
	struct udphdr *udp = (void*)iph+sizeof(*iph);

	if((void*)udp+sizeof(*udp) <= data_end) {
		if(udp->dest == 12347) {
			return 1;
		}
	}
	return 0;
}

*/


SEC("xdp_sock")
int xdp_sock_prog(struct xdp_md *ctx)
{
	long int ctime = bpf_ktime_get_ns();
	int index = ctx->rx_queue_index;
      	static int key=0;
      
     	void * data_end= (void*) (long) ctx->data_end;
     	void *data = (void*) (long)ctx->data;
     	struct ethhdr *eth = data;
     	__u64 nh_off;
     	__u32 ipproto = 0;
     
     	nh_off = sizeof(*eth);
     
     	if (data + nh_off > data_end) {
      	return XDP_ABORTED;
     	}
        if (eth->h_proto == 8) 
     	ipproto = parse_ipv4(data,nh_off, data_end);
     	
     	if(ipproto == 17 )
     	{
     	 	if(bpf_map_update_elem(&xdp_stats_map,&key,&ctime,BPF_ANY)!=0) {
     			return XDP_DROP;
     	 	}
     	 	key++;
     	 	key=key%1024;
     	 	
     	 	return bpf_redirect_map(&xsks_map, index, 0);
     	}
     	 	
     	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
