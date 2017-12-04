#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/inet.h>
#include <linux/tcp.h>
#include <linux/ip.h>
#include <net/ip.h>
#include <net/tcp.h>

#define NIPQUAD(addr) \
    ((unsigned char *)&addr)[0], \
    ((unsigned char *)&addr)[1], \
    ((unsigned char *)&addr)[2], \
    ((unsigned char *)&addr)[3]

#define SRC_PORT 7777
#define DST_PORT 7777
#define DST_IP "1.2.3.4"

static unsigned int hook_pre_route_func(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
    struct iphdr *ih = ip_hdr(skb);
    struct tcphdr *th = tcp_hdr(skb);
     
    unsigned char protocol = ih->protocol;
    unsigned int src_addr = ih->saddr;
    unsigned int dst_addr = ih->daddr;
   
    unsigned short src_port = ntohs(th->source);
    unsigned short dst_port = ntohs(th->dest);

    int datalen;
    
    printk(KERN_DEBUG "PRE_ROUTING : (%u,%u,%u,%u.%u.%u.%u,%u.%u.%u.%u)\n", protocol, src_port, dst_port, NIPQUAD(src_addr), NIPQUAD(dst_addr));

    switch(protocol)
    {
        case IPPROTO_TCP :
            if(src_port == 33333)
            {
                ih->daddr = in_aton(DST_IP);

                ip_send_check(ih);

                th->source = htons(SRC_PORT);
                th->dest = htons(DST_PORT);

                datalen = skb->len - ih->ihl*4;

                th->check = 0;
                th->check = tcp_v4_check(datalen, ih->saddr, ih->daddr, csum_partial(th, datalen, 0));

                printk(KERN_DEBUG "Forwarding Complete.\n");
            }
        default :
            break;
    }

    return NF_ACCEPT;
}

static unsigned int hook_forward_func(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
    struct iphdr *ih = ip_hdr(skb);
    struct tcphdr *th = tcp_hdr(skb);

    unsigned char protocol = ih->protocol;
    unsigned int src_addr = ih->saddr;
    unsigned int dst_addr = ih->daddr;
 
    unsigned short src_port = ntohs(th->source);
    unsigned short dst_port = ntohs(th->dest);

    printk(KERN_DEBUG "FORWARD : (%u,%u,%u,%u.%u.%u.%u,%u.%u.%u.%u)\n", protocol, src_port, dst_port, NIPQUAD(src_addr), NIPQUAD(dst_addr));
         
    return NF_ACCEPT;
}

static unsigned int hook_post_route_func(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
    struct iphdr *ih = ip_hdr(skb);
    struct tcphdr *th = tcp_hdr(skb);
     
    unsigned char protocol = ih->protocol;
    unsigned int src_addr = ih->saddr;
    unsigned int dst_addr = ih->daddr;
     
    unsigned short src_port = ntohs(th->source);
    unsigned short dst_port = ntohs(th->dest);
       
    printk(KERN_DEBUG "POST_ROUTING : (%u,%u,%u,%u.%u.%u.%u,%u.%u.%u.%u)\n", protocol, src_port, dst_port, NIPQUAD(src_addr), NIPQUAD(dst_addr));

    return NF_ACCEPT;
}

static struct nf_hook_ops nf_pre_route_hook_ops =
{
    .hook = hook_pre_route_func,
    .pf = PF_INET,
    .hooknum = NF_INET_PRE_ROUTING,
    .priority = NF_IP_PRI_FIRST,
};

static struct nf_hook_ops nf_forward_hook_ops = 
{
    .hook = hook_forward_func,
    .pf = PF_INET,
    .hooknum = NF_INET_FORWARD,
    .priority = NF_IP_PRI_FILTER,
};

static struct nf_hook_ops nf_post_route_hook_ops = 
{
    .hook = hook_post_route_func,
    .pf = PF_INET,
    .hooknum = NF_INET_POST_ROUTING,
    .priority = NF_IP_PRI_FILTER,
};

static int __init packet_forward_module_init(void)
{
    printk(KERN_INFO "Module Init\n");

    nf_register_hook(&nf_pre_route_hook_ops);
    nf_register_hook(&nf_forward_hook_ops);
    nf_register_hook(&nf_post_route_hook_ops);

    return 0;
}

static void __exit packet_forward_module_exit(void)
{
    printk(KERN_INFO "Module exit\n");

    nf_unregister_hook(&nf_pre_route_hook_ops);
    nf_unregister_hook(&nf_forward_hook_ops);
    nf_unregister_hook(&nf_post_route_hook_ops);

    return;
}

module_init(packet_forward_module_init);
module_exit(packet_forward_module_exit);

MODULE_AUTHOR("Kim SeungYoon and Choi ChangMin");
MODULE_DESCRIPTION("Read queue buffer using proc file system.");
MODULE_LICENSE("GPL");
MODULE_VERSION("NEW");
