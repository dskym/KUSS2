#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>

static unsigned int hook_pre_route_func(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
    return NF_ACCEPT;
}

static unsigned int hook_forward_func(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
    return NF_ACCEPT;
}

static unsigned int hook_post_route_func(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
    return NF_ACCEPT;
}

static struct nf_hook_ops nf_pre_route_hook_ops =
{
    .hook = hook_pre_route_func,
    .pf = PF_INET,
    .hooknum = NF_INET_PRE_ROUTING,
    .priority = NF_IP_PRI_FILTER,
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
