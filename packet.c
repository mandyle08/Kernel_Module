#include <linux/module.h>    // included for all kernel modules
#include <linux/kernel.h>    // included for KERN_INFO
#include <linux/init.h>      // included for __init and __exit macros
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/proc_fs.h>
#include <linux/list.h>
#include <asm/uaccess.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/skbuff.h>//socket buffer module acronym SKB
#include <linux/ip.h>
#include <linux/netfilter.h>
#include <linux/string.h>

//#undef __KERNEL__
#include <linux/netfilter_ipv4.h>
//#define __KERNEL__

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Amanda Le and Phil Neff");
MODULE_DESCRIPTION("Packet Analysis Kernel");

static struct nf_hook_ops nfho;   //net filter hook option struct
static struct nf_hook_ops nfho_out;   //net filter hook option struct
int get_sockfd(struct sock *sk);
char source[16];


unsigned int my_hook_in(unsigned int hooknum,
    struct sk_buff *skb,
    const struct net_device *in,
    const struct net_device *out,
    int (*okfn)(struct sk_buff *))  {//this is from skbuff.h - socket buffer

    // get ipheader from socket buffer
    struct iphdr *ip_header = (struct iphdr *)skb_network_header(skb);
    struct udphdr *udp_header;
    struct tcphdr *tcp_header;

    // get ip from ipheader
    void*  srcip = &(ip_header->saddr);
    void*  destip =&(ip_header->daddr);

    // declare ports and set to zero for now
    unsigned int srcport = 0;
    unsigned int destport = 0;

    if (ip_header->protocol==17)         { // udp
      udp_header = (struct udphdr *)(skb_transport_header(skb)+20);
      srcport = (unsigned int)ntohs(udp_header->source);
      destport = (unsigned int)ntohs(udp_header->dest);
    } else if (ip_header->protocol == 6) { // tcp
      tcp_header = (struct tcphdr *)(skb_transport_header(skb)+20);
      srcport = (unsigned int)ntohs(tcp_header->source);
      destport = (unsigned int)ntohs(tcp_header->dest);
    }

printk(KERN_INFO " **********************************************\n \
Incoming Packet:\n source IP: %pI4\t source PORT: %u;\n \
dest IP: %pI4\t dest PORT: %u;\n \
\t\tproto: %s \
**********************************************",srcip, srcport,destip, destport, ip_header->protocol == 6 ? "TCP\n" : "UDP\n");
    return NF_ACCEPT;
}

unsigned int my_hook_out(unsigned int hooknum,
    struct sk_buff *skb,
    const struct net_device *in,
    const struct net_device *out,
    int (*okfn)(struct sk_buff *))  {

    // get ipheader from socket buffer
    struct iphdr *ip_header = (struct iphdr *)skb_network_header(skb);
    struct udphdr *udp_header;
    struct tcphdr *tcp_header;

    // get ip from ipheader
   void* srcip = &(ip_header->saddr);

  void* destip =&(ip_header->daddr);

    // declare ports and set to zero for now
    unsigned int srcport = 0;
    unsigned int destport = 0;

    if (ip_header->protocol==17)         { // udp
      udp_header = (struct udphdr *)(skb_transport_header(skb)+20);
      srcport = (unsigned int)ntohs(udp_header->source);
      destport = (unsigned int)ntohs(udp_header->dest);
    } else if (ip_header->protocol == 6) { // tcp
      tcp_header = (struct tcphdr *)(skb_transport_header(skb)+20);
      srcport = (unsigned int)ntohs(tcp_header->source);
      destport = (unsigned int)ntohs(tcp_header->dest);
    }

        //printk(" %pI4",&ip_header->saddr);



printk(KERN_INFO " **********************************************\n \
Incoming Packet:\n source IP: %pI4\t source PORT: %u;\n \
dest IP: %pI4\t dest PORT: %u;\n \
\t\t proto: %s \
**********************************************", srcip, srcport, destip, destport, ip_header->protocol == 6 ? "TCP\n" : "UDP\n");
    return NF_ACCEPT;
}

static int init_filter_if(void)
{
  nfho.hook = (void*)my_hook_in;
  nfho.hooknum = NF_INET_LOCAL_IN;
  nfho.pf = PF_INET;
  nfho.priority = NF_IP_PRI_FIRST;

  nf_register_hook(&nfho);

  nfho_out.hook = (void*)my_hook_out;
  nfho_out.hooknum = NF_INET_LOCAL_OUT;
  nfho_out.pf = PF_INET;
  nfho_out.priority = NF_IP_PRI_FIRST;

  nf_register_hook(&nfho_out);

  return 0;
}

static int __init hello_init(void)
{
    printk(KERN_INFO "Hello world!\n");
    init_filter_if();
    return 0;    // Non-zero return means that the module couldn't be loaded.
}

static void __exit hello_cleanup(void)
{
  nf_unregister_hook(&nfho);
  nf_unregister_hook(&nfho_out);
  printk(KERN_INFO "Cleaning up module.\n");
}

module_init(hello_init);
module_exit(hello_cleanup);
