#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/types.h>
#include <linux/netdevice.h>
#include <linux/skbuff.h>
#include <linux/netfilter_ipv4.h>
#include <linux/inet.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/if_ether.h>
#include <linux/string.h>
#include <linux/delay.h>
#include <linux/netfilter_bridge.h>

#include "domain_map.h"

MODULE_LICENSE("GPL");

extern uint8_t localIP[4];
extern uint16_t localIPV6[8];
extern uint8_t localdm[64];

//UDP pseudo head, used for calibration
typedef struct
{
  unsigned long saddr;
  unsigned long daddr;
  char mbz;//mbz must be zero
  char protocal;
  unsigned short tcpl;//UDP(head+len)
}Fake_UDPheader;

typedef struct {
char name[256];
int len;
}Name_info;

int8_t D_name[] =
{
0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00,
0x00, 0x05, 0x00, 0x04, 0x0a, 0x0a, 0x0a, 0xfe
};

int8_t D_6name[] =
{
0xc0, 0x0c, 0x00, 0x1c, 0x00, 0x01, 0x00, 0x00,
0x00, 0x05, 0x00, 0x10, 0x30, 0x01, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x01
};


/**********************************
description: domain prase
***********************************/
int domain_prase(uint8_t *pos, int len)
{
  int8_t d_buf[64];
  int i = 0;
  if(len <= 0)
    return -1;

  memset(d_buf, 0, sizeof(d_buf));
  for(i = 0; pos[i] && i < len; i++)
  {
    if(pos[i] < 20)
      d_buf[i] = '.';
    else
      d_buf[i] = pos[i];
    if(i>=63)
      return -1;
  }
  if(i == 0)
    return -1;

    printk("d_buf = %s, i = %d\n",d_buf,i);
    extern uint8_t alldns;
    if(alldns == 1)
    {
        //skip s20 checking
        if(memcmp(d_buf, "connectivity.samsung.com.cn", strlen("connectivity.samsung.com.cn")) == 0)
        {
            return -1;
        }
        return 1;
    }
  if(memcmp(d_buf, localdm, strlen(localdm)) == 0)
  {
    printk("domain: %s  len: %d\n", d_buf, strlen(d_buf));
    return 1;
  }

  return -1;
}

#define NIPQUAD(addr) \
  ((unsigned char *)&addr)[0], \
  ((unsigned char *)&addr)[1], \
  ((unsigned char *)&addr)[2], \
  ((unsigned char *)&addr)[3]

static int send_dns(struct net_device* dev, uint8_t dest_addr[ETH_ALEN], uint16_t proto,__be32 source,__be32 dest,__be16 sport ,__be16 dport,Name_info *save_name)
{
  int            ret;
  unsigned char* data;

  int udp_header_len = 8;
  int udp_payload_len = save_name->len;
  int udp_total_len = udp_header_len+udp_payload_len;

  int ip_header_len = 20;
  int ip_payload_len = udp_total_len;
  int ip_total_len = ip_header_len + ip_payload_len;

/* skb */
  struct sk_buff* skb = alloc_skb(ETH_HLEN+ip_total_len, GFP_ATOMIC);//allocate a network buffer
  skb->dev = dev;
  skb->pkt_type = PACKET_OUTGOING;
  skb_reserve(skb, ETH_HLEN+ip_header_len+udp_header_len);//adjust headroom
/* allocate space to data and write it */
  data = skb_put(skb,udp_payload_len);
  memcpy(data, save_name->name, save_name->len);
/* UDP header */
  struct udphdr* uh = (struct udphdr*)skb_push(skb,udp_header_len);
  uh->len = htons(udp_total_len);
  uh->source = sport;
  uh->dest = dport;



/* IP header */
  struct iphdr* iph = (struct iphdr*)skb_push(skb,ip_header_len);
  iph->ihl = ip_header_len/4;//4*5=20 ip_header_len
  iph->version = 4; // IPv4u
  //iph->id = ip_id;
  iph->tos = 0;
  iph->tot_len=htons(ip_total_len);
  iph->frag_off = htons(16384);
  iph->ttl = 64; // Set a TTL.
  iph->protocol = IPPROTO_UDP; //  protocol.
  iph->check = 0;
  iph->saddr = source;
  iph->daddr = dest;

  uh->check = 0;
  uh->check = csum_tcpudp_magic(iph->saddr, iph->daddr, udp_total_len, IPPROTO_UDP, csum_partial(uh, udp_total_len, 0));

  iph->check    = 0;
  iph->check    = ip_fast_csum((unsigned char *)iph, iph->ihl);



  /*changing Mac address */
  struct ethhdr* eth = (struct ethhdr*)skb_push(skb, sizeof (struct ethhdr));//add data to the start of a buffer
  skb->protocol = eth->h_proto = htons(proto);
  skb->no_fcs = 1;
  memcpy(eth->h_source, dev->dev_addr, ETH_ALEN);
  memcpy(eth->h_dest, dest_addr, ETH_ALEN);


  skb->pkt_type = PACKET_OUTGOING;
  ret = dev_queue_xmit(skb);

   if(0 != ret && NULL != skb)//这里前面的nret判断是必须的，不然必定死机
   {
        dev_put(dev);//减少设备的引用计数
        kfree_skb(skb);//销毁数据包
   }
  return 1;
}

static int send_dnsv6(struct net_device* dev, uint8_t dest_addr[ETH_ALEN], uint16_t proto,struct	in6_addr source,struct	in6_addr dest,__be16 sport ,__be16 dport,Name_info *save_name)
{
  int            ret;
  unsigned char* data;

  int udp_header_len = 8;
  int udp_payload_len = save_name->len;
  int udp_total_len = udp_header_len+udp_payload_len;

  int ip_header_len = 40;
  int ip_payload_len = udp_total_len;
  int ip_total_len = ip_header_len + ip_payload_len;

/* skb */
  struct sk_buff* skb = alloc_skb(ETH_HLEN+ip_total_len, GFP_ATOMIC);//allocate a network buffer
  skb->dev = dev;
  skb->pkt_type = PACKET_OUTGOING;
  skb_reserve(skb, ETH_HLEN+ip_header_len+udp_header_len);//adjust headroom
/* allocate space to data and write it */
  data = skb_put(skb,udp_payload_len);
  memcpy(data, save_name->name, save_name->len);
/* UDP header */
  struct udphdr* uh = (struct udphdr*)skb_push(skb,udp_header_len);
  uh->len = htons(udp_total_len);
  uh->source = sport;
  uh->dest = dport;

/* IP header */
  struct ipv6hdr* iph = (struct ipv6hdr*)skb_push(skb,ip_header_len);
  iph->priority = 0;
  iph->version = 6; // IPv4u
  iph->nexthdr = 17; //udp
  //iph->id = ip_id;
  iph->flow_lbl[0] = 0;
  iph->flow_lbl[1] = 0;
  iph->flow_lbl[2] = 0;
  iph->payload_len=htons(ip_payload_len);
  iph->hop_limit = 64;
  iph->saddr = source;
  iph->daddr = dest;



  uh->check = 0;
  uh->check = csum_ipv6_magic(&iph->saddr, &iph->daddr, udp_total_len, IPPROTO_UDP, csum_partial((char *)uh,
			udp_total_len, 0));

  /*changing Mac address */
  struct ethhdr* eth = (struct ethhdr*)skb_push(skb, sizeof (struct ethhdr));//add data to the start of a buffer
  skb->protocol = eth->h_proto = htons(proto);
  skb->no_fcs = 1;
  memcpy(eth->h_source, dev->dev_addr, ETH_ALEN);
  memcpy(eth->h_dest, dest_addr, ETH_ALEN);


  skb->pkt_type = PACKET_OUTGOING;
  ret = dev_queue_xmit(skb);

   if(0 != ret && NULL != skb)//这里前面的nret判断是必须的，不然必定死机
   {
        dev_put(dev);//减少设备的引用计数
        kfree_skb(skb);//销毁数据包
   }
  return 1;
}



/**********************************
description:
***********************************/
unsigned int parsIpv6Dns(struct sk_buff *skb)
{
    struct ipv6hdr *ip;
    struct udphdr *udp;
    uint8_t *p;
    struct net_device *br0;
    br0 = dev_get_by_name(&init_net,"br0");
    Name_info save_name;
    struct ethhdr *eth = eth_hdr(skb);
    uint16_t *p_data = NULL;

    ip = ipv6_hdr(skb);

    if(!ip)
    return NF_ACCEPT;

    if(ip->nexthdr != 17) //get udp data
    return NF_ACCEPT;

    udp = (struct udphdr *)(ip+1);

    if(!udp)
    return NF_ACCEPT;

    if((ntohs(udp->dest) != 53) ) //DNS req
    {
    return NF_ACCEPT;
    }

    //printk("udp->len = %d\n",ntohs(udp->len));

    if(ntohs(udp->len) > 128 || ntohs(udp->len) < 21)
    return NF_ACCEPT;

    p = (uint8_t *)udp + 8 + 12 + 1;
    if(!p)
        return NF_ACCEPT;

    if(domain_prase(p,ntohs(udp->len)-16-8)>0)
    {
        p_data = (uint16_t *)(udp + 1);
        if(p_data == NULL)
            return NF_ACCEPT;
        p_data[1] = htons(0x8580); //FLAGS
        p_data[3] = htons(1); //AuswerRRs
        memset(&save_name,0,sizeof(save_name));
        memcpy(save_name.name,(char *)udp + sizeof(*udp),ntohs(udp->len)-sizeof(*udp));
        save_name.len = ntohs(udp->len)-sizeof(*udp);
        printk("addr type = %x\n",save_name.name[ntohs(udp->len)-sizeof(*udp)-3]);
        if(save_name.name[ntohs(udp->len)-sizeof(*udp)-3] == 0x01) // ipv4 addr
        {
            memcpy(&D_name[sizeof(D_name)-4], localIP, 4);
            memcpy(save_name.name+save_name.len,D_name,sizeof(D_name));
            save_name.len += sizeof(D_name);
        }
        else if(save_name.name[ntohs(udp->len)-sizeof(*udp)-3] == 0x1c) //ipv6 addr
        {
            uint16_t netIpv6[8];
            int i;
            for(i=0; i < 8; i++)
            {
                netIpv6[i] = htons(localIPV6[i]);
            }
            memcpy(&D_6name[sizeof(D_6name)-16], netIpv6, 16);
            memcpy(save_name.name+save_name.len,D_6name,sizeof(D_6name));
            save_name.len += sizeof(D_6name);
        }
        send_dnsv6(br0,eth->h_source,ETH_P_IPV6,ip->daddr,ip->saddr,udp->dest,udp->source,&save_name);

        return NF_DROP;

    }
    return NF_ACCEPT;
}


unsigned int parsIpv4Dns(struct sk_buff *skb)
{
    struct iphdr *ip;
    struct udphdr *udp;
    uint8_t *p;
    struct net_device *br0;
    br0 = dev_get_by_name(&init_net,"br0");
    Name_info save_name;
    struct ethhdr *eth = eth_hdr(skb);
    uint16_t *p_data = NULL;

    ip = ip_hdr(skb);

    if(!ip)
    return NF_ACCEPT;

    if(ip->protocol != 17) //get udp data
    return NF_ACCEPT;

    udp = (struct udphdr *)(ip+1);

    if(!udp)
    return NF_ACCEPT;

    if((ntohs(udp->dest) != 53) ) //DNS req
    {
    return NF_ACCEPT;
    }

    //printk("udp->len = %d\n",ntohs(udp->len));

    if(ntohs(udp->len) > 128 || ntohs(udp->len) < 21)
    return NF_ACCEPT;

    p = (uint8_t *)udp + 8 + 12 + 1;
    if(!p)
    return NF_ACCEPT;

    if(domain_prase(p,ntohs(udp->len)-16-8)>0)
    {
        p_data = (uint16_t *)(udp + 1);
        if(p_data == NULL)
            return NF_ACCEPT;
        p_data[1] = htons(0x8580); //FLAGS
        p_data[3] = htons(1); //AuswerRRs
        memset(&save_name,0,sizeof(save_name));
        memcpy(save_name.name,(char *)udp + sizeof(*udp),ntohs(udp->len)-sizeof(*udp));
        save_name.len = ntohs(udp->len)-sizeof(*udp);
        memcpy(&D_name[sizeof(D_name)-4], localIP, 4);
        memcpy(save_name.name+save_name.len,D_name,sizeof(D_name));
        save_name.len += sizeof(D_name);
        send_dns(br0,eth->h_source,ETH_P_IP,ip->daddr,ip->saddr,udp->dest,udp->source,&save_name);

        return NF_DROP;

    }
    return NF_ACCEPT;
}


unsigned int domain_hook(const struct nf_hook_ops *ops,
             struct sk_buff *skb,
             const struct nf_hook_state *state)
{
    if (!skb)
        return NF_ACCEPT;

    if(skb->protocol == htons(0x0800)) //get ip data
    {
        return parsIpv4Dns(skb);
    }
    else if(skb->protocol == htons(0x86dd)) //get ipv6 data
    {
       return parsIpv6Dns(skb);
    }
    else
    {
        return NF_ACCEPT;
    }
}

struct nf_hook_ops flow_ops = {
  .list =  {NULL,NULL},
  .hook = domain_hook,
  .pf = NFPROTO_BRIDGE,
  .hooknum = NF_BR_PRE_ROUTING,
  .priority = NF_BR_PRI_FIRST+1
};

static int __init m_init(void)
{
  init_dm_ip_moudle();
  nf_register_hook(&flow_ops);

  printk(" init ok\n");

  return 0;
}

static void __exit m_exit(void)
{
  nf_unregister_hook(&flow_ops);
  exit_dm_ip_moudle();
  printk("exit domain_hijack\n");
}

module_init(m_init);
module_exit(m_exit);

/**********************************
description: dns respone data
***********************************/


/**********************************
description: forge dns respone data
***********************************/





