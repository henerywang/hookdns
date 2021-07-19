

#include <linux/ctype.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/fs.h>
#include <linux/seq_file.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/init.h>
#include <linux/ip.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/vmalloc.h>
#include <linux/module.h>
#include <linux/netdevice.h>
#include <linux/netfilter.h>
#include <linux/inetdevice.h>
#include <linux/skbuff.h>
#include <linux/socket.h>
#include <linux/string.h>
#include <linux/syscalls.h>
#include <linux/tcp.h>
#include <linux/uaccess.h>
#include <linux/unistd.h>
#include <linux/version.h>
#include <linux/mman.h>
#include <linux/spinlock.h>
#include <linux/rcupdate.h>
#include <linux/highmem.h>
#include <net/netfilter/nf_conntrack.h>
#include <net/ip.h>
#include <net/tcp.h>
#include <net/udp.h>
#include <linux/proc_fs.h>


//
static struct proc_dir_entry *proc_entry;
static struct proc_dir_entry *flow_root;

uint8_t localIP[4]={0x0a, 0x0a, 0x0a, 0xfe}; //IP
uint16_t localIPV6[8]={0x3001, 0x0000,
0x0000, 0x0000, 0x0000, 0x0000,
0x0000, 0x0001}; //IP


uint8_t localdm[64]="mydomain.com"; //domain
uint8_t alldns = 0;

static int dm_ip_read(struct seq_file *s, void *v)
{
  seq_printf(s, "%s %d.%d.%d.%d\n", localdm, localIP[0], localIP[1], localIP[2], localIP[3]);
  seq_printf(s, "%s %04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x\n", localdm, localIPV6[0], localIPV6[1], localIPV6[2], localIPV6[3],
            localIPV6[4],localIPV6[5],localIPV6[6],localIPV6[7]);
  seq_printf(s, "hook all dns %u\n",alldns);
  return 0;
}


void str__(int8_t *p)
{
  while(*p++)
  {
    if(*p == '.')
      *p = ' ';
  }
}

/******************
return: the count that be written success
note: don't return 0, thus system will enter into bad loop
*******************/
//ssize_t dm_ip_write (struct file *, const char __user *, size_t, loff_t *);

ssize_t dm_ip_write(struct file *file, const char __user *buffer, size_t count, loff_t *data)
{
  int8_t buf[64];
  int8_t tmpbuf1[8], tmpbuf2[60] = {0};
  int len = 0;
  int err = 1;

  memset(buf, 0, sizeof(buf));
  memset(tmpbuf1, 0, sizeof(tmpbuf1));
  //

  len = sizeof(buf)-1;
  if(count<len)
    len = count;

  if(copy_from_user(buf, buffer, len))
  {
    printk("dm_ip_write fail!\n");
    goto result;
  }

  err = sscanf(buf, "%s %s", tmpbuf1, tmpbuf2);



  if(strncmp(tmpbuf1, "ip", strlen("ip")) == 0)
  {
    //ip
    int a, b, c, d;
    str__(tmpbuf2);
    err = sscanf(tmpbuf2, "%d %d %d %d", &a, &b, &c, &d);
    if(err>0)
    {
      localIP[0] = a & 0x00ff;
      localIP[1] = b & 0x00ff;
      localIP[2] = c & 0x00ff;
      localIP[3] = d & 0x00ff;
    }

  }

  if(strncmp(tmpbuf1, "ipv6", strlen("ipv6")) == 0)
  {
    //ipv6
    uint16_t tmpIpv6[8] = {0};
    str__(tmpbuf2);
    err = sscanf(tmpbuf2, "%x:%x:%x:%x:%x:%x:%x:%x", &tmpIpv6[0], &tmpIpv6[1], &tmpIpv6[2], &tmpIpv6[3],
        &tmpIpv6[4],&tmpIpv6[5],&tmpIpv6[6],&tmpIpv6[7]);
    if(err>0)
    {
        memcpy(localIPV6,tmpIpv6,sizeof(tmpIpv6));
    }

  }
  else if(strncmp(tmpbuf1, "dm", strlen("dm")) == 0)
  {
    //domain
    memcpy(localdm, tmpbuf2, strlen(tmpbuf2)+1);
  }
    else if(strncmp(tmpbuf1, "alldns", strlen("alldns")) == 0)
    {
        alldns = tmpbuf2[0]-'0';
    }

result:
  return len;
}
int dns_redirect_proc_open(struct inode *inode, struct file *file)
{
    return(single_open(file, dm_ip_read, NULL));
}

static const struct file_operations dns_redirect_set_proc_fops = {
    .open  = dns_redirect_proc_open,
    .write  = dm_ip_write,
    .read           = seq_read,
    .llseek         = seq_lseek,
    .release        = single_release,


};


/**********************************
description: make a folder and a file, and appoint callback function write and read
***********************************/
int init_dm_ip_moudle(void)
{
  int ret = 0;

  flow_root = proc_mkdir("router_domain", NULL);
  if(flow_root == NULL)
  {
    printk("create dir router_domain fail\n");
    return -1;
  }

    proc_entry = proc_create("dm_ip", 0644, flow_root, &dns_redirect_set_proc_fops);
  if(proc_entry==NULL)
  {
    printk("fortune :couldn't create proc entry\n");
    ret = -2;
    return ret;
  }

  return ret;
}


void exit_dm_ip_moudle(void)
{
  remove_proc_entry("dm_ip", flow_root);
    remove_proc_entry("router_domain", NULL);
}


