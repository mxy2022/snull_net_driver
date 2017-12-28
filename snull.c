/********************************************************************************* 
 * snull network driver                                                          *
 * Linux kernel version - 4.4.0                                                  *
 * Author: Meixiuyi                                                              *
 *********************************************************************************/

#include <linux/module.h>
#include <linux/init.h>
#include <linux/moduleparam.h>

#include <linux/sched.h>
#include <linux/kernel.h> /* printk() */
#include <linux/slab.h> /* kmalloc() */
#include <linux/errno.h>  /* error codes */
#include <linux/types.h>  /* size_t */
#include <linux/interrupt.h> /* mark_bh */

#include <linux/in.h>
#include <linux/netdevice.h>  /* struct device, and other headers */
#include <linux/etherdevice.h> /* eth_type_trans */
#include <linux/ip.h>          /* struct iphdr */
#include <linux/tcp.h>        /* struct tcphdr */
#include <linux/skbuff.h>

#include "snull.h"

#include <linux/in6.h>
#include <asm/checksum.h>

MODULE_AUTHOR("Alessandro Rubini, Jonathan Corbet");
MODULE_LICENSE("Dual BSD/GPL");

/*
 * Transmitter lockup simulation, normally disabled.
 */
static int lockup = 0;
module_param(lockup, int, 0);

static int timeout = SNULL_TIMEOUT;
module_param(timeout, int, 0);

/*
 * Do we run in NAPI mode?
 */
//#define NEWAPI_POLL;
static int use_napi = 0;
module_param(use_napi, int, 0);

 /*
 * A structure representing an in-flight packet.
 */
struct snull_packet {
    struct snull_packet *next;
    struct net_device *dev;
    int    datalen;
    u8 data[ETH_DATA_LEN];
};

int pool_size = 8;
module_param(pool_size, int, 0);

/*
* This structure is private to each device. It is used to pass
* packets in and out, so there is place for a packet
*/
 struct snull_priv {
    struct net_device_stats stats;
    int status;
    struct snull_packet *ppool;
    struct snull_packet *rx_queue;  /* List of incoming packets */
    int rx_int_enabled;
    int tx_packetlen;
    u8 *tx_packetdata;
    struct sk_buff *skb;
    spinlock_t lock;
    struct net_device *dev;
    //struct napi_struct napi;
};
 
static void snull_tx_timeout(struct net_device *dev);
static void (*snull_interrupt)(int, void *, struct pt_regs *);


/****************************************************************
 * Set up a device's packet pool.
 ****************************************************************/
void snull_setup_pool(struct net_device *dev)
{
    struct snull_priv *priv = netdev_priv(dev);
    int i;
    struct snull_packet *pkt;

    priv->ppool = NULL;
    for (i = 0; i < pool_size; i++)
	{
        pkt = kmalloc (sizeof (struct snull_packet), GFP_KERNEL);
        if (pkt == NULL) 
		{
            printk (KERN_NOTICE "Ran out of memory allocating packet pool\n");
            return;
        }
        pkt->dev = dev;
        pkt->next = priv->ppool;
        priv->ppool = pkt;
    }
}

void snull_teardown_pool(struct net_device *dev)
{
    struct snull_priv *priv = netdev_priv(dev);
    struct snull_packet *pkt;
    
    while ((pkt = priv->ppool)) {
        priv->ppool = pkt->next;
        kfree (pkt);
        /* FIXME - in-flight packets ? */
    }
}   

/*
 * Buffer/pool management.
 */
struct snull_packet *snull_get_tx_buffer(struct net_device *dev)
{
    struct snull_priv *priv = netdev_priv(dev);
    unsigned long flags;
    struct snull_packet *pkt;
    
    spin_lock_irqsave(&priv->lock, flags);
    pkt = priv->ppool;
    priv->ppool = pkt->next;
    if (priv->ppool == NULL) {
        printk (KERN_INFO "Pool empty\n");
        netif_stop_queue(dev);
    }
    spin_unlock_irqrestore(&priv->lock, flags);
    return pkt;
}


void snull_release_buffer(struct snull_packet *pkt)
{
    unsigned long flags;
    struct snull_priv *priv = netdev_priv(pkt->dev);
    
    spin_lock_irqsave(&priv->lock, flags);
    pkt->next = priv->ppool;
    priv->ppool = pkt;
    spin_unlock_irqrestore(&priv->lock, flags);
    if (netif_queue_stopped(pkt->dev) && pkt->next == NULL)
        netif_wake_queue(pkt->dev);

    printk("snull_release_buffer\n");
}

void snull_enqueue_buf(struct net_device *dev, struct snull_packet *pkt)
{
    unsigned long flags;
    struct snull_priv *priv = netdev_priv(dev);

    spin_lock_irqsave(&priv->lock, flags);
    pkt->next = priv->rx_queue;  /* FIXME - misorders packets */
    priv->rx_queue = pkt;
    spin_unlock_irqrestore(&priv->lock, flags);
}

struct snull_packet *snull_dequeue_buf(struct net_device *dev)
{
    struct snull_priv *priv = netdev_priv(dev);
    struct snull_packet *pkt;
    unsigned long flags;

    spin_lock_irqsave(&priv->lock, flags);
    pkt = priv->rx_queue;
    if (pkt != NULL)
        priv->rx_queue = pkt->next;
    spin_unlock_irqrestore(&priv->lock, flags);
    return pkt;
}

/*
 * Enable and disable receive interrupts.
 */
static void snull_rx_ints(struct net_device *dev, int enable)
{
    struct snull_priv *priv = netdev_priv(dev);
    priv->rx_int_enabled = enable;
}

    
/**************************************************************************
 * Open/initialize the board.  This is called (in the current kernel)
 * sometime after booting when the 'ifconfig' program is run.
 **************************************************************************/
 int snull_open(struct net_device *dev)
{
    /* request_region(), request_irq(), ....  (like fops->open) */

    /* 
    * Assign the hardware address of the board: use "\0SNULx", where
    * x is 0 or 1. The first byte is '\0' to avoid being a multicast
    * address (the first byte of multicast addrs is odd).
    */
    /* [cgw]: ����һ���ٵ�Ӳ����ַ��������������ʱ�������ַ�Ǵ������������� */
    memcpy(dev->dev_addr, "\0SNUL0", ETH_ALEN);
    /* -----------------------------------------------------------------------------
    * [cgw]: ��Ϊע�������������������ڶ������������ĵ�ַ����һ���ĵ�ַ���벻һ��
    * ��������������ַ�ֱ�Ϊ\0SNUL0��\0SNUL1
    *------------------------------------------------------------------------------*/
    if (dev == snull_devs[1])
        dev->dev_addr[ETH_ALEN-1]++; /* \0SNUL1 */
    /* [cgw]: �������Ͷ��� */
    netif_start_queue(dev);

    printk("snull_open\n");
    
    return 0;
}

int snull_release(struct net_device *dev)
{
    /* release ports, irq and such -- like fops->close */

    netif_stop_queue(dev); /* can't transmit any more */
    
    printk("snull_release\n");
    
    return 0;
}

/*
 * Configuration changes (passed on by ifconfig)
 */
int snull_config(struct net_device *dev, struct ifmap *map)
{
    if (dev->flags & IFF_UP) /* can't act on a running interface */
        return -EBUSY;

    /* Don't allow changing the I/O address */
    if (map->base_addr != dev->base_addr) {
        printk(KERN_WARNING "snull: Can't change I/O address\n");
        return -EOPNOTSUPP;
    }

    /* Allow changing the IRQ */
    if (map->irq != dev->irq) {
        dev->irq = map->irq;
            /* request_irq() is delayed to open-time */
    }

    printk("snull_config\n");

    /* ignore other fields */
    return 0;
}

/*
 * Receive a packet: retrieve, encapsulate and pass over to upper levels
 */
void snull_rx(struct net_device *dev, struct snull_packet *pkt)
{
    struct sk_buff *skb;
    struct snull_priv *priv = netdev_priv(dev);

    /*
    * The packet has been retrieved from the transmission
    * medium. Build an skb around it, so upper layers can handle it
    */
    /* [cgw]: Ϊ���հ�����һ��skb */
    skb = dev_alloc_skb(pkt->datalen + 2);
    if (!skb) {
        if (printk_ratelimit())
            printk(KERN_NOTICE "snull rx: low on mem - packet dropped\n");
        priv->stats.rx_dropped++;
        goto out;
    }
    /* [cgw]: 16�ֽڶ��룬��IP�ײ�ǰ������Ӳ����ַ�ײ�����ռ14�ֽڣ���ҪΪ������2
    * ���ֽ� 
    */
    skb_reserve(skb, 2); /* align IP on 16B boundary */
    /* [cgw]: ����һ�����ݻ��������ڴ�Ž������� */
    memcpy(skb_put(skb, pkt->datalen), pkt->data, pkt->datalen);

    /* Write metadata, and then pass to the receive level */
    skb->dev = dev;
    if (skb->dev == snull_devs[0]) {
        printk("skb->dev is snull_devs[0]\n");
    } else {
        printk("skb->dev is snull_devs[1]\n");
    }
    /* [cgw]: ȷ������Э��ID */
    skb->protocol = eth_type_trans(skb, dev);

    printk("skb->protocol = %d\n", skb->protocol);
    
    skb->ip_summed = CHECKSUM_UNNECESSARY; /* don't check it */
    /* [cgw]: ͳ�ƽ��հ������ֽ��� */
    priv->stats.rx_packets++;
    priv->stats.rx_bytes += pkt->datalen;
    /* [cgw]: �ϱ�Ӧ�ò� */
    netif_rx(skb);

    printk("snull_rx\n");
    
  out:
    return;
}
   
#if 0
/*******************************************************
 * The poll implementation.
 *********************************************************/
//static int snull_poll(struct napi_struct *napi, int budget)
static int snull_poll(struct net_device *dev, int *budget)
{
    //int npackets = 0;
    //struct sk_buff *skb;
    //struct snull_priv *priv = container_of(napi, struct snull_priv, napi);
    //struct net_device *dev = priv->dev;
    //struct snull_packet *pkt;

    int npackets = 0, quota = min(dev->quota, *budget);
    struct sk_buff *skb;
    struct snull_priv *priv = netdev_priv(dev);
    struct snull_packet *pkt;

    printk("snull_poll\n");
    
    //while (npackets < budget && priv->rx_queue) {
    while (npackets < quota && priv->rx_queue) {
        pkt = snull_dequeue_buf(dev);
        skb = dev_alloc_skb(pkt->datalen + 2);
        if (! skb) {
            if (printk_ratelimit())
                printk(KERN_NOTICE "snull: packet dropped\n");
            priv->stats.rx_dropped++;
            snull_release_buffer(pkt);
            continue;
        }
        skb_reserve(skb, 2); /* align IP on 16B boundary */  
        memcpy(skb_put(skb, pkt->datalen), pkt->data, pkt->datalen);
        skb->dev = dev;
        skb->protocol = eth_type_trans(skb, dev);
        skb->ip_summed = CHECKSUM_UNNECESSARY; /* don't check it */
        netif_receive_skb(skb);
        
            /* Maintain stats */
        npackets++;
        priv->stats.rx_packets++;
        priv->stats.rx_bytes += pkt->datalen;
        snull_release_buffer(pkt);
    }
    /* If we processed all packets, we're done; tell the kernel and reenable ints */
    *budget -= npackets;
    dev->quota -= npackets;
    if (! priv->rx_queue) {
        //napi_complete(napi);
        netif_rx_complete(dev);
        snull_rx_ints(dev, 1);
        return 0;
    }
    /* We couldn't process everything. */
    //return npackets;
    return 1;
}
#endif
        
/*
 * The typical interrupt entry point
 */
static void snull_regular_interrupt(int irq, void *dev_id, struct pt_regs *regs)
{
    int statusword;
    struct snull_priv *priv;
    struct snull_packet *pkt = NULL;
    /*
    * As usual, check the "device" pointer to be sure it is
    * really interrupting.
    * Then assign "struct device *dev"
    */
    struct net_device *dev = (struct net_device *)dev_id;
    /* ... and check with hw if it's really ours */

    /* paranoid */
    if (!dev)
        return;

    /* Lock the device */
    priv = netdev_priv(dev);
    spin_lock(&priv->lock);

    /* [cgw]: �жϲ�������ʲô���͵��жϣ����ջ����ж� */
    /* retrieve statusword: real netdevices use I/O instructions */
    statusword = priv->status;
    
    printk("priv->status = %d\n", priv->status);
    
    priv->status = 0;
    /* [cgw]: ��������ж� */
    if (statusword & SNULL_RX_INTR) {
        /* send it to snull_rx for handling */
        pkt = priv->rx_queue;
        if (pkt) {
            priv->rx_queue = pkt->next;
            /* [cgw]: �������յ����ݣ��ϱ���Ӧ�ò� */
            snull_rx(dev, pkt);
        }
    }
    /* [cgw]: ��������ж� */
    if (statusword & SNULL_TX_INTR) {
        /* [cgw]: ͳ���ѷ��͵İ��������ֽ��������ͷ���������ڴ� */
        /* a transmission is over: free the skb */
        priv->stats.tx_packets++;
        priv->stats.tx_bytes += priv->tx_packetlen;
        dev_kfree_skb(priv->skb);
    }

    /* Unlock the device and we are done */
    spin_unlock(&priv->lock);
    if (pkt) snull_release_buffer(pkt); /* Do this outside the lock! */

    printk("snull_regular_interrupt\n");

    return;
}

#ifdef NEWAPI_POLL
/*******************************************
 * A NAPI interrupt handler.
 *******************************************/
static void snull_napi_interrupt(int irq, void *dev_id, struct pt_regs *regs)
{
    int statusword;
    struct snull_priv *priv;

    /*
    * As usual, check the "device" pointer for shared handlers.
    * Then assign "struct device *dev"
    */
    struct net_device *dev = (struct net_device *)dev_id;
    /* ... and check with hw if it's really ours */

    printk("snull_napi_interrupt\n");

    /* paranoid */
    if (!dev)
        return;

    /* Lock the device */
    priv = netdev_priv(dev);
    spin_lock(&priv->lock);

    /* retrieve statusword: real netdevices use I/O instructions */
    statusword = priv->status;
    priv->status = 0;
    if (statusword & SNULL_RX_INTR) {
        snull_rx_ints(dev, 0);  /* Disable further interrupts */
        //napi_schedule(&priv->napi);
        netif_rx_schedule(dev);
    }
    if (statusword & SNULL_TX_INTR) {
            /* a transmission is over: free the skb */
        priv->stats.tx_packets++;
        priv->stats.tx_bytes += priv->tx_packetlen;
        dev_kfree_skb(priv->skb);
    }

    /* Unlock the device and we are done */
    spin_unlock(&priv->lock);
    return;
}
#endif

/***********************************************
 * Transmit a packet (low level interface)
 ***********************************************/
static void snull_hw_tx(char *buf, int len, struct net_device *dev)
{
    /*
    * This function deals with hw details. This interface loops
    * back the packet to the other snull interface (if any).
    * In other words, this function implements the snull behaviour,
    * while all other procedures are rather device-independent
    */
    struct iphdr *ih;
    struct net_device *dest;
    struct snull_priv *priv;
    u32 *saddr, *daddr;
    struct snull_packet *tx_buffer;
    
    /* I am paranoid. Ain't I? */
    if (len < sizeof(struct ethhdr) + sizeof(struct iphdr)) {
        printk("snull: Hmm... packet too short (%i octets)\n",
                len);
        return;
    }

    /* ---------------------------------------------------------------
     * [cgw]: ��ӡ�ϲ�Ӧ��(��ping)Ҫ���������������
     * ������ĸ�ʽΪ:
     * 14�ֽ���̫���ײ�+20�ֽ�IP��ַ�ײ�+8�ֽ�ICMP��ַ�ײ�+n�ֽ�����
     *----------------------------------------------------------------*/
    
    if (1) { /* enable this conditional to look at the data */
        int i;
        PDEBUG("len is %i\n" KERN_DEBUG "data:",len);
        /* [cgw]: 14�ֽ���̫���ײ� */
        for (i=0 ; i<14; i++)
            printk(" %02x",buf[i]&0xff);
        printk("\n");

        /* [cgw]: 20�ֽ�IP��ַ�ײ� */
        for (i=14 ; i<34; i++)
            printk(" %02x",buf[i]&0xff);
        printk("\n");
#if 0
        /* [cgw]: 20�ֽ�TCP��ַ�ײ� */
        for (i=34 ; i<54; i++)
            printk(" %02x",buf[i]&0xff);
        printk("\n");
#endif
         /* 8bytes ICMP header - ping */
        for (i = 34; i < 42; i++)
        {
            printk(" %02x", buf[i]&0xff);
        }
        printk("\n");
        
        /* [cgw]: n�ֽ����� */
        for (i = 43 ; i<len; i++)
            printk(" %02x",buf[i]&0xff);
        printk("\n");
    }
    /*----------------------------------------------------------
     * Ethhdr is 14 bytes, but the kernel arranges for iphdr
     * to be aligned (i.e., ethhdr is unaligned)
     *----------------------------------------------------------*/
    /* [cgw]: ��ȡ���غ�Ŀ��IP��ַ */
    ih = (struct iphdr *)(buf+sizeof(struct ethhdr));
    saddr = &ih->saddr;
    daddr = &ih->daddr;
    
    printk("ih->protocol = %d is buf[23]\n", ih->protocol);
    printk("saddr = %d.%d.%d.%d\n", *((u8 *)saddr + 0), *((u8 *)saddr + 1), *((u8 *)saddr + 2), *((u8 *)saddr + 3));
    printk("daddr = %d.%d.%d.%d\n", *((u8 *)daddr + 0), *((u8 *)daddr + 1), *((u8 *)daddr + 2), *((u8 *)daddr + 3));

    /* [cgw]: �ı䱾�غ�Ŀ��IP��ַ�ĵ������ֽڵ����λ����ԭ����0�����Ϊ1��ԭ����1�����Ϊ0
    */
    ((u8 *)saddr)[2] ^= 1; /* change the third octet (class C) */
    ((u8 *)daddr)[2] ^= 1;

    /* [cgw]: ���¼���У�飬��ΪIP�Ѹı� */
    ih->check = 0;        /* and rebuild the checksum (ip needs it) */
    ih->check = ip_fast_csum((unsigned char *)ih,ih->ihl);

    /* [cgw]: ��ӡ���ĺ��IP��ַ����TCP��ַ��
    */
    if (dev == snull_devs[0])
        //PDEBUGG("%08x:%05i --> %08x:%05i\n",
        printk("%08x:%05i --> %08x:%05i\n",
                ntohl(ih->saddr),ntohs(((struct tcphdr *)(ih+1))->source),
                ntohl(ih->daddr),ntohs(((struct tcphdr *)(ih+1))->dest));
    else
        //PDEBUGG("%08x:%05i <-- %08x:%05i\n",
        printk("%08x:%05i <-- %08x:%05i\n",
                ntohl(ih->daddr),ntohs(((struct tcphdr *)(ih+1))->dest),
                ntohl(ih->saddr),ntohs(((struct tcphdr *)(ih+1))->source));

    /*
    * Ok, now the packet is ready for transmission: first simulate a
    * receive interrupt on the twin device, then  a
    * transmission-done on the transmitting device
    */
    /* [cgw]: ���Ŀ�������豸 */
    dest = snull_devs[dev == snull_devs[0] ? 1 : 0];
    
    if (dev == snull_devs[0]) {
        printk("snull_devs[0]\n");
    } else {
        printk("snull_devs[1]\n");
    }
    
    priv = netdev_priv(dest);
    /* [cgw]: ȡ��һ���ڴ������������� */
    tx_buffer = snull_get_tx_buffer(dev);
    /* [cgw]: �������ݰ���С */
    tx_buffer->datalen = len;
    
    printk("tx_buffer->datalen = %d\n", tx_buffer->datalen);

    /* [cgw]: ��䷢������������ */
    memcpy(tx_buffer->data, buf, len);
    /* [cgw]: �ѷ��͵�����ֱ�Ӽ��뵽���ն��У������൱�ڱ�������Ҫ���͵�����
    * �Ѿ���Ŀ������ֱ�ӽ��յ���
    */
    snull_enqueue_buf(dest, tx_buffer);
    /* [cgw]: ��������ж�ʹ�ܣ����Ҳ��ģ��Ľ����жϣ���Ϊ�����Ѿ�ģ�����
    * �����ݣ��������̲���һ���ж�
    */
    if (priv->rx_int_enabled) {
        priv->status |= SNULL_RX_INTR;
        printk("priv->status = %d\n", priv->status);
        /* [cgw]: ִ�н����ж� */
        snull_interrupt(0, dest, NULL);
        printk("snull_interrupt(0, dest, NULL);\n");
    }

    /* [cgw]: ��ñ���������˽������ָ�� */
    priv = netdev_priv(dev);
    /* [cgw]: �ѱ�������Ҫ���͵����ݴ浽˽�����ݻ����������Ų���һ�������ж�
    */
    priv->tx_packetlen = len;
    priv->tx_packetdata = buf;
    priv->status |= SNULL_TX_INTR;
    printk("[meixiuyi] lockup = %d", lockup);
    if (lockup && ((priv->stats.tx_packets + 1) % lockup) == 0) {
            /* Simulate a dropped transmit interrupt */
        netif_stop_queue(dev);
        PDEBUG("Simulate lockup at %ld, txp %ld\n", jiffies,
                (unsigned long) priv->stats.tx_packets);
    }
    else {
        /* [cgw]: ����һ�������ж� */
        snull_interrupt(0, dev, NULL);
        printk("snull_interrupt(0, dev, NULL);\n");
    }
}

/*
 * Transmit a packet (called by the kernel)
 */
int snull_tx(struct sk_buff *skb, struct net_device *dev)
{
    int len;
    char *data, shortpkt[ETH_ZLEN];
    struct snull_priv *priv = netdev_priv(dev);

    /* [cgw]: ��ȡ�ϲ���Ҫ���͵����ݺͳ��� */
    data = skb->data;
    len = skb->len;

     /* skb->len - hard_header+IP+ICMP(ping)+DATA */
    printk("skb->len = %d\n", skb->len);
    
    if (len < ETH_ZLEN) {
        memset(shortpkt, 0, ETH_ZLEN);
         memcpy(shortpkt, skb->data, skb->len);
        len = ETH_ZLEN;
        data = shortpkt;
    }
    /* [cgw]: ��ʼ����ʱ��أ����ڴ����ͳ�ʱ */
    dev->trans_start = jiffies; /* save the timestamp */

    /* Remember the skb, so we can free it at interrupt time */
    priv->skb = skb;
    
    printk("snull_tx\n");

    /* actual deliver of data is device-specific, and not shown here */
    /* [cgw]: ģ������ݰ�д��Ӳ����ͨ��Ӳ�����ͳ�ȥ����ʵ���ϲ��� */
    snull_hw_tx(data, len, dev);

    return 0; /* Our simple device can not fail */
}

/*
 * Deal with a transmit timeout.
 */
void snull_tx_timeout (struct net_device *dev)
{
    struct snull_priv *priv = netdev_priv(dev);

    PDEBUG("Transmit timeout at %ld, latency %ld\n", jiffies,
            jiffies - dev->trans_start);
        /* Simulate a transmission interrupt to get things moving */
    priv->status = SNULL_TX_INTR;
    snull_interrupt(0, dev, NULL);
    priv->stats.tx_errors++;
    netif_wake_queue(dev);

    printk("snull_tx_timeout\n");
    
    return;
}


/*
 * Ioctl commands 
 */
int snull_ioctl(struct net_device *dev, struct ifreq *rq, int cmd)
{
    PDEBUG("ioctl\n");
    printk("ioctl\n");
    return 0;
}

/*
 * Return statistics to the caller
 */
struct net_device_stats *snull_stats(struct net_device *dev)
{
    struct snull_priv *priv = netdev_priv(dev);

    printk("snull_stats\n");
    
    return &priv->stats;
}

/************************************************************************
 * This function is called to fill up an eth header, since arp is not
 * available on the interface
 ************************************************************************/
int 
snull_header_parse
(
  const struct sk_buff *skb, 
  unsigned char *haddr
)
{
    struct ethhdr *eth = (struct ethhdr *) skb->data;
    struct net_device *dev = skb->dev;
    
    memcpy(eth->h_source, dev->dev_addr, dev->addr_len);
    memcpy(eth->h_dest, dev->dev_addr, dev->addr_len);
    eth->h_dest[ETH_ALEN-1]  ^= 0x01;  /* dest is us xor 1 */

    //memcpy(haddr, eth->h_source, ETH_ALEN);
	
    printk("snull_header_parse\n");
    
    return ETH_ALEN;
}



/*************************************************************************************
 * snull_hard_header - 
 *       Create hardware header according to the saddr and daddr has been retrieved.
 *
 * @dev: source device
 * @type: Ethernet type field
 * @len: packet length

 * It was called when excute ping cmd - example.
 *************************************************************************************/
static int 
snull_hard_header(struct sk_buff *skb, struct net_device *dev,
                unsigned short type, const void *daddr, const void *saddr,
                unsigned int len)              
{
    struct ethhdr *eth = (struct ethhdr *)skb_push(skb,ETH_HLEN);

    printk("len = %d\n", len);

    printk("type = %02x\n", type); //ETH_P_IP    0x0800        /* Internet Protocol packet    */

    /* --------------------------------------------------------------------------
     * htons�ǽ����ͱ����������ֽ�˳��ת��������ֽ�˳�� 
     * ���������ڵ�ַ�ռ�洢��ʽ��Ϊ����λ�ֽڴ�����ڴ�ĵ͵�ַ��
     *---------------------------------------------------------------------------*/
    eth->h_proto = htons(type);
    printk("h_proto = %d\n", eth->h_proto);
    
    printk("addr_len = %d\n", dev->addr_len);
    printk("dev_addr = %02x.%02x.%02x.%02x.%02x.%02x\n", 
      dev->dev_addr[0], dev->dev_addr[1], dev->dev_addr[2], dev->dev_addr[3], dev->dev_addr[4], dev->dev_addr[5]);

    if (saddr) {
        printk("saddr = %02x.%02x.%02x.%02x.%02x.%02x\n", 
          *((unsigned char *)saddr + 0), *((unsigned char *)saddr + 1), *((unsigned char *)saddr + 2), *((unsigned char *)saddr + 3), *((unsigned char *)saddr + 4), *((unsigned char *)saddr + 5));
    }

    if (daddr) {
        printk("daddr = %02x.%02x.%02x.%02x.%02x.%02x\n", *((unsigned char *)daddr + 0), *((unsigned char *)daddr + 1), *((unsigned char *)daddr + 2), *((unsigned char *)daddr + 3), *((unsigned char *)daddr + 4), *((unsigned char *)daddr + 5));
    }

    /* [cgw]: �ϲ�Ӧ��Ҫ��������ʱ��ͨ���²����Ӳ����ַ�����ܾ������͵��Ǹ�Ŀ������
    */
    memcpy(eth->h_source, saddr ? saddr : dev->dev_addr, dev->addr_len);
    memcpy(eth->h_dest,  daddr ? daddr : dev->dev_addr, dev->addr_len);
    printk("h_source = %02x.%02x.%02x.%02x.%02x.%02x\n", eth->h_source[0], eth->h_source[1], eth->h_source[2],eth->h_source[3], eth->h_source[4], eth->h_source[5]);
    printk("h_dest = %02x.%02x.%02x.%02x.%02x.%02x\n", eth->h_dest[0], eth->h_dest[1], eth->h_dest[2], eth->h_dest[3], eth->h_dest[4], eth->h_dest[5]);

    /* ---------------------------------------------------------------------------------------
     * [cgw]: ����Ŀ������Ӳ����ַ��������������Ŀ������Ӳ����ַ�����һ���ֽڵ������Чλ
     * ���෴��ϵ����������\0SNUL0�Ļ���Ŀ�����\0SNUL1�����߱�����\0SNUL1��Ŀ�����\0SNUL0
     *----------------------------------------------------------------------------------------*/
    eth->h_dest[ETH_ALEN-1]  ^= 0x01;  /* dest is us xor 1 */
    printk("h_dest[ETH_ALEN-1] ^ 0x01 = %02x\n", eth->h_dest[ETH_ALEN-1]);

     /* hard_header_len - maximum hardware header length */
    printk("hard_header_len = %d\n", dev->hard_header_len);
    
   return (dev->hard_header_len);
}

/*********************************************************
 * The "change_mtu" method is usually not needed.
 * If you need it, it must be like this.
 *********************************************************/
int snull_change_mtu(struct net_device *dev, int new_mtu)
{
    unsigned long flags;
    struct snull_priv *priv = netdev_priv(dev);
    spinlock_t *lock = &priv->lock;
    
    /* check ranges */
    if ((new_mtu < 68) || (new_mtu > 1500))
        return -EINVAL;
    /*
    * Do anything you need, and the accept the value
    */
    spin_lock_irqsave(lock, flags);
    dev->mtu = new_mtu;
    spin_unlock_irqrestore(lock, flags);
    return 0; /* success */
}

static const struct header_ops snull_header_ops = {
    .create    = snull_hard_header,
    .parse     =  snull_header_parse,
};

static const struct net_device_ops snull_netdev_ops = {
    .ndo_open            = snull_open,
    .ndo_stop            = snull_release,
    .ndo_start_xmit      = snull_tx,
    .ndo_do_ioctl        = snull_ioctl,
    .ndo_set_config      = snull_config,
    .ndo_get_stats       = snull_stats,
    .ndo_change_mtu      = snull_change_mtu,
    .ndo_tx_timeout      = snull_tx_timeout
};

/*******************************************************
 * The init function (sometimes called probe).
 * It is invoked by register_netdev()
 *******************************************************/
void snull_init(struct net_device *dev)
{
    struct snull_priv *priv;
 
    /* *********************
     * Then, assign other fields in dev, using ether_setup() and some
     * hand assignments
     *****************************************************************/
    ether_setup(dev); /* assign some of the fields */
    dev->watchdog_timeo = timeout;
    
    dev->netdev_ops = &snull_netdev_ops;
    dev->header_ops = &snull_header_ops;

#if 0 /* Old kernel version */
    dev->hard_header = snull_header;
    dev->rebuild_header = snull_rebuild_header;
    
    dev->open = snull_open;
    dev->stop = snull_release;
    dev->hard_start_xmit = snull_tx;
    dev->do_ioctl = snull_ioctl;
    dev->set_config = snull_config;
    dev->get_stats = snull_stats;
    dev->change_mtu = snull_change_mtu;
    dev->tx_timeout = snull_tx_timeout;
#endif
   
    /* keep the default flags, just add NOARP */
    dev->flags          |= IFF_NOARP;
    dev->features       |= NETIF_F_HW_CSUM;
    //dev->hard_header_cache = NULL;

    /* ********
     * Then, initialize the priv field. This encloses the statistics
     * and a few private fields.
     ***************************************/
    priv = netdev_priv(dev);
    /* not support Poll method
    #if 0 
    if (use_napi) {
        netif_napi_add(dev, &priv->napi, snull_poll,2);
    } 
    #else
    if (use_napi) {
        dev->poll = snull_poll; //��ѯ��ʽ
        dev->weight = 2;
    }
    #endif
    */
    memset(priv, 0, sizeof(struct snull_priv));
    spin_lock_init(&priv->lock);
    snull_rx_ints(dev, 1);        /* enable receive interrupts */
    snull_setup_pool(dev);

    printk("snull_init\n");
}

/* *********************
 * Define two devices in array snull_devs[]
 * *****************************************/
struct net_device *snull_devs[2];
 
/***********************************************
 * Finally, the module stuff
 ***********************************************/
void snull_cleanup(void)
{
    int i;
    
    for (i = 0; i < 2;  i++) {
        if (snull_devs[i]) {
            unregister_netdev(snull_devs[i]);
            snull_teardown_pool(snull_devs[i]);
            free_netdev(snull_devs[i]);
        }
    }
    return;
}

/*********************************************************
 *********************************************************/
int snull_init_module(void)
{
    int result, i, ret;

    /* Select a interrupt func */
#ifdef NEWAPI_POLL
    snull_interrupt = use_napi?snull_napi_interrupt:snull_regular_interrupt;
#else
    snull_interrupt = snull_regular_interrupt;
#endif

    /* ------------------------------------
     * Allocate the memory space for devices, and check success.
     * The old kernel release - alloc_netdev only have 3 parameters.
     * ---------------------------------------------------------------*/
    snull_devs[0] = alloc_netdev(sizeof(struct snull_priv), 
                            "sn%d", NET_NAME_UNKNOWN, snull_init);
    snull_devs[1] = alloc_netdev(sizeof(struct snull_priv), 
                            "sn%d", NET_NAME_UNKNOWN, snull_init);
    if (snull_devs[0] == NULL || snull_devs[1] == NULL)
      goto out;

    ret = -ENODEV;
    for (i = 0; i < 2;  i++)
    {
        if ((result = register_netdev(snull_devs[i])))
        {
            printk("snull: error %i registering device \"%s\"\n", result, snull_devs[i]->name);
        }
        else
        {
            ret = 0;
        }
    }

    printk("snull_init_module\n");
            
  out:
    if (ret) 
        snull_cleanup();
    return ret;
}

module_init(snull_init_module);
module_exit(snull_cleanup);


