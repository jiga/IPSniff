/* 	
 * 	IPSniff kernel module header includes
 */

#include <linux/config.h>
#include <linux/version.h>
#include <linux/module.h>
#include <linux/byteorder/swab.h>
#include <linux/netdevice.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/string.h>
#include <linux/errno.h>
#include <linux/vmalloc.h>
#include <linux/sched.h>
#include <linux/wrapper.h>
#include <linux/net.h>
#include <linux/wait.h>
#include <linux/wrapper.h>
#include <linux/smp_lock.h>
#include <linux/byteorder/generic.h>
#include <asm/uaccess.h>
#include <asm/atomic.h>
#include <linux/init.h>
#include <linux/in.h>

#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/icmp.h>
#include <linux/if_ether.h>
#include <linux/tcp.h>
#include <linux/if_arp.h>
#include <linux/udp.h>

#include "ioctl.h"
#include "filter.h"

#define NBUF_SIZE	56
#define NUM_OF_BUFFS	1000	
#define DEVICE_NAME	"sniffer"

