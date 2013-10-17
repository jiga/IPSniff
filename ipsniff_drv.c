/* 	
 * 	IPSniff kernel module
 */

#include "sniff.h"


MODULE_DESCRIPTION("IPSniff Kernel Module");
MODULE_AUTHOR("Praveen, Jignesh");
MODULE_LICENSE("GPL");
MODULE_SUPPORTED_DEVICE("ipsniffer");

MODULE_PARM(DEVNAME,"s");
MODULE_PARM(PROMISCUITY,"b");

MODULE_PARM_DESC(DEVNAME,"Device name of the interface card e.g. eth0");
MODULE_PARM_DESC(PROMISCUITY,"Promiscous Sniffing mode- 1: Enable, 0: Disable");

wait_queue_head_t wq;

// device object
static struct net_device *dev;
static char *DEVNAME="eth0";
static unsigned short PROMISCUITY=0;
static int prom=0;

// circular queue buffer to store packet headers
static int cur=0;
static int tail=0;
static user_buf *net_buff;

// Filtering rules are stored in the rules object
static filter_t *rules;

// general purpose functions					
void set_prom(int);
int byteMatch(unsigned char *pkt, unsigned char *val,int len);

// packet handler function
int sniff_pack_rcv(struct sk_buff *skb, struct net_device *dev, struct
	       packet_type *pt);

// sniffer hook to register with ptype_* 
static struct packet_type sniff_hook = 
{
	__constant_htons(ETH_P_IP),
	NULL,
	sniff_pack_rcv,
	(void*)1,
	NULL
};

// sniffer device vfs functions
int sniff_open(struct inode *, struct file *);
int sniff_read(struct file *, char *,size_t,loff_t *);
int sniff_release(struct inode *, struct file *);
int sniff_ioctl(struct inode *,struct file *, unsigned int, unsigned long);

// sniffer device file operations
struct file_operations sniff_fops = {
  .owner=      THIS_MODULE,
  .read=       sniff_read,
  .ioctl=      sniff_ioctl, 
  .open=       sniff_open,
  .release=    sniff_release 
};

// function to set/reset the device promisciuity
void set_prom(int val){
	if(val==1)
	printk("Setting promiscious mode on\n");
	else
	printk("Setting promiscious mode off\n");

	if ( (dev = __dev_get_by_name(DEVNAME)) == NULL ){
		printk("Error opening device eth0\n");
		return ;
	}
	
	dev->flags = (dev->flags & ~(IFF_PROMISC|IFF_ALLMULTI| \
			IFF_RUNNING))|(dev->gflags & \
			(IFF_PROMISC|IFF_ALLMULTI));
	
	if( netif_running(dev) && netif_carrier_ok(dev)) {
		dev->flags |= IFF_RUNNING;
		dev->flags |= IFF_PROMISC;
	}	

	dev_set_promiscuity(dev,val);
}


/* loading the module */
int init_module(void)
{
	// register the sniff device driver as character driver
	if( register_chrdev(MAJOR,DEVICE_NAME,&sniff_fops)< 0 ){
		printk("Error registering device\n");
		return 1;
	}

	if( (net_buff=(user_buf *)kmalloc(sizeof(*net_buff)*NUM_OF_BUFFS, \
					GFP_KERNEL)) ==NULL ){
		printk("Unable to allocate mem to net_buff\n");
		return 1;
	}
	printk("IPSniff Module Loaded \n");
	
	init_waitqueue_head(&wq);

        return(0);
}

// unloading the module
void cleanup_module(void)
{
	int err=0;
	if ( unregister_chrdev(MAJOR,DEVICE_NAME)< 0 )
	       printk("Error in unregister_chrdev\n");

	kfree(net_buff);	
	printk("IPSniff Module Successfully unloaded \n");
	
	return;
}

// sniff device open function
int sniff_open(struct inode *i, struct file *f){

	printk("Opening IPSniff device\n");

	dev_add_pack(&sniff_hook);
	
	if((rules=(filter_t *)kmalloc(sizeof(filter_t)*10,GFP_KERNEL))==NULL){
		printk("Unable to allocate mem to filter\n");
		return -1;
	}
//	MOD_INC_USE_COUNT;
	return 0;
}

// utility function to copy 
int bytecopy(unsigned char *dest, unsigned char *src,int len)
{
	int j=0,k=0;
	int ret=0;
	
	for(j=len-1,k=0;k<len;k++,j--){
		put_user(*(src++),dest++);
	}	
	
	return ret;
}

// utility function to match a big-endian buffer with little-endian buffer
int byteMatch(unsigned char *pkt, unsigned char *val,int len)
{
	int j=0,k=0;
	int ret=1;
	
	for(j=len-1,k=0;k<len;k++,j--){
		if(pkt[j] == val[k]) continue;
		else{
			ret = 0;
			printk("\nOpps!!!!!! value mismatch\n");
			break;
		}
	}	
	
	return ret;
}

// sniffer device read function
int sniff_read(struct file *filp,char *buf, size_t len, loff_t *n){

	int ret;
	size_t	total_copied = 0;
	user_buf  *local_buf=(user_buf*)buf;	

	if (tail==cur ){
	    if ( filp->f_flags & O_NONBLOCK )
	       return 0;
	    else {
	       //printk("Waiting for packets ... \n");
	       interruptible_sleep_on(&wq);
	    }
	}
	
	for (ret=0;total_copied <len;ret++,total_copied++) {
	    if(tail!=cur && tail < NUM_OF_BUFFS){
		unsigned char *pkt = net_buff[tail].buff;
		unsigned char *value;
		size_t length;
		int r=0;
		int ismatch = 1;
		
		{ // print the raw packet !
			int j=0;
			printk("\n--> pkt = ");
		
			for(j=0;j<56;j++){
				printk("%x%x",((unsigned char)pkt[j]&0xf0)>>4,\
					       (unsigned char)pkt[j]&0x0f);
		
			}
			printk(" <--\n ");
		}

		while(rules[r].filter.offset!=0||rules[r].filter.len!=0 \
				||rules[r].filter.value!=0){
			
			printk("\n~~ rule value = %x ~~",rules[r].filter.value);
			printk(" ~~ pkt value %d = %x%x ~~"
					,pkt[rules[r].filter.offset]
					,(pkt[rules[r].filter.offset]&0xf0)>>4
					,pkt[rules[r].filter.offset]&0x0f
					);

			value = (unsigned char*) &rules[r].filter.value;
			length = (size_t)rules[r].filter.len;
			
			printk("~~ value = %x%x%x%x%x%x%x%x ~~"
					,(value[0]&0xf0)>>4
					,value[0]&0x0f
					,(value[1]&0xf0)>>4
					,value[1]&0x0f
					,(value[2]&0xf0)>>4
					,value[2]&0x0f
					,(value[3]&0xf0)>>4
					,value[3]&0x0f
					,(value[4]&0xf0)>>4
					,value[4]&0x0f
					,(value[5]&0xf0)>>4
					,value[5]&0x0f
					,(value[6]&0xf0)>>4
					,value[6]&0x0f
					,(value[7]&0xf0)>>4
					,value[7]&0x0f
					);
			
			if(! byteMatch(&pkt[rules[r].filter.offset],value, \
						length)){
				
				ismatch = 0;
				total_copied--;
				ret--; // decrement return value
				break;
			}
			r++;
		}
		if(ismatch==1)
	       		memcpy(local_buf+ret,&net_buff[tail].pkt_hdr,NBUF_SIZE);
		tail++;
	    }
	    else break;
	}

	// manage the queue
	if(tail >= NUM_OF_BUFFS)
		tail = 0;	

	return (ret);
}

// sniffer driver ioctl interface function
int sniff_ioctl(struct inode *i,struct file *filp, unsigned int ioctl_num, \
		unsigned long ioctl_param){

	int err=0;
	int size_sniff=0;
	int jig=0;
	
	/* do the critical error checking first */
	if(_IOC_TYPE(ioctl_num)!=MAJOR) return -ENOTTY;
	if(_IOC_NR(ioctl_num) > 15) return -ENOTTY;

	if(_IOC_DIR(ioctl_num) & _IOC_READ)
		err = !access_ok(VERIFY_READ, (void *)ioctl_param, \
				_IOC_SIZE(ioctl_num));
	else if (_IOC_DIR(ioctl_num) & _IOC_WRITE)
		err = !access_ok(VERIFY_WRITE,(void *)ioctl_param, \
				_IOC_SIZE(ioctl_num));
	if(err) return -EFAULT;
	switch(ioctl_num){
		case IOCTL_PROM: 
			prom = ((ioctl_param==1) ? 1:0);
			set_prom(ioctl_param);
			return 0;

		case IOCTL_FILTER:
			do {
				if((size_sniff=copy_from_user( \
					&rules[jig].filter,(((filter_t*)\
					(ioctl_param))+jig),sizeof(filter_t)))\
						!=0){
					printk("\nIOCTLError:copying from ");
					printk("user to kernel .:.:.:.:.:.\n");
					return -1;
				}
			
				printk("Rule %d %d %x \n",\
					rules[jig].filter.offset,\
					rules[jig].filter.len,\
					rules[jig].filter.value);
				jig = jig + 1;

		       }while(rules[jig-1].filter.offset!=0 \
				       || rules[jig-1].filter.len!=0 \
				       || rules[jig-1].filter.value!=0);				break;
		case IOCTL_HARDRESET: 
			printk(" ########### Module remove hack ########");
			printk("resetting module usage count to 0 ..");
			__this_module.uc.usecount.counter=1;
			printk("Module remove hack successfull ;)");
			return 0;
		default:
			break;
	};

	return 0;	
}

// sniffer driver close function
int sniff_release(struct inode *i, struct file *f){
	
	printk("Closing IPSniff device\n");
	dev_remove_pack(&sniff_hook);
	kfree(rules);
	
	if(prom)
		set_prom(-1);
//	MOD_DEC_USE_COUNT;
	return 0;
}

int sniff_pack_rcv(struct sk_buff *skb, struct net_device *dev, \
		struct packet_type *pt) {
	
	printk("Sniffer hook recvd a Pkt of len: %u\n",skb->len);
	lock_kernel();
		
/*	memcpy(&(net_buff[cur].pkt_hdr.eh),skb->mac.ethernet,14);
	memcpy(&(net_buff[cur].pkt_hdr.iph),skb->nh.iph,20);
	memcpy(&(net_buff[cur].pkt_hdr.ich),&skb->h.icmph,20);

	memcpy(&(net_buff[cur].pkt_hdr.mac.raw),skb->mac.ethernet,14);
	memcpy(&(net_buff[cur].pkt_hdr.nh.raw),skb->nh.raw,20);
	memcpy(&(net_buff[cur].pkt_hdr.th.raw),&skb->h.raw,20);
*/

//	memcpy(&net_buff[cur].buff,skb->mac.raw,(skb->len<56)?skb->len:56);
	bytecopy((char*)&net_buff[cur].buff,(char*)skb->mac.raw,(skb->len<56)?skb->len:56);
	unlock_kernel();

	if ( cur == NUM_OF_BUFFS-1){
		printk("sniffer panic: memory overflow\n");
		cur=0;
		return 1;
	}
	else 
		cur++;
	wake_up_interruptible(&wq);
	return skb->len;
}

