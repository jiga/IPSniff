#include <linux/ioctl.h>

#define MAJOR		100
#define IOCTL_PROM	_IOR(MAJOR,0,int)
#define IOCTL_FILTER	_IOR(MAJOR,1,int)
#define FILTER_SIP	_IOW(MAJOR,2,filter_t)
#define FILTER_DIP	_IOW(MAJOR,3,filter_t)	
#define FILTER_SPORT	_IOW(MAJOR,4,filter_t)
#define FILTER_DPORT	_IOW(MAJOR,5,filter_t)
#define FILTER_PROTO	_IOW(MAJOR,6,filter_t)
#define FILTER_FAMILY	_IOW(MAJOR,7,filter_t)
#define IOCTL_HARDRESET	_IO(MAJOR,15)

