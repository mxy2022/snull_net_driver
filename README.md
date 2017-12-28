# snull_net_driver
Realize a virtual net driver on Ubuntu (Linux kernel version - 4.4.0)

# configture in Ubuntu
1 /etc/hosts
*----------------------*
192.168.0.1 local0
192.168.0.2 remote0
192.168.1.2 local1
192.168.1.1 remote1
*----------------------*
2 /etc/networks
*----------------------*
snullnet0 192.128.0.0
snullnet1 192.128.1.0
*----------------------*

sudo insmod snull.ko // Load snull driver
ifconfig sn0 local0
ifconfig sn1 local1  // Open sn0 and sn1
