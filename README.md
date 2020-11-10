# hookdns
dns respond by kernel

## how to use
1. seting a domain name that you want hook.
echo "dm specal_domain_name" > /proc/router_domain/dm_ip
2. setting a ip that kernel can response when catching your setting domain name.
echo "ip 192.168.0.1" > /proc/router_domain/dm_ip

## it works
![1](./dns_hook/proc.png)
![1](./dns_hook/dns.png)
