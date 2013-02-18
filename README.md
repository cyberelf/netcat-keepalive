Netcat Keep alive
===============

### Add [tcp keepalive](http://tldp.org/HOWTO/TCP-Keepalive-HOWTO/index.html) parameters for netcat. ###

The following new switches are provided to config keepalive parameters:

>-K              Turn on TCP Keepalive

>-O secs         TCP keepalive timeout

>-I secs         TCP keepalive interval

>-P count        TCP keepalive probe count


If any of "-O" "-I" "-P" not specified when -K is on, it will use kernel parameters by default. On linux for example, it will use:

>sysctl -a  | grep keepalive

>  net.ipv4.tcp_keepalive_time = 7200

>  net.ipv4.tcp_keepalive_probes = 9

>  net.ipv4.tcp_keepalive_intvl = 75

COMPILE FROM SOURCE
-----

### COMPILATION

make [platform_name]. For example:

>`make linux`
