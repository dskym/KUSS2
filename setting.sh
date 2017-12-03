sudo route add -net 1.2.3.0 netmask 255.255.255.0 dev enp0s3
sudo sysctl -w net.ipv4.ip_forward=1

