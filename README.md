# iran_resolver
iran_resolver is a coredns plugin to generate hosts file for banned and sanctioned urls.
It's useful to create something liked https://shecan.ir/; A DNS server witch resolve banned and sanctioned urls with ur custom server ip

## config 
example:
```
iran_resolver {
    dns-to-check 78.157.42.101:53 10.202.10.202:53  # Reqiered

    sanction-search develop.403 electro
    ban-search 10.10.34.35

    sanction-hosts-file /etc/hosts_dir/hosts-sanction
    ban-hosts-file /etc/hosts_dir/hosts-ban

    result-hosts-file /etc/hosts_dir/hosts-ir

    sanction-dest-server-ips 10.10.10.10 20.20.20.20 # Reqiered
    ban-dest-server-ips 40.40.40.40 30.30.30.30 # Reqiered

    sanction-buffer-size 10
    ban-buffer-size 10
}
```