# unshare-fun
Experiments with unshare

## per-app-crypted-home.py
This script uses an encrypted container as home directory for the application given as argument. It unshares mountpoint, network, IPC and UTS namespaces. The script is designed as pretty advanced proof of concept application sandboxing wrapper. Shadowing of original home, "/run" and "/tmp" directories is intentional. To be able to use unshare/setns, mount, dm-crypt and configure network the script needs sudo to get root access. To use X it preserves "/tmp/.X11-unix" and handles Xauthority. To run X applications you need to pass "--xauth". To allow applications to access internet use "--skip-network" or "--nat" option. If you pass "--skip-network" options "--tcpdump" and "--nat" will not work.

Warning: Option "--nat" will enable IP forwarding on your default network interfaces and WILL NOT remove thoses changes on tear down. Also the script preserves environment variables while switching between your user and root.

Info: This script is Python rewrite of "per-app-crypted-home.bash" including additional features.

### Usage
```

```

### Simple example
```sh
# start firefox without virtual network
./per-app-crypted-home.py --skip-network --xauth firefox
# start firefox with virtual network and NAT (see warning)
./per-app-crypted-home.py --nat --xauth firefox
```
### Advanced examples
```sh
# key file, pipe, exit code and quite example
head -c32 /dev/random > ~/secret_key
echo "hello world"|./per-app-crypted-home.py --key-file ~/secret_key --quiet -- "$SHELL" -c "cat; exit 42"
# application arguments with quote example
./per-app-crypted-home.py --key-file ~/secret_key "$SHELL" -c "pwd; ls -la; mount |grep \"$HOME\"; echo \"sleeping 1m so you can try to find this mount in another shell. Hint: it won't be easy.\"; sleep 1m"
# resize shrink example
./per-app-crypted-home.py --resize 128M --key-file ~/secret_key -- "$SHELL" -c "df -h ."
# quiet resize expand example
./per-app-crypted-home.py --quiet --resize 512M --key-file ~/secret_key -- "$SHELL" -c "df -h ."
# capture ip activities (excluding TCP stream data)
./per-app-crypted-home.py --xauth --nat --tcpdump --key-file ~/secret_key chromium
ls -lh chromium*.pcap
# bind mount $HOME/Downloads into private container
./per-app-crypted-home.py --key-file ~/secret_key -b Downloads "$SHELL" -c "ls -la Downloads"
# spoof network MAC address
./per-app-crypted-home.py --key-file ~/secret_key --mac-address c0:01:da:1a:d0:0d "$SHELL" -c "ip link |grep link/ether"
# CPU quota options
./per-app-crypted-home.py --key-file ~/secret_key --cpu-quota 0.1 "$SHELL" -c 'for i in $( seq 1 $( grep "^processor" /proc/cpuinfo |wc -l ) ); do while true; do true; done & done; top'
# hiding host /tmp, /run and /home
./per-app-crypted-home.py --key-file ~/secret_key "$SHELL" -c "ls -la /tmp /run /home"
```

