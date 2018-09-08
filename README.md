# unshare-fun
Experiments with unshare

## per-app-crypted-home.py
This script uses an encrypted container as home directory for the application given as argument. It unshares mountpoint, network, IPC and UTS namespaces. The script is designed as proof of concept application sandboxing wrapper. Shadowing of original home directory is intentional. To be able to mount, use dm-crypt and configure network the script needs sudo to get root access. To use X it preserves environment variables while switching between your user and root. To run X applications you need to pass "--skip-network" and "--skip-uts" or "--xauth-add" and "--nat". If you pass "--skip-network" than "--tcpdump" and "--nat" won't work.

Warning: Option "--nat" will enable IP forwarding on your default network interface and WILL NOT remove thoses changes on tear down. Option "--xauth-add" will add an exception to your X access control list and also WILL NOT remove changes on quit.

Rewrite of "per-app-crypted-home.bash" in Python with additional features.

### Usage
```
Usage: 
  ./per-app-crypted-home.py [options] [-b<DIR>]... [--] <application> [<arguments>...]

Runs application within an encrypted sandboxed filesystem used as home shadowing users original home directory.

Options:
  -b DIRECTORY                    Bind mount given subdirectory of home into containers home
  -c, --container=FILE            File used as container for encrypted home [default: $HOME/.crypted-homes/$APPLICATION_ID]
  --cpu-quota=FLOAT               Quota for CPU time ( 0.5 = 50% of 1 core, 4 = 100% of 4 cores )
  -f, --fs-type=TYPE              Filesystem type inside container [default: ext4]
  -h, --help                      Display this help and exits
  -H, --hash=COMMAND              Hash executable used to build application identifier [default: sha256sum]
  -i, --id=APPLICATION_ID         Application identifier [default: $BASENAME-$PATHHASH]
  -k, --key-file=FILE             Use key from FILE instead of passphrase for dm-crypt
  -m, --mac-address=MAC           Spoof virtual ethernet MAC address
  --max-memory=SIZE               Set memory limit for container
  -n, --nat                       Setup NAT for internet access
  -q, --quiet                     Suppress extra output
  -r, --resize=SIZE               Resize an existing container
  -s, --size=SIZE                 Maximum size of container [default: 4G]
  --skip-dbus-launch              Skip DBUS launch inside container
  --skip-devices                  Skip restricting devices access inside container
  --skip-hide-run                 Skip mount new tmpfs to /run
  --skip-hide-tmp                 Skip mount new tmpfs to /tmp
  --skip-ipc                      Skip IPC virtualisation
  --skip-network                  Skip network virtualisation
  --skip-uts                      Skip UTS (hostname) virtualisation
  --skip-xdg-runtime-dir          Skip shadowing of XDG_RUNTIME_DIR
  -v, --verbose                   Verbose logging output 
  --version                       Shows version and exits
  -x, --xauth-add                 Add xauth cookie
  -t, --tcpdump                   Dump reduced version of network traffic with tcpdump
  --teardown-timeout=SECONDS      Timeout for closing the container in seconds [default: 10]
```

### Simple example
```sh
# start firefox without virtual network
./per-app-crypted-home.py --skip-network --skip-uts firefox
# start firefox with virtual network and NAT (see warning above usage section)
./per-app-crypted-home.py -xn firefox
```
### Advanced examples
```sh
# key file, pipe and exit code example
head -c32 /dev/random > ~/secret_key
echo "hello world"|./per-app-crypted-home.py --key-file ~/secret_key -- "$SHELL" -c "cat; exit 42"
# application arguments with quote example
./per-app-crypted-home.py --key-file ~/secret_key "$SHELL" -c "pwd; ls -la; mount |grep \"$HOME\"; echo \"sleeping 1m so you can try to find this mount in another shell. Hint: it won't be easy.\"; sleep 1m"
# resize shrink example
./per-app-crypted-home.py --resize 128M --key-file ~/secret_key -- "$SHELL" -c "df -h ."
# quiet resize expand example
./per-app-crypted-home.py --quiet --resize 512M --key-file ~/secret_key -- "$SHELL" -c "df -h ."
# capture ip activities (currently only TCP SYN/FIN, all udp and all icmp)
./per-app-crypted-home.py --xhost-add-localuser --nat --tcpdump --key-file ~/secret_key chromium
# bind mount $HOME/Downloads into private container
./per-app-crypted-home.py --key-file ~/secret_key -b Downloads "$SHELL" -c "ls -la Downloads"
# spoof network MAC address
./per-app-crypted-home.py --key-file ~/secret_key --mac-address c0:01:da:1a:d0:0d "$SHELL" -c "ip l |grep c0:01:da:1a:d0:0d"
# CPU quota options
./per-app-crypted-home.py --key-file ~/secret_key --cpu-quota 0.1 "$SHELL" -c 'for i in $( seq 1 $( grep "^processor" /proc/cpuinfo |wc -l ) ); do while true; do true; done & done; top'
# new tmpfs for /tmp, /run and /home
./per-app-crypted-home.py --key-file ~/secret_key "$SHELL" -c "ls -la /tmp /run /home"
```

