# unshare-fun
Experiments with unshare
(currently only one)

## per-app-crypted-home.bash
This script creates an encrypted container used as home directory for the application given as argument. It unshares mountpoint, network, IPC and UTS namespaces. The script is designed as proof of concept application sandboxing wrapper. Shadowing of original home directory is intentional. To use dm-crypt and configure NAT the script needs sudo to get root access. To use X it preserves environment variables while switching between your user and root. To run X applications you need to pass "--skip-network" and "--skip-uts" or "--xhost-add-localuser" and "--nat". If you pass "--skip-network" than "--tcpdump" and "--nat" won't work.

Warning: Option "--nat" will enable IP forwarding on your default network interface and WILL NOT remove thoses changes on tear down. Option "--xhost-add-localuser" will add an exception to your X access control list and also WILL NOT remove changes on quit.


### Usage
```
Usage:
  ./per-app-crypted-home.bash [options] [--] <application> [arguments]

Runs application within an encrypted sandboxed filesystem used as home shadowing users original home directory.

Options:
  -c, --container=FILE            File used as container for encrypted home ( default: "$HOME/crypted-home-for-$APPLICATION_ID" )
  -f, --fs-type=TYPE              Filesystem type inside container ( default: ext4 )
  -H, --hash=COMMAND              Hash executable used to build application identifier ( default: /usr/bin/sha256sum )
  -i, --id=APPLICATION_ID         Application identifier ( default: "$BASENAME-$PATHHASH" )
  -k, --key-file=FILE             Use key from FILE instead of passphrase for dm-crypt
  -n, --nat                       Setup NAT for internet access
  -r, --resize=SIZE               Resize an existing container
  -s, --size=SIZE                 Maximum size of container ( default: 1024M )
  --skip-ipc                      Skip IPC virtualisation
  --skip-network                  Skip network virtualisation
  --skip-uts                      Skip UTS (hostname) virtualisation
  -x, --xhost-add-localuser       Add current user via xhost to X access control list
  -t, --tcpdump                   Dump reduced version of network traffic with tcpdump
  --teardown-timeout=SECONDS      Timeout for closing the container ( default: 10 seconds )
  -q, --quiet                     Suppress extra output
  -h, --help                      Display this help and exits

```
### Simple example
```sh
# start firefox without virtual network
./per-app-crypted-home.bash --skip-network --skip-uts firefox
# start firefox with virtual network and NAT (see warning above usage section)
./per-app-crypted-home.bash -xn firefox
```
### Advanced examples
```sh
# application arguments with quote example
./per-app-crypted-home.bash "$SHELL" -c "pwd; ls -la; mount |grep \"$HOME\"; echo \"sleeping 1m so you can try to find this mount in another shell. Hint: it won't be easy.\"; sleep 1m"
# key file, pipe and exit code example
head -c32 /dev/random > ~/secret_key
echo "hello world"|./per-app-crypted-home.bash --key-file ~/secret_key -- "$SHELL" -c "cat; exit 42"
# resize shrink example
./per-app-crypted-home.bash --resize 128M --key-file ~/secret_key -- "$SHELL" -c "df -h ."
# quiet resize expand example
./per-app-crypted-home.bash --quiet --resize 512M --key-file ~/secret_key -- "$SHELL" -c "df -h ."
# capture ip activities (currently only TCP SYN/FIN, all udp and all icmp)
./per-app-crypted-home.bash --xhost-add-localuser --nat --tcpdump --key-file ~/secret_key chromium
```
