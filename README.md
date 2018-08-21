# unshare-fun
Experiments with unshare
(currently only one)

## per-app-crypted-home.bash
This script creates a crypted 1 GiB container used as home to run the application given as argument. It unshares only mountpoints and full attention is on $HOME. It is designed as a proof of concept of application sandboxing. The script also preserves environment variables and needs to switch to root. Shadowing of original home directory is intentional.

### Usage
```
Usage:
  ./per-app-crypted-home.bash [options] [--] <application> [arguments]

Runs application within an encrypted sandboxed filesystem used as home shadowing users original home directory.

Options:
  -c, --container=FILE            File used as container for encrypted home ( default: "~/crypted-home-for-IDENTIFIER" )
  -f, --fs-type=TYPE              Filesystem type inside container ( default: ext4 )
  -H, --hash=COMMAND              Hash executable used to build application identifier ( default: /usr/bin/sha256sum )
  -i, --id=IDENTIFIER             Used to seperate containers for different applications with same basename ( default: "APP:BASENAME_APP:PATH:HASH" )
  -r, --resize=SIZE               Resize an existing container
  -s, --size=SIZE                 Maximum size of container ( default: 1024M )
  -t, --teardown-timeout=SECONDS  Timeout for closing the container ( default: 10 seconds )
  -q, --quiet                     Suppress extra output
  -h, --help                      Display this help and exits
```
### Simple example
```sh
./per-app-crypted-home.bash firefox
```
### Advanced examples
```sh
# application arguments with quote example
./per-app-crypted-home.bash "$SHELL" -c "pwd; ls -la; mount |grep \"$HOME\"; echo \"sleeping 1m so you can try to find this mount in another shell. Hint: it won't be easy.\"; sleep 1m"
# key file, pipe and return value example
head -c32 /dev/random > ~/secret_key
echo "hello world"|./per-app-crypted-home.bash --key-file ~/secret_key -- "$SHELL" -c cat
# resize shrink example
./per-app-crypted-home.bash --resize 128M --key-file ~/secret_key -- "$SHELL" -c "df -h ."
# quiet resize expand example
./per-app-crypted-home.bash --quiet --resize 512M --key-file ~/secret_key -- "$SHELL" -c "df -h ."
```
