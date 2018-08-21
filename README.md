# unshare-fun
Experiments with unshare
(currently only one)

## per-app-crypted-home.bash
This script creates a crypted 1 GiB container used as home to run the application given as argument. It unshares only mountpoints and full attention is on $HOME. It is designed as a proof of concept of application sandboxing. The script also preserves environment variables and needs to switch to root. Shadowing of original home directory is intentional.

### Usage
```sh
Usage: ./per-app-crypted-home.bash executable [arguments...]
```
### Simple example
```sh
./per-app-crypted-home.bash firefox
```
### Advanced example
```sh
./per-app-crypted-home.bash "$SHELL" -c "pwd; ls -la; mount |grep \"$HOME\"; echo \"sleeping 1m so you can try to find this mount in another shell. Hint: it won't be easy.\"; sleep 1m"
```
