#!/usr/bin/env bash
# License: GPL
# Author: b2ag

# some stupid stuff
BASH="$( which bash )"
BASENAME="$( which basename )"
BLOCKDEV="$( which blockdev )"
CAT="$( which cat )"
CRYPTSETUP="$( which cryptsetup )"
CUT="$( which cut )"
CHOWN="$( which chown )"
DATE="$( which date )"
DU="$( which du )"
FILE="$( which file )"
FSCK="$( which fsck )"
GETOPT="$( which getopt )"
GREP="$( which grep )"
HEAD="$( which head )"
ID="$( which id )"
IP="$( which ip )"
IPTABLES="$( which iptables )"
IP6TABLES="$( which ip6tables )"
MKFS="$( which mkfs )"
MOUNT="$( which mount )"
NSENTER="$( which nsenter )"
REPLACE="$( which replace )"
RESIZE2FS="$( which resize2fs )"
RM="$( which rm )"
SED="$( which sed )"
SH="$( which sh )"
SLEEP="$( which sleep )"
STAT="$( which stat )"
SU="$( which su )"
SUDO="$( which sudo )"
TAIL="$( which tail )"
TCPDUMP="$( which tcpdump )"
TIMEOUT="$( which timeout )"
TRUNCATE="$( which truncate )"
UNSHARE="$( which unshare )"
XARGS="$( which xargs )"
XHOST="$( which xhost )"

# some interesting stuff
APPLICATION=
APPLICATION_ARGS=
HASHCMD="$( which sha256sum )"
HOMECONTAINER="\$HOME/crypted-home-for-\$APPLICATION_ID"
APPLICATION_ID="\$BASENAME-\$PATHHASH"
KEY_FILE=
DMCRYPTED_HOMECONTAINER=
CONTAINER_SIZE="1024M"
FS_TYPE="ext4"
TEAR_DOWN_TIMEOUT=10 # Seconds
QUIET=
LOG_PREFIX="[$0]"
UNSHARE_OPTIONS=( --kill-child --fork --pid --mount-proc --mount ) # --net --ipc
DO_NAT=
DO_RESIZE=
DO_XHOST_ADD_LOCALUSER=
SKIP_DBUS_LAUNCH=
SKIP_IPC=
SKIP_NETWORK=
SKIP_UTS=
SKIP_XDG_RUNTIME_DIR=
VETH_LUCKYNR=$(( ( RANDOM % 128 )  + 32 ))
VETH_HOST_IP4="192.168.$VETH_LUCKYNR.1"
VETH_VM_IP4="192.168.$VETH_LUCKYNR.2"
VETH_SUBNET4="24"
VETH_HOST_IP6="fd63:e832:5133:6194::1"
VETH_VM_IP6="fd63:e832:5133:6194::2"
VETH_VM_NET6="fd63:e832:5133:6194::/64"
VETH_SUBNET6="64"
TCPDUMP_LOGGING=

print_usage() {
  cat <<USAGE > /dev/stderr
Usage:
  $0 [options] [--] <application> [arguments]

Runs application within an encrypted sandboxed filesystem used as home shadowing users original home directory.

Options:
  -c, --container=FILE            File used as container for encrypted home ( default: "$HOMECONTAINER" )
  -f, --fs-type=TYPE              Filesystem type inside container ( default: $FS_TYPE )
  -H, --hash=COMMAND              Hash executable used to build application identifier ( default: $HASHCMD )
  -i, --id=APPLICATION_ID         Application identifier ( default: "$APPLICATION_ID" )
  -k, --key-file=FILE             Use key from FILE instead of passphrase for dm-crypt
  -n, --nat                       Setup NAT for internet access
  -r, --resize=SIZE               Resize an existing container
  -s, --size=SIZE                 Maximum size of container ( default: $CONTAINER_SIZE )
  --skip-dbus-launch              Skip DBUS launch inside container
  --skip-ipc                      Skip IPC virtualisation
  --skip-network                  Skip network virtualisation
  --skip-uts                      Skip UTS (hostname) virtualisation
  --skip-xdg-runtime-dir          Skip shadowing of XDG_RUNTIME_DIR
  -x, --xhost-add-localuser       Add current user via xhost to X access control list
  -t, --tcpdump                   Dump reduced version of network traffic with tcpdump
  --teardown-timeout=SECONDS      Timeout for closing the container ( default: $TEAR_DOWN_TIMEOUT seconds )
  -q, --quiet                     Suppress extra output
  -h, --help                      Display this help and exits

USAGE
}

# original toBytes by user1088084 - https://stackoverflow.com/a/24289918/6257086
toBytes() { local X="$( echo $1 | "$SED" 's/.*/\L\0/;s/t/Xg/g;s/g/Xm/g;s/m/Xk/g;s/k/X/g;s/b//g;s/X/ *1024/g' )" && echo "$X" | grep -qv "[^0-9\* ]" && echo $(("$X")); }

parse_options() {
  if (( $# == 0 )); then
    print_usage
    exit 1
  fi
  OPTS=$( POSIXLY_CORRECT=1 "$GETOPT" --options 'c:f:H:i:k:nr:s:tqxh' --longoptions 'container:,fs-type:,hash:,id:,key-file:,nat,resize:,size:,skip-ipc,skip-dbus-launch,skip-network,skip-uts,skip-xdg-runtime-dir,tcpdump,teardown-timeout:,quiet,xhost-add-localuser,help' --name "$0" -- "$@" )
  GETOPT_RETURN_CODE=$?
  if [ "$GETOPT_RETURN_CODE" != "0" ]; then
    print_usage
    exit 1
  fi
  eval set -- "$OPTS"
  while (( $# > 0 )); do
    case "$1" in
      -c|--container) shift; HOMECONTAINER="$1";;
      -f|--fs-type) shift; FS_TYPE="$1"; { which "$MKFS.$FS_TYPE" && which "$FSCK.$FS_TYPE"; } >/dev/null 2>&1 || die "Mkfs \"$MKFS.$FS_TYPE\" or fsck \"$FSCK.$FS_TYPE\" missing for filesystem type \"$1\"";;
      -H|--hash) shift; HASHCMD="$( which "$1" 2>/dev/null )" || die "Hash executable \"$1\" not found or not executable";;
      -i|--id) shift; APPLICATION_ID="$1";;
      -k|--key-file) shift; KEY_FILE="$1";;
      -n|--nat) DO_NAT=true;;
      -r|--resize) shift; [ "$( toBytes "$1")" -gt 0 ] 2>/dev/null && DO_RESIZE="$1" || die "Resize size \"$1\" seems to be invalid";;
      -s|--size) shift; [ "$( toBytes "$1")" -gt 0 ] 2>/dev/null && CONTAINER_SIZE="$1" || die "Container size \"$1\" seems to be invalid";;
      --skip-dbus-launch) SKIP_DBUS_LAUNCH=true;;
      --skip-ipc) SKIP_IPC=true;;
      --skip-network) SKIP_NETWORK=true;;
      --skip-uts) SKIP_UTS=true;;
      --skip-xdg-runtime-dir) SKIP_XDG_RUNTIME_DIR=true;;
      -t|--tcpdump) TCPDUMP_LOGGING=true;;
      --teardown-timeout) shift; [ "$1" -gt 0 ] 2>/dev/null && TEAR_DOWN_TIMEOUT="$1" || die "Timeout \"$1\" seems to be invalid";;
      -x|--xhost-add-localuser) DO_XHOST_ADD_LOCALUSER=true;;
      -q|--quiet) QUIET=true;;
      --) shift; APPLICATION="$( which "$1" 2>/dev/null )" || die "Application executable \"$1\" not found or not executable"; shift; APPLICATION_ARGS=( "$@" ); break;;
      -h|--help) print_usage; exit 0;;
      *) echo "$LOG_PREFIX Usage or getopt error" > /dev/stderr; print_usage; exit 1;;
    esac
    shift;
  done
  APPLICATION_ID="$( echo "$APPLICATION_ID" | "$REPLACE" "\$BASENAME" "$( "$BASENAME" "$APPLICATION" )" | "$REPLACE" "\$PATHHASH" "$( echo "$APPLICATION" | "$HASHCMD" |"$CUT" -f1 -d' ' )" )"
  HOMECONTAINER="$( echo "$HOMECONTAINER" | "$REPLACE" "\$APPLICATION_ID" "$APPLICATION_ID" | "$REPLACE" "\$HOME" "$HOME" )"
  DMCRYPTED_HOMECONTAINER="/dev/mapper/$APPLICATION_ID"
}

echo_if_not_quiet() { [ -z "$QUIET" ] && echo "$LOG_PREFIX $@" || true; }

print_info() {
  echo_if_not_quiet "Options:"
  echo_if_not_quiet " Application executable: $APPLICATION"
  echo_if_not_quiet " Application identifier: $APPLICATION_ID"
  echo_if_not_quiet " Application arguments: ${APPLICATION_ARGS[@]}"
  echo_if_not_quiet " Container filesystem: $FS_TYPE"
  echo_if_not_quiet " Container size: $CONTAINER_SIZE"
  echo_if_not_quiet " Container path: $HOMECONTAINER $( [ -e "$HOMECONTAINER" ] && echo "(exists)")"
  echo_if_not_quiet " Mapped dm-crypt path: $DMCRYPTED_HOMECONTAINER $( [ -e "$DMCRYPTED_HOMECONTAINER" ] && echo "(exists)")"
  [ -n "$KEY_FILE" ] && echo_if_not_quiet " Key file: $KEY_FILE"
}

escalate_priviledges() {
  if [ "$( "$ID" -u )" != "0" ]; then
    echo_if_not_quiet "Need to escalate priviledges"
    exec "$SUDO" -E "USER=$USER" "HOME=$HOME" "NEED_FORMAT=$NEED_FORMAT" "$0" "$@"
  fi
  echo "$LOG_PREFIX Something is wrong" > /dev/stderr
  exit 8
}

# die helper vars
CONTAINER_OPEN=
DIE_RECURSION_STOP=
die() {
  echo "$LOG_PREFIX $@" > /dev/stderr
  if [ "$NEED_FORMAT" = "true" ] && [ -e "$HOMECONTAINER" ] && ! "$FILE" "$HOMECONTAINER" | grep -q "LUKS encrypted file"; then
    echo "$LOG_PREFIX Removing unformated container at \"$HOMECONTAINER\"" > /dev/stderr
    "$RM" "$HOMECONTAINER"
  fi
  if [ "$CONTAINER_OPEN" = "true" ] && [ -z "$DIE_RECURSION_STOP" ]; then
    DIE_RECURSION_STOP=true
    tear_down
  fi
  exit 1
}

# define tear down operation
TEAR_DOWN_EXTRA_CMDS="true"
tear_down() {
  eval "$TEAR_DOWN_EXTRA_CMDS"
  TEAR_DOWN_TIMEOUT_DATE=$(( $("$DATE" +%s) + TEAR_DOWN_TIMEOUT ))
  echo_if_not_quiet "Closing container"
  while "$CRYPTSETUP" status "$APPLICATION_ID" > /dev/null 2>&1; do
    "$CRYPTSETUP" close "$APPLICATION_ID" && echo_if_not_quiet "Successfully close container" || echo_if_not_quiet "Couldn't close container. Retry"
    if [ "$( "$DATE" +%s )" -ge "$TEAR_DOWN_TIMEOUT_DATE" ]; then
      die "Timed out while trying to close container \"$APPLICATION_ID\"."$'\n'"To close it yourself run following command as root."$'\n'"\"$CRYPTSETUP\" close \"$APPLICATION_ID\""
      false
      return
    fi
    "$SLEEP" 2
  done
  true
}

create_empty_container() {
  if [ ! -e "$HOMECONTAINER" ]; then
    echo_if_not_quiet "Create container of size $CONTAINER_SIZE"
    "$TRUNCATE" --size "$CONTAINER_SIZE" "$HOMECONTAINER" || die "Couldn't create empty container at \"$HOMECONTAINER\" to size \"$CONTAINER_SIZE\""
    echo_if_not_quiet "Empty container is not yet LUKS formated. If sudo fails you need to remove \"$HOMECONTAINER\" and start over."
  fi
}

luks_format_container() {
  echo_if_not_quiet "LUKS format container"
  if "$FILE" "$HOMECONTAINER" | grep -q "LUKS encrypted file"; then
    die "Container already contains a LUKS header. Refuse to work"
  fi
  CMD=( "$CRYPTSETUP" luksFormat "$HOMECONTAINER" --type luks2 --batch-mode )
  [ -n "$LUKS_KEY_FILE_ARG" ] && CMD+=( "$LUKS_KEY_FILE_ARG" ) || CMD+=( "--verify-passphrase" );
  "${CMD[@]}" || die "Couldn't LUKS format container at \"$HOMECONTAINER\""
}

luks_open_container() {
  if [ ! -e "$HOMECONTAINER" ]; then
    die "Couldn't find container at \"$HOMECONTAINER\""
  else
    echo_if_not_quiet "LUKS open container"
    CMD=( "$CRYPTSETUP" open "$HOMECONTAINER" "$APPLICATION_ID" --type luks )
    [ -n "$LUKS_KEY_FILE_ARG" ] && CMD+=( "$LUKS_KEY_FILE_ARG" );
    "${CMD[@]}" || die "Couldn't open container \"$HOMECONTAINER\""
  fi
}

mkfs_open_container() {
  echo_if_not_quiet "Format uncrypted container"
  echo_if_not_quiet "Warning: Random data (cause fresh crypted device) seen as filesystem headers may irritate mkfs"
  [ -z "$QUIET" ] && MKFS_OUT=/dev/stdout || MKFS_OUT=/dev/null
  "$MKFS.$FS_TYPE" "$DMCRYPTED_HOMECONTAINER" > "$MKFS_OUT" 2>&1 || die "Couldn't create \"$FS_TYPE\" filesystem with \"$(basename "$MKFS.$FS_TYPE")\" for container \"$HOMECONTAINER\""
}
fsck_open_container() {
  echo_if_not_quiet "Filesystem check on open container"
  [ -z "$QUIET" ] && FSCK_OUT=/dev/stdout || FSCK_OUT=/dev/null
  if ! "$FSCK.$FS_TYPE" -y $1 "$DMCRYPTED_HOMECONTAINER" > "$FSCK_OUT" 2>&1; then
    echo "$LOG_PREFIX Warning: Filesystem check tool \"$FSCK.$FS_TYPE\" failed" > /dev/stderr
  fi
}

decide_about_resize() {
  RESIZE_MODE=
  if [ -n "$DO_RESIZE" ]; then
    [ -e "$HOMECONTAINER" ] || die "Can't resize no-existing container \"$HOMECONTAINER\""
    CONTAINER_SIZE="$( "$STAT" --printf="%s" "$HOMECONTAINER" )"
    NEW_SIZE="$( toBytes "$DO_RESIZE" )"
    [ "$( "$ID" -u )" = "0" ] || [ "$NEW_SIZE" -ne "$CONTAINER_SIZE" ] || echo "$LOG_PREFIX Warning: Option resize given, but container already has size \"$DO_RESIZE\""
    [ "$FS_TYPE" = "ext2" ] || [ "$FS_TYPE" = "ext3" ] || [ "$FS_TYPE" = "ext4" ] || die "Option resize only supports ext filesystem types"
    [ -x "$RESIZE2FS" ] || die "Resize tool \"$RESIZE2FS\" is not executable"
    if [ "$NEW_SIZE" -gt "$CONTAINER_SIZE" ]; then
      RESIZE_MODE="expand"
      echo_if_not_quiet "Inflate container file"
      "$TRUNCATE" --size "$DO_RESIZE" "$HOMECONTAINER" || die "Couldn't inflate container at \"$HOMECONTAINER\" to size \"$DO_RESIZE\""
    elif [ "$NEW_SIZE" -lt "$CONTAINER_SIZE" ]; then
      RESIZE_MODE="shrink"
    else
      # just run resize2fs
      RESIZE_MODE="auto"
    fi
    NEED_FORMAT=false
  fi
}

main() {

  parse_options "$@"
  [ "$( "$ID" -u )" != "0" ] && print_info

  # handle resize
  decide_about_resize

  # prepare (1/4) (create empty file if needed)
  [ -z "$NEED_FORMAT" ] && NEED_FORMAT=false
  if [ "$( "$ID" -u )" != "0" ] && [ ! -e "$HOMECONTAINER" ]; then
    NEED_FORMAT=true
    create_empty_container
  fi
  # become root now
  if [ "$( "$ID" -u )" != "0" ]; then
    escalate_priviledges "$@"
  fi
  # check if dm-crypt already opened our container
  if [ -e "$DMCRYPTED_HOMECONTAINER" ]; then
    echo "Container already open \"$DMCRYPTED_HOMECONTAINER\""
    read -p "Do you want to close it? [y/N] " yn
    case "$yn" in
      [Yy] ) tear_down ;;
      [Yy][Ee][Ss] ) tear_down ;;
      * ) exit 2;;
    esac
  fi
  # key file option
  if [ -n "$KEY_FILE" ]; then
    [ -r "$KEY_FILE" ] || die "Couldn't read key file \"$KEY_FILE\""
    LUKS_KEY_FILE_ARG="--key-file=$KEY_FILE"
  else
    LUKS_KEY_FILE_ARG=
  fi
  # prepare (2/4) (LUKS format if needed)
  if [ "$NEED_FORMAT" = "true" ]; then
    luks_format_container
  elif ! "$FILE" "$HOMECONTAINER" | grep -q "LUKS encrypted file"; then
    die "Container missing LUKS header at \"$HOMECONTAINER\""
  fi
  # prepare (3/4) (LUKS open)
  luks_open_container
  # check if dm-crypt worked
  if [ ! -e "$DMCRYPTED_HOMECONTAINER" ]; then
    die "Couldn't find open container at \"$DMCRYPTED_HOMECONTAINER\""
  else
    CONTAINER_OPEN=true
  fi
  # prepare (4/4) (filesystem)
  if [ "$NEED_FORMAT" = "true" ]; then
    mkfs_open_container
  else
    # resize fs
    if [ -n "$RESIZE_MODE" ]; then
      fsck_open_container "-f"
      DMCRYPT_OFFSET="$(( $CONTAINER_SIZE - "$( "$BLOCKDEV" --getsize64 "$DMCRYPTED_HOMECONTAINER" )"  ))"
      "$RESIZE2FS" "$DMCRYPTED_HOMECONTAINER" "$(( (( $( toBytes "$DO_RESIZE" ) - $DMCRYPT_OFFSET )) / 512 ))s" || die "Couldn't resize filesystem for device \"$DMCRYPTED_HOMECONTAINER\""
    fi
    # fsck
    fsck_open_container
    # truncate container if shrink is requested
    if [ "$RESIZE_MODE" = "shrink" ]; then
      echo_if_not_quiet "Shrinking container file"
      "$TRUNCATE" --size "$DO_RESIZE" "$HOMECONTAINER" || die "Couldn't shrink container at \"$HOMECONTAINER\" to size \"$DO_RESIZE\""
    fi
  fi

  # install trap handler
  trap tear_down SIGTERM SIGINT

  # change into new environment
  echo_if_not_quiet "Change into container"

  # shell argument escape fun
  APPLICATION_CMD=( "$APPLICATION" )
  APPLICATION_CMD+=( "${APPLICATION_ARGS[@]}" )
  APPLICATION_CMD_SERIALIZED_L1="$( typeset -p APPLICATION_CMD )"
  APPLICATION_CMD_SERIALIZED_L2="$( typeset -p APPLICATION_CMD_SERIALIZED_L1 )"
  APPLICATION_CMD_SERIALIZED_L3="$( echo "${APPLICATION_CMD_SERIALIZED_L2::-1}" |cut -d'"' -f2- ); exec \\\"\\\${APPLICATION_CMD[@]}\\\""

  # TODO overwrite by cmdline option
  NET_NAME="${APPLICATION_ID:0:8}${APPLICATION_ID:(-7)}"


  USER_EXTRA_CMDS=

  CHOWN_CMD=
  if [ "$NEED_FORMAT" = "true" ]; then
    CHOWN_CMD="'$CHOWN' '$USER:' '-R' '$HOME'"
  fi

  if [ "$SKIP_IPC" != "true" ]; then
    UNSHARE_OPTIONS+=("--ipc")
  fi

  if [ "$DO_XHOST_ADD_LOCALUSER" ]; then
    "$XHOST" si:localuser:$USER # not to forget to punch holes in our sandbox
  fi

  HIDE_XGD_RUNTIME_DIR_CMDS=
  if [ "$SKIP_XDG_RUNTIME_DIR" != "true" ] && [ -d "$XDG_RUNTIME_DIR" ]; then
    HIDE_XGD_RUNTIME_DIR_CMDS="mount -t tmpfs tmpfs '$XDG_RUNTIME_DIR' && \
                   chown '$USER:' '$XDG_RUNTIME_DIR' && \
                   chmod go-rwx '$XDG_RUNTIME_DIR'"
  fi

  DBUS_LAUNCH_CMDS=
  if [ "$SKIP_DBUS_LAUNCH" != "true" ]; then
    #DBUS_LAUNCH_CMDS="export \"DBUS_SESSION_BUS_ADDRESS=\$( su \"$USER\" -c \"dbus-daemon --session --fork --address=unix:path=$XDG_RUNTIME_DIR/bus --nosyslog --print-pid --print-address\" )\""
    DBUS_LAUNCH_CMDS="unset DBUS_SESSION_BUS_ADDRESS"
    USER_EXTRA_CMDS="export DBUS_SESSION_BUS_ADDRESS=\\\$( dbus-daemon --session --fork --address=unix:path=$XDG_RUNTIME_DIR/bus --nosyslog --print-address ); "
  fi

  UTS_CMDS=
  if [ "$SKIP_UTS" != "true" ]; then
    UTS_CMDS="hostname '$NET_NAME'"
    UNSHARE_OPTIONS+=("--uts")
  fi

  unshare_net_hook() { "$@"; }
  if [ "$SKIP_NETWORK" != "true" ]; then
    #echo "NET_NAME=$NET_NAME"
    NET_MOUNT_POINT="$XDG_RUNTIME_DIR/net-$NET_NAME"
    touch "$NET_MOUNT_POINT"
    "$UNSHARE" "--net=$NET_MOUNT_POINT" -pf --kill-child true
    "$IP" link add "$NET_NAME" type veth peer name "$NET_NAME" netns "$NET_MOUNT_POINT"
    "$IP" link set "$NET_NAME" up
    TEAR_DOWN_EXTRA_CMDS="$TEAR_DOWN_EXTRA_CMDS; umount '$NET_MOUNT_POINT'; rm '$NET_MOUNT_POINT'"
    NETWORK_SETUP_CMDS="'$IP' link set dev $NET_NAME up"
    NETWORK_SETUP_CMDS="$NETWORK_SETUP_CMDS && '$IP' link set dev lo up"
    unshare_net_hook() { nsenter "--net=$NET_MOUNT_POINT" "$@"; }
  fi

  exec 3< <( cat <<UNSHARE_COMMANDS ;
exec 3<&-
set -e
[ -z "$QUIET" ] && set -x
$HIDE_XGD_RUNTIME_DIR_CMDS
$DBUS_LAUNCH_CMDS
$NETWORK_SETUP_CMDS
$UTS_CMDS
"$MOUNT" "$DMCRYPTED_HOMECONTAINER" "$HOME"
$CHOWN_CMD
cd "$HOME"
exec su "$USER" --preserve-environment -s "$BASH" -c "$USER_EXTRA_CMDS$APPLICATION_CMD_SERIALIZED_L3"
UNSHARE_COMMANDS
)
  exec 6<&0
  exec < /dev/null
  { sleep infinity; } & MAIN_PROCESS_EXIT_HELPER_PID=$!

  {
    unshare_net_hook "$UNSHARE" "${UNSHARE_OPTIONS[@]}" "$BASH" "/proc/self/fd/3" < /proc/self/fd/6
    UNSHARE_EXIT=$?
    kill $MAIN_PROCESS_EXIT_HELPER_PID
    sleep 2
    tear_down
    echo_if_not_quiet "Everything went fine. Bye!"
    exit $UNSHARE_EXIT
  } & MAIN_PROCESS_PID=$!

  DAEMON_PIDS=

  if [ "$SKIP_NETWORK" != "true" ]; then
    timeout 10s "$BASH" -c "while ! '$IP' -6 addr show '$NET_NAME' |'$GREP' -q 'UP,LOWER_UP' 2>/dev/null; do sleep 1; done"
    #VETH_HOST_IP6="$( "$IP" -6 addr show "$NET_NAME" |"$GREP" -oE "inet6 [0-9a-f:]+"| "$CUT" -d' ' -f2- )"
    #echo "VETH_HOST_IP6=$VETH_HOST_IP6"
    UNSHARE_PID="$(pgrep -P "$MAIN_PROCESS_PID" )"
    "$IP" address add "$VETH_HOST_IP4/$VETH_SUBNET4" dev "$NET_NAME"
    "$NSENTER" -at $UNSHARE_PID -- "$IP" address add "$VETH_VM_IP4/$VETH_SUBNET4" dev "$NET_NAME"
    "$IP" -6 address add "$VETH_HOST_IP6/$VETH_SUBNET6" dev "$NET_NAME"
    "$NSENTER" -at $UNSHARE_PID -- "$IP" -6 address add "$VETH_VM_IP6/$VETH_SUBNET6" dev "$NET_NAME"
    if [ "$DO_NAT" = "true" ]; then
      # container ip masquerading
      echo 1 > "/proc/sys/net/ipv4/conf/$NET_NAME/forwarding"
      #echo 1 > "/proc/sys/net/ipv6/conf/$NET_NAME/forwarding"
      "$NSENTER" -at $UNSHARE_PID -- "$IP" route add default via "$VETH_HOST_IP4" dev "$NET_NAME"
      "$NSENTER" -at $UNSHARE_PID -- "$IP" route add default via "$VETH_HOST_IP6" dev "$NET_NAME"
      # host ip masquerading
      HOST_DEFAULT_ROUTE_INTERFACE="$( "$IP" route show default |"$GREP" -o " dev [^ ]*"|"$CUT" -d' ' -f3- )"
      for INTERFACE in $HOST_DEFAULT_ROUTE_INTERFACE; do
        echo 1 > "/proc/sys/net/ipv4/conf/$INTERFACE/forwarding"
        #echo 1 > "/proc/sys/net/ipv6/conf/$INTERFACE/forwarding"
        "$IPTABLES" -t nat -C POSTROUTING -o $INTERFACE -j MASQUERADE 2>/dev/null || \
        "$IPTABLES" -t nat -A POSTROUTING -o $INTERFACE -j MASQUERADE
        ## TODO FIXME tear down remove:
        #"$IP6TABLES" -t nat -C POSTROUTING -o $INTERFACE -s "$VETH_VM_NET6" -j MASQUERADE 2>/dev/null || \
        #"$IP6TABLES" -t nat -A POSTROUTING -o $INTERFACE -s "$VETH_VM_NET6" -j MASQUERADE
	# handle only first interface
	break
      done
    fi
    # capture tcp syn&fin, all udp and all icmp
    if [ "$TCPDUMP_LOGGING" = "true" ]; then
      "$TCPDUMP" -ni "$NET_NAME" -w "$NET_NAME.$(date +"%Y%m%d%H%M").pcap" "tcp[tcpflags] & (tcp-syn|tcp-fin) != 0 or udp or icmp" & DAEMON_PIDS="$DAEMON_PIDS $!"
    fi
  fi

  # wait for tear down
  wait $MAIN_PROCESS_EXIT_HELPER_PID
  [ -n "$DAEMON_PIDS" ] && kill $DAEMON_PIDS
  wait $MAIN_PROCESS_PID
}

main "$@"
