#!/usr/bin/bash
# Author: b2ag
# License: GPL

# some stupid stuff
CAT="$( which cat )"
CRYPTSETUP="$( which cryptsetup )"
CUT="$( which cut )"
DATE="$( which date )"
DD="$( which dd )"
FILE="$( which file )"
FSCK="$( which fsck )"
ID="$( which id )"
MKFS="$( which mkfs )"
MOUNT="$( which mount )"
RM="$( which rm )"
SH="$( which sh )"
SUDO="$( which sudo )"
SU="$( which su )"
SLEEP="$( which sleep )"
TAIL="$( which tail )"
UNSHARE="$( which unshare )"
XARGS="$( which xargs )"

# some interesting stuff
APPLICATION="$( which "$1" 2>/dev/null )"
HASHCMD="$( which sha256sum )"
APPLICATION_ID="$( basename "$APPLICATION" )-$( echo "$APPLICATION" | "$HASHCMD" |"$CUT" -f1 -d' ' )"
DMCRYPTED_HOMECONTAINER="/dev/mapper/$APPLICATION_ID"
HOMECONTAINER="$HOME/crypted-home-for-$APPLICATION_ID"
SIZE_IN_MiB=1024 # MiB
FS_TYPE=ext4
TEAR_DOWN_TIMEOUT=10 # Seconds
QUIET="$QUIET"

print_usage() {
  echo "Usage: $0 executable [arguments...]" > /dev/stderr
}

# check required script parameters
if [ ! -x "$APPLICATION" ]; then
  print_usage
  exit 1
fi

echo_if_not_quiet() { [ -z "$QUIET" ] && echo "$@" || true; }

escalate_priviledges() {
  if [ "$( "$ID" -u )" != "0" ]; then
    echo_if_not_quiet "Need to escalate priviledges..."
    exec "$SUDO" -E "USER=$USER" "HOME=$HOME" "NEED_FORMAT=$NEED_FORMAT" "QUIET=$QUIET" "$0" "$@"
  fi
  echo "Something is wrong" > /dev/stderr
  exit 8
}

die() {
  echo "$@" > /dev/stderr
  if $NEED_FORMAT && [ -e "$HOMECONTAINER" ] && ! "$FILE" "$HOMECONTAINER" | grep -q "LUKS encrypted file"; then
    echo "Removing unformated container at \"$HOMECONTAINER\"" > /dev/stderr
    "$RM" "$HOMECONTAINER"
  fi
  exit 1
}

# define tear down operation
tear_down() {
  TEAR_DOWN_TIMEOUT_DATE=$(( $("$DATE" +%s) + TEAR_DOWN_TIMEOUT ))
  echo_if_not_quiet "Closing container..."
  while "$CRYPTSETUP" status "$APPLICATION_ID" > /dev/null 2>&1; do
    "$CRYPTSETUP" close "$APPLICATION_ID" && echo_if_not_quiet "Successfully close container" || echo_if_not_quiet "Couldn't close container. Retry..."
    if [ "$( "$DATE" +%s )" -ge "$TEAR_DOWN_TIMEOUT_DATE" ]; then
      die "Timed out while trying to close container \"$APPLICATION_ID\"."$'\n'"To close it yourself run following command as root."$'\n'"\"$CRYPTSETUP\" close \"$APPLICATION_ID\""
      false
      return
    fi
    "$SLEEP" 2
  done
  true
}

# prepare (1/4) (create empty file if needed)
if [ "$( "$ID" -u )" != "0" ] && [ ! -e "$HOMECONTAINER" ]; then
  echo_if_not_quiet "Create container of size $SIZE_IN_MiB mebibyte..."
  NEED_FORMAT=true
  "$DD" bs=$((1024*1024)) count=$SIZE_IN_MiB if=/dev/zero "of=$HOMECONTAINER" || die "Couldn't prepare empty container at \"$HOMECONTAINER\""
  escalate_priviledges "$@"
fi

# become root now
if [ "$( "$ID" -u )" != "0" ]; then
  NEED_FORMAT=false
  escalate_priviledges "$@"
fi

# check if dm-crypt already has our container open
if [ -e "$DMCRYPTED_HOMECONTAINER" ]; then
  echo "Container already open \"$DMCRYPTED_HOMECONTAINER\""
  read -p "Do you want to close it? [y/N] " yn
  case "$yn" in
    [Yy] ) tear_down ;;
    [Yy][Ee][Ss] ) tear_down ;;
    * ) exit 2;;
  esac
fi

# prepare (2/4) (LUKS format)
if [ "$NEED_FORMAT" = "true" ]; then
  echo_if_not_quiet "LUKS format container..."
  "$CRYPTSETUP" -q luksFormat --type luks2 "$HOMECONTAINER" || die "Couldn't LUKS format container at \"$HOMECONTAINER\""
elif ! "$FILE" "$HOMECONTAINER" | grep -q "LUKS encrypted file"; then
  die "Container missing LUKS header at \"$HOMECONTAINER\""
fi

# prepare (3/4) (LUKS open)
if [ ! -e "$HOMECONTAINER" ]; then
  die "Couldn't find container at \"$HOMECONTAINER\""
else
  echo_if_not_quiet "LUKS open container..."
  "$CRYPTSETUP" open --type luks "$HOMECONTAINER" "$APPLICATION_ID" || die "Couldn't open container \"$HOMECONTAINER\""
fi

# check if dm-crypt worked
if [ ! -e "$DMCRYPTED_HOMECONTAINER" ]; then
  die "Couldn't find open container at \"$DMCRYPTED_HOMECONTAINER\""
fi

# prepare (4/4) (mkfs if needed)
if [ "$NEED_FORMAT" = "true" ]; then
  echo_if_not_quiet "Format uncrypted container..."
  echo_if_not_quiet "Warning: Random data (cause fresh crypted device) seen has filesystem headers may irritate mkfs"
  "$MKFS.$FS_TYPE" "$DMCRYPTED_HOMECONTAINER" || die "Couldn't format filesystem \"$FS_TYPE\" with \"$(basename "$MKFS.$FS_TYPE")\" for container \"$HOMECONTAINER\""
elif ! "$FSCK.$FS_TYPE" "$DMCRYPTED_HOMECONTAINER"; then
  die "Container filesystem or fsck tool \"$FSCK.$FS_TYPE\" corrupt"
fi

# install trap handler
trap tear_down SIGTERM SIGINT

# change into new environment
echo_if_not_quiet "Change into container..."
MOUNT_CMD="\"$MOUNT\" \"$DMCRYPTED_HOMECONTAINER\" \"$HOME\""
if [ "$NEED_FORMAT" = "true" ]; then
  MOUNT_CMD="$MOUNT_CMD && chown \"$USER:\" -R \"$HOME\""
fi
MOUNT_CMD="$MOUNT_CMD && cd \"$HOME\""
if (( $# >= 2 )); then
  # first part of this line ensures arguments are handed over properly
  "$CAT" /proc/$$/cmdline | "$TAIL" -z -n+4 | "$UNSHARE" -m "$SH" -c "$MOUNT_CMD && \"$SU\" -c \"\\\"$XARGS\\\" -0 \\\"$APPLICATION\\\"\" --preserve-environment \"$USER\""
else
  # no extra arguments, pass stdin
  "$UNSHARE" -m "$SH" -c "$MOUNT_CMD && \"$SU\" -c \"$APPLICATION\" --preserve-environment \"$USER\""
fi

tear_down
echo_if_not_quiet "Everything went fine. Bye!"
