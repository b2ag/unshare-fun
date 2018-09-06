#!/usr/bin/env python
"""
Usage: 
  $0 [options] [-b<DIR>]... [--] <application> [<arguments>...]

Runs application within an encrypted sandboxed filesystem used as home shadowing users original home directory.

Options:
  -b DIRECTORY                    Bind mount given subdirectory of home into containers home
  -c, --container=FILE            File used as container for encrypted home [default: $HOME/.crypted-homes/$APPLICATION_ID]
  -f, --fs-type=TYPE              Filesystem type inside container [default: ext4]
  -h, --help                      Display this help and exits
  -H, --hash=COMMAND              Hash executable used to build application identifier [default: sha256sum]
  -i, --id=APPLICATION_ID         Application identifier [default: $BASENAME-$PATHHASH]
  -k, --key-file=FILE             Use key from FILE instead of passphrase for dm-crypt
  -m, --mac-address=MAC           Spoof virtual ethernet MAC address
  -n, --nat                       Setup NAT for internet access
  -q, --quiet                     Suppress extra output
  -r, --resize=SIZE               Resize an existing container
  -s, --size=SIZE                 Maximum size of container [default: 4G]
  --skip-dbus-launch              Skip DBUS launch inside container
  --skip-ipc                      Skip IPC virtualisation
  --skip-network                  Skip network virtualisation
  --skip-uts                      Skip UTS (hostname) virtualisation
  --skip-xdg-runtime-dir          Skip shadowing of XDG_RUNTIME_DIR
  -v, --verbose                   Verbose logging output 
  --version                       Shows version and exits
  -x, --xhost-add-localuser       Add current user via xhost to X access control list
  -t, --tcpdump                   Dump reduced version of network traffic with tcpdump
  --teardown-timeout=SECONDS      Timeout for closing the container in seconds [default: 10]
"""
import atexit
import ctypes
import ctypes.util
import datetime
import distutils.spawn
from docopt import docopt
import logging
import math
import os
import re
import subprocess
import signal
import sys
import time

libc = ctypes.CDLL( ctypes.util.find_library('c'), use_errno=True )
# int mount( source, target, filesystemtype, mountflags, data)
libc.mount.argtypes = [ ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_ulong, ctypes.c_char_p ]
# int setns(int fd, int nstype)
libc.setns.argtypes = [ ctypes.c_int, ctypes.c_int ]
# int unshare(int flags)
libc.unshare.argtypes = [ ctypes.c_int ]
# int prctl(int option, unsigned long arg2, unsigned long arg3, unsigned long arg4, unsigned long arg5)
libc.prctl.argtypes = [ ctypes.c_int, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong ]
class CLONE_FLAGS(object):
  flags = [
    (0x00020000, 'CLONE_NEWNS'),
    (0x04000000, 'CLONE_NEWUTS'),
    (0x08000000, 'CLONE_NEWIPC'),
    (0x10000000, 'CLONE_NEWUSER'),
    (0x20000000, 'CLONE_NEWPID'),
    (0x40000000, 'CLONE_NEWNET'),
    ]
  @classmethod
  def from_param(cls, data):
    return c_uint(encode_flags(self.flags, data))

def bytes2human( value, long_names=False ):
  mapping = {0:'B',10:'KiB',20:'MiB',30:'GiB',40:'TiB',50:'PiB',60:'EiB',70:'ZiB',80:'YiB'}
  if long_names:
    mapping = {0:'byte',10:'kibibyte',20:'mebibyte',30:'gibibyte',40:'tebibyte',50:'pebibyte',60:'exbibyte',70:'zebibyte',80:'yobibyte'}
  key=int(math.log2(value)/10)*10
  return '{} {}'.format(int(value/(2**key)),mapping[key])

def human2bytes( value ):
  mapping = {'b':1,'k':1024,'m':1024**2,'g':1024**3,'t':1024**4,'p':1024**5,'e':1024**6,'z':1024**7,'y':1024*8}
  match = re.search('^([0-9\.]+)\s?([bkmgtpezy])$',value.lower())
  if match:
    return round( float(match.group(1)) * mapping[match.group(2)] )

def die( msg ):
  logging.fatal(msg)
  sys.exit(1)

def parse_arguments():
  arguments = docopt( __doc__.replace('$0',sys.argv[0]), options_first=True, version='{} 0.1'.format(sys.argv[0]))
  config = {}
  config['quiet'] = False
  config['verbose'] = False
  if arguments['--verbose']:
    logging.getLogger().setLevel( logging.DEBUG )
    config['verbose'] = True
  elif arguments['--quiet']:
    logging.getLogger().setLevel( logging.ERROR )
    config['quiet'] = True
  # TODO remove me
  if os.getuid() is not 0:  logging.debug('Arguments:\n{}'.format(arguments))
  config['app_path'] = distutils.spawn.find_executable(arguments['<application>'])
  if not config['app_path']:
    die("Couldn't find application executable for \"{}\"".format(arguments['<application>']))
  config['app_arguments'] = arguments['<arguments>']
  config['app_basename'] = os.path.basename(arguments['<application>'])
  config['unshare_flags'] = [ 'CLONE_NEWNS', 'CLONE_NEWPID' ]
  config['hashtool'] = arguments['--hash']
  config['teardown_timeout'] = int(arguments['--teardown-timeout'])
  config['app_path_hash'] = subprocess.Popen([config['hashtool']],stdout=subprocess.PIPE,stdin=subprocess.PIPE,stderr=subprocess.DEVNULL).communicate(config['app_path'].encode()+b'\n')[0].decode().split(' ')[0] # extra newline for compability with bash script version
  config['app_id'] = arguments['--id'].replace('$BASENAME',config['app_basename']).replace('$PATHHASH',config['app_path_hash'])
  config['container'] = arguments['--container'].replace('$HOME',os.getenv("HOME")).replace('$APPLICATION_ID', config['app_id'])
  config['fs_type'] = arguments['--fs-type'].lower()
  config['fsck'] = distutils.spawn.find_executable('fsck.{}'.format(config['fs_type']))
  config['mkfs'] = distutils.spawn.find_executable('mkfs.{}'.format(config['fs_type']))
  config['key_file'] = arguments['--key-file']
  config['open_container'] = '/dev/mapper/{}'.format(config['app_id'])
  config['do_mkfs'] = os.getuid() is 0 and os.getenv('DO_MKFS') is '1'
  config['USER'] = os.getenv('USER')
  config['HOME'] = os.getenv('HOME')
  config['net_name'] = config['app_id'][:8] + config['app_id'][-7:]
  config['parent'] = True
  if arguments['--resize']:
    config['resize'] = arguments['--resize'].upper()
    if not human2bytes(config['resize']):
      die("Can't parse resize argument \"{}\"".format(config['resize']))
  else:
    config['resize'] = False
  config['size'] = arguments['--size'].upper()
  if not human2bytes(config['size']):
    die("Can't parse size argument \"{}\"".format(config['size']))
  return config

def escalate_priviledges( config ):
  if os.getuid() is not 0:
    logging.info('Need to escalate priviledges')
    os.execvp(
            'sudo',
            [
                'sudo',
                '-E',
                'USER={USER}'.format(**config),
                'HOME={HOME}'.format(**config),
                'DO_MKFS={do_mkfs:d}'.format(**config),
            ]+sys.argv)
  else:
    die('Should not get here')

def try_close_container( config ):
  # let the parent close the container
  if not config['parent']: return
  deadline = datetime.datetime.utcnow() + datetime.timedelta(seconds=config['teardown_timeout'])
  while subprocess.run(['cryptsetup','status',config['app_id']],stdout=subprocess.DEVNULL).returncode is 0:
    if subprocess.run(['cryptsetup','close',config['app_id']]).returncode is 0:
      logging.info("Successfully closed container")
    else:
      logging.warning("Couldn't close container. Retrying")
    if datetime.datetime.utcnow() >= deadline:
      return False
    time.sleep(2)
  return True

def create_empty_container( config ):
  logging.info('Create container of size {size}'.format(**config))
  os.makedirs( os.path.dirname(config['container']), exist_ok=True, mode=0o700 )
  with open( config['container'], 'ab' ) as f: f.truncate( human2bytes( config['size'] ) )
  logging.info('Empty container is not yet LUKS formated. If sudo fails you need to manually remove "{container}" and start over.'.format(**config))

def luks_format_container( config ):
  logging.info('LUKS formating container')
  file_output = subprocess.check_output(['file',config['container']])
  if file_output.find(b'LUKS encrypted file') != -1:
    die("Container already contains a LUKS header. Refusing to format it.")
  cmd = [ 'cryptsetup', 'luksFormat', config['container'], '--type', 'luks2', '--batch-mode' ]
  if config['key_file']: cmd+= [ '--key-file', config['key_file'] ]
  else: cmd+= [ '--verify-passphrase' ]
  returncode = subprocess.run(cmd).returncode
  if returncode is 0:
    logging.info('Successfully LUKS formated container')
  else:
    atexit.register(os.unlink,config['container'])
    die("LUKS format failed")

def luks_open_container( config ):
  logging.info('LUKS opening container')
  file_output = subprocess.check_output(['file',config['container']])
  if file_output.find(b'LUKS encrypted file') == -1:
    die("Container missing a LUKS header. Refusing to open it.")
  cmd = [ 'cryptsetup', 'open', config['container'], config['app_id'], '--type', 'luks2' ]
  if config['key_file']: cmd+= [ '--key-file', config['key_file'] ]
  returncode = subprocess.run(cmd).returncode
  if returncode is 0:
    logging.info('Successfully opened container')
    atexit.register( try_close_container, config )
  else:
    die("LUKS open failed")

def mkfs_open_container( config ):
  logging.info( "Creating filesystem on opened container" )
  logging.warning( "Warning: Random data caused by reading freshly created crypted container may irritate mkfs" )
  if config['quiet']: outfd=subprocess.DEVNULL
  else: outfd=sys.stdout
  returncode = subprocess.run([ config['mkfs'], config['open_container'] ], stdout=outfd, stderr=outfd).returncode
  if returncode is 0:
    logging.info('Successfully created filesystem')
  else:
    die("Mkfs failed")

def fsck_open_container( config, force=False ):
  logging.info( "Checking filesystem on opened container" )
  if config['verbose']: outfd=sys.stdout
  else: outfd=subprocess.DEVNULL
  cmd=[ config['fsck'], '-y' ]
  if force: cmd+=['-f']
  returncode = subprocess.run( cmd+[config['open_container']], stdout=outfd, stderr=outfd).returncode
  if returncode is 0:
    logging.info('Filesystem is clean')
  else:
    logging.warning('Filesystem check failed')

def decide_about_resize( config ):
  config['resize_mode'] = False
  if config['resize']:
    if not os.path.exists( config['container'] ):
      die("Can't resize no-existing container \"{}\"".format( config['container'] ))
    if not config['fsck']:
      die('Unable to resize \"{}\" filesystem without check tool'.format(config['fs_type']))
    current_size=os.stat(config['container']).st_size
    new_size=human2bytes(config['resize'])
    if current_size == new_size:
      logging.warning("Option resize given, but container already is {}".format(bytes2human(current_size,long_names=True)))
    if config['fs_type'] not in [ 'ext2', 'ext3', 'ext4' ]:
      die("Option resize only supports ext filesystems")
    if not distutils.spawn.find_executable('resize2fs'):
      die("Resize tool \"resize2fs\" not found")
    if new_size > current_size:
      logging.info("Inflating container file")
      config['resize_mode'] = 'expand'
      with open( config['container'], 'ab' ) as f: f.truncate( human2bytes( config['size'] ) )
    elif new_size < current_size:
      config['resize_mode'] = 'shrink'
    else:
      config['resize_mode'] = 'auto'

def main():
  logging.basicConfig(format='[{}|%(levelname)s] %(message)s'.format(sys.argv[0]),level=logging.INFO)
  config=parse_arguments()
  if os.getuid() is not 0:
    logging.debug('Configuration:\n{}'.format(config))
    if not config['mkfs']: logging.warning('Mkfs tool for "{}" not found. Not able to format new containers'.format(config['fs_type']))
    if not config['fsck']: logging.warning('Fsck tool for "{}" not found. Not able to check container filesystem'.format(config['fs_type']))
    if not os.path.exists( config['container'] ):
      config['do_mkfs'] = True
      create_empty_container( config )
      luks_format_container( config )
    escalate_priviledges( config )
  decide_about_resize( config )
  if not os.path.exists( config['container'] ):
    die("Container \"{container}\" does not exist".format(**config))
  if os.path.exists( config['open_container'] ):
    logging.warning('Container already open at "{open_container}"'.format(**config))
    answer = input('Do you want to close it? [y/N] ')
    if answer.lower() not in [ 'y', 'yes' ]:
      sys.exit(2)
    try_close_container(config)
  luks_open_container( config )
  if config['do_mkfs']:
    if not config['mkfs']:
      die("Can't proceed without mkfs tool")
    mkfs_open_container( config )
  if config['fsck']:
    if config['resize']:
      fsck_open_container( config, force=True )
      current_size=os.stat(config['container']).st_size
      header_offset=current_size - int(subprocess.check_output(['blockdev','--getsize64',config['open_container']]))
      new_size='{}s'.format(int((human2bytes(config['resize'])-header_offset)/512))
      logging.info("Resizing filesystem on opened container")
      resize2fs = subprocess.run(['resize2fs',config['open_container'],new_size])
      if resize2fs.returncode is not 0:
        die("Resizing filesystem failed")
    fsck_open_container( config )
    if config['resize'] and config['resize_mode'] is 'shrink':
      logging.info("Shrinking container file")

  config['realsize']=bytes2human( os.stat(config['container']).st_blocks*512, long_names=True )
  logging.info("Container currently uses {realsize}".format(**config))
  logging.info("Setting up virtual environment for opened container")
  r,w=os.pipe()
  r,w=os.fdopen(r,'r'), os.fdopen(w,'w')
  child_pid = os.fork()
  if child_pid:
    w.close()
    def parent_sigterm_handler( signr, stack ):
      logging.info("Forwarding SIGTERM to child and waiting for it to finish")
      os.kill( child_pid, signal.SIGTERM )
      deadline = datetime.datetime.utcnow() + datetime.timedelta(seconds=config['teardown_timeout'])
      while True:
        pid, returncode = os.waitpid( child_pid, os.WNOHANG )
        if ( pid, returncode ) != ( 0, 0 ):
          sys.exit(returncode)
        if datetime.datetime.utcnow() > deadline:
          logging.info("Timed out")
          sys.exit(1)
          break
        time.sleep(2)
    signal.signal( signal.SIGTERM, parent_sigterm_handler )
    while True:
      try:
        pid, returncode = os.waitpid( child_pid, 0 )
        sys.exit( returncode )
      except KeyboardInterrupt:
        # forward CTRL+C and continue waiting
        os.kill( child_pid, signal.SIGINT )
  else:
    config['parent'] = False
    PR_SET_PDEATHSIG=1
    libc.prctl( PR_SET_PDEATHSIG, signal.SIGTERM, 0, 0, 0 )
    r.close()
    def application_exit_helper( application, config ):
      deadline = datetime.datetime.utcnow() + datetime.timedelta(seconds=config['teardown_timeout']-2)
      while not application.returncode:
        logging.info("Subprocess still alive. Sending SIGTERM")
        os.kill( application.pid, signal.SIGTERM )
        if datetime.datetime.utcnow() > deadline:
          logging.info("Timed out. Sending SIGKILL")
          os.kill( application.pid, signal.SIGKILL )
          break
        time.sleep(2)
        if not application.returncode:
          logging.info("Retrying")
    application = subprocess.Popen([config['app_path']]+config['app_arguments'])
    def child_sigterm_handler( signr, stack ):
      application_exit_helper( application, config )
    signal.signal( signal.SIGTERM, child_sigterm_handler )
    #atexit.register( application_exit_helper, application, config )
    try:
      sys.stdout, sys.stderr = application.communicate( sys.stdin )
    except KeyboardInterrupt:
      application.send_signal( signal.SIGINT )

    # see
    # https://github.com/karelzak/util-linux/blob/master/sys-utils/unshare.c
    # https://github.com/karelzak/util-linux/blob/master/sys-utils/mount.c



if __name__ == "__main__":
  main()
