#!/usr/bin/env python
"""
Usage: 
  $0 [options] [-b<DIR>]... [--] <application> [<arguments>...]

Runs application within an encrypted sandboxed filesystem used as home shadowing users original home directory.

Options:
  -b DIRECTORY                    Bind mount given subdirectory of home into containers home
  --container=FILE                File used as container for encrypted home (default: $HOME/.crypted-homes/$APPLICATION_ID)
  -c, --config=NAME               Use a config file
  --cpu-quota=FLOAT               Quota for CPU time ( 0.5 = 50% of 1 core, 4 = 100% of 4 cores )
  -d, --display=DISPLAY           Display to use
  -f, --fs-type=TYPE              Filesystem type inside container (default: ext4)
  -h, --help                      Display this help and exits
  -H, --hash=COMMAND              Hash executable used to build application identifier (default: sha256sum)
  -i, --id=APPLICATION_ID         Application identifier (default: $BASENAME-$PATHHASH)
  --int-do-mkfs=<0|1>             Used internally when becoming root after creating a new container
  -k, --key-file=FILE             Use key from FILE instead of passphrase for dm-crypt
  -m, --mac-address=MAC           Spoof virtual ethernet MAC address
  --max-memory=SIZE               Set memory limit for container
  -n, --nat                       Setup NAT for internet access
  -q, --quiet                     Suppress extra output
  -r, --resize=SIZE               Resize an existing container
  -s, --size=SIZE                 Maximum size of container (default: 4G)
  --seccomp                       Sandbox syscalls with seccomp
  --skip-dbus-launch              Skip DBUS launch inside container
  --skip-devices                  Skip restricting devices access inside container
  --skip-hide-run                 Skip mount new tmpfs to /run
  --skip-hide-tmp                 Skip mount new tmpfs to /tmp
  --skip-ipc                      Skip IPC virtualisation
  --skip-network                  Skip network virtualisation
  --skip-uts                      Skip UTS (hostname) virtualisation
  --skip-bind-x11-unix            Skip bind mount of /tmp/.X11-unix
  --skip-xdg-runtime-dir          Skip providing XDG_RUNTIME_DIR
  -u, --user=USER                 User to run as
  -v, --verbose                   Verbose logging output 
  --version                       Shows version and exits
  -w, --write-config              Write current settings to config
  -x, --xauth                     Xauth cookie handling
  -t, --tcpdump                   Dump reduced version of network traffic with tcpdump
  --teardown-timeout=SECONDS      Timeout for closing the container in seconds (default: 10)
"""
import atexit
import binascii
import configparser
import ctypes
import ctypes.util
import datetime
import distutils.spawn
import docopt
import hashlib
import json
import logging
import math
import os
import pathlib
import pwd
import random
import re
import subprocess
import signal
import sys
import time

class FLAGS(object):
  flags = {}
  @classmethod
  def from_param( self, data ):
    return self.ctype(sum([ self.flags[x] for x in set(data) ]))
class UNSHARE_FLAGS(FLAGS):
  ctype = ctypes.c_int
  flags = { 'CLONE_NEWNS':0x00020000, 'CLONE_NEWCGROUP':0x02000000, 'CLONE_NEWUTS':0x04000000, 'CLONE_NEWIPC':0x08000000, 'CLONE_NEWUSER':0x10000000, 'CLONE_NEWPID':0x20000000, 'CLONE_NEWNET':0x40000000 }
class MOUNT_FLAGS(FLAGS):
  ctype = ctypes.c_ulong
  flags = { 'MS_RDONLY':1, 'MS_NOSUID':2, 'MS_NODEV':4, 'MS_NOEXEC':8, 'MS_SYNCHRONOUS':16, 'MS_REMOUNT':32, 'MS_MANDLOCK':64, 'MS_DIRSYNC':128, 'MS_NOATIME':1024, 'MS_NODIRATIME':2048, 'MS_BIND':4096, 'MS_MOVE':8192, 'MS_REC':16384, 'MS_SILENT':32768, 'MS_POSIXACL':(1<<16), 'MS_UNBINDABLE':(1<<17), 'MS_PRIVATE':(1<<18), 'MS_SLAVE':(1<<19), 'MS_SHARED':(1<<20), 'MS_RELATIME':(1<<21), 'MS_KERNMOUNT':(1<<22), 'MS_I_VERSION':(1<<23), 'MS_STRICTATIME':(1<<24), 'MS_NOSEC':(1<<28), 'MS_BORN':(1<<29), 'MS_ACTIVE':(1<<30), 'MS_NOUSER':(1<<31) }
PR_SET_PDEATHSIG=1
PR_SET_SECCOMP=22
SECCOMP_MODE_DISABLED=0
SECCOMP_MODE_STRICT=1
SECCOMP_MODE_FILTER=2
libc = ctypes.CDLL( ctypes.util.find_library('c'), use_errno=True )
# int mount( source, target, filesystemtype, mountflags, data)
libc.mount.argtypes = [ ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p, MOUNT_FLAGS, ctypes.c_char_p ]
# int prctl(int option, unsigned long arg2, unsigned long arg3, unsigned long arg4, unsigned long arg5)
libc.prctl.argtypes = [ ctypes.c_int, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong ]
# int setns(int fd, int nstype)
libc.setns.argtypes = [ ctypes.c_int, ctypes.c_int ]
# int umount(const char *target)
libc.umount.argtypes = [ ctypes.c_char_p ]
# int unshare(int flags)
libc.unshare.argtypes = [ UNSHARE_FLAGS ]

def bytes2human( value, long_names=False ):
  mapping = {0:'B',10:'KiB',20:'MiB',30:'GiB',40:'TiB',50:'PiB',60:'EiB',70:'ZiB',80:'YiB'}
  if long_names:
    mapping = {0:'byte',10:'kibibyte',20:'mebibyte',30:'gibibyte',40:'tebibyte',50:'pebibyte',60:'exbibyte',70:'zebibyte',80:'yobibyte'}
  key=int(math.log2(value)/10)*10
  return '{} {}'.format(int(value/(2**key)),mapping[key])

def human2bytes( value ):
  mapping = {'':1,'b':1,'k':1024,'m':1024**2,'g':1024**3,'t':1024**4,'p':1024**5,'e':1024**6,'z':1024**7,'y':1024*8}
  match = re.search('^([0-9\.]+)\s?([bkmgtpezy]?)$',value.lower())
  if match:
    return round( float(match.group(1)) * mapping[match.group(2)] )

def die( msg ):
  logging.fatal(msg)
  sys.exit(1)

def parse_arguments():
  arguments = docopt.docopt( __doc__.replace('$0',os.path.basename(sys.argv[0])), options_first=True, version='{} 0.2'.format(os.path.basename(sys.argv[0])))
  config = {}
  config['quiet'] = False
  if arguments['--quiet']:
    logging.getLogger().setLevel( logging.ERROR )
    config['quiet'] = True
  # defaults
  config['unshare_flags'] = [ 'CLONE_NEWNS', 'CLONE_NEWPID', 'CLONE_NEWUTS', 'CLONE_NEWIPC', 'CLONE_NEWNET', 'CLONE_NEWCGROUP' ]
  config['container'] = '$HOME/.crypted-homes/$APPLICATION_ID'
  config['fs_type'] = 'ext4'
  config['hashtool'] = 'sha256sum'
  config['app_id'] = '$BASENAME-$PATHHASH'
  config['size'] = '4G'
  config['teardown_timeout'] = 10
  config['seccomp_syscalls'] = syscalls
  # read config
  if arguments['--config']:
    config_parser = configparser.ConfigParser()
    config_file_name = '{}.cfg'.format(arguments['--config'])
    if os.path.exists(config_file_name):
      config_parser.read_file(open(config_file_name))
      config_file_contents = config_parser.items(configparser.DEFAULTSECT)
      for key, value in config_file_contents:
        if value: config[key] = json.loads(value)
  # arguments override
  if arguments['--fs-type']: config['fs_type'] = arguments['--fs-type'].lower()
  if arguments['--hash']: config['hashtool'] = arguments['--hash']
  if arguments['--id']: config['app_id'] = arguments['--id']
  if arguments['--teardown-timeout']: config['teardown_timeout'] = int(arguments['--teardown-timeout'])
  if arguments['--key-file' or 'key_file' not in config]: config['key_file'] = arguments['--key-file']
  if arguments['--nat' or 'do_nat' not in config]: config['do_nat'] = arguments['--nat']
  if arguments['--xauth' or 'configure_xauth' not in config]: config['configure_xauth'] = arguments['--xauth']
  if arguments['--skip-xdg-runtime-dir'] or 'xdg_runtime_dir' not in config: config['xdg_runtime_dir'] = '/run/user/$UID' if not arguments['--skip-xdg-runtime-dir'] else False
  if arguments['--mac-address'] or 'mac_address' not in config: config['mac_address'] = arguments['--mac-address']
  if arguments['-b'] or 'bind_dirs' not in config: config['bind_dirs'] = arguments['-b']
  if arguments['--tcpdump'] or 'do_tcpdump' not in config: config['do_tcpdump'] = arguments['--tcpdump']
  if arguments['--seccomp'] or 'use_seccomp' not in config: config['use_seccomp'] = arguments['--seccomp']
  if arguments['--skip-dbus-launch'] or 'do_launch_dbus' not in config: config['do_launch_dbus'] = not arguments['--skip-dbus-launch']
  if arguments['--cpu-quota'] or 'cpu_quota' not in config: config['cpu_quota'] = arguments['--cpu-quota']
  if config['cpu_quota']:
    config['cpu_quota'] = float(config['cpu_quota'])
  if arguments['--skip-devices'] or 'restrict_devices' not in config: config['restrict_devices'] = not arguments['--skip-devices']
  if arguments['--max-memory'] or 'max_memory' not in config: config['max_memory'] = arguments['--max-memory']
  if config['max_memory']:
    config['max_memory'] = config['max_memory'].upper()
    if not human2bytes(config['max_memory']):
      die("Can't parse memory limit option \"{}\"".format(config['max_memory']))
  if arguments['--skip-ipc']:
    config['unshare_flags'].remove('CLONE_NEWIPC')
  if arguments['--skip-network']:
    config['unshare_flags'].remove('CLONE_NEWNET')
  if arguments['--skip-uts']:
    config['unshare_flags'].remove('CLONE_NEWUTS')
  if arguments['--size']: config['size'] = arguments['--size'].upper()
  if not human2bytes(config['size']):
    die("Can't parse size argument \"{}\"".format(config['size']))
  if 'xauth_key' not in config: config['xauth_key'] = binascii.hexlify(os.urandom(16)).decode()
  if arguments['--skip-hide-tmp'] or 'hide_tmp' not in config: config['hide_tmp'] = not arguments['--skip-hide-tmp']
  if arguments['--skip-hide-run'] or 'hide_run' not in config: config['hide_run'] = not arguments['--skip-hide-run']
  if arguments['--skip-bind-x11-unix'] or 'do_bind_.X11-unix' not in config: config['do_bind_.X11-unix'] = not arguments['--skip-bind-x11-unix']
  if arguments['--display'] or 'display' not in config: config['display'] = arguments['--display'] if arguments['--display'] else os.getenv('DISPLAY')
  if arguments['--container'] or 'container' not in config: config['container'] = arguments['--container']
  # save config
  if arguments['--config']:
    if arguments['--write-config']:
      for key, value in config.items():
        config_parser.set( configparser.DEFAULTSECT, key, json.dumps(value) )
      with open(config_file_name, 'w') as configfile:
        config_parser.write(configfile)
      logging.info('Successfully writen config "{}"'.format(config_file_name))
      sys.exit(0)
  # config override
  config['resize'] = arguments['--resize']
  if config['resize']:
    config['resize'] = config['resize'].upper()
    if not human2bytes(config['resize']):
      die("Can't parse resize argument \"{}\"".format(config['resize']))
  config['do_mkfs'] = ( arguments['--int-do-mkfs'] is '1' ) if arguments['--int-do-mkfs'] else False
  config['uid'] = pwd.getpwnam(arguments['--user']).pw_uid if arguments['--user'] else os.getuid()
  config['gid'] = pwd.getpwuid(config['uid']).pw_gid
  config['user'] = pwd.getpwuid(config['uid']).pw_name
  config['home'] = pwd.getpwuid(config['uid']).pw_dir
  config['superuser'] = os.getuid() is 0
  config['app_basename'] = os.path.basename(arguments['<application>'])
  config['app_path'] = distutils.spawn.find_executable(arguments['<application>'])
  if not config['app_path']:
    die("Couldn't find application executable for \"{}\"".format(arguments['<application>']))
  config['app_path_hash'] = subprocess.Popen([config['hashtool']],stdout=subprocess.PIPE,stdin=subprocess.PIPE,stderr=subprocess.DEVNULL).communicate(config['app_path'].encode()+b'\n')[0].decode().split(' ')[0] # extra newline for compability with bash script version
  config['app_id'] = config['app_id'].replace('$BASENAME',config['app_basename']).replace('$PATHHASH',config['app_path_hash'])
  config['container'] = config['container'].replace('$HOME',config['home']).replace('$APPLICATION_ID', config['app_id'])
  config['open_container'] = '/dev/mapper/{}'.format(config['app_id'])
  config['net_name'] = config['app_id'][:8] + config['app_id'][-7:]
  config['cg_cpu_sub'] = '/sys/fs/cgroup/cpu/{}'.format(config['net_name'])
  config['cg_devices_sub'] = '/sys/fs/cgroup/devices/{}'.format(config['net_name'])
  config['cg_memory_sub'] = '/sys/fs/cgroup/memory/{}'.format(config['net_name'])
  if config['xdg_runtime_dir']: config['xdg_runtime_dir'] = config['xdg_runtime_dir'].replace('$UID',str(config['uid']))
  config['app_arguments'] = arguments['<arguments>']
  config['verbose'] = False
  if arguments['--verbose']:
    logging.getLogger().setLevel( logging.DEBUG )
    config['verbose'] = True
  new_cmdline = [ sys.argv[0] ]
  new_cmdline += [ '--user', config['user'] ]
  new_cmdline += [ '--display', config['display'] ]
  for argument, value in arguments.items():
    if not argument.startswith('-'): continue
    if type(value) is bool:
      if value is True:
        new_cmdline.append( argument )
    elif type(value) in [ int, float, str ]:
      new_cmdline.append( argument )
      new_cmdline.append( value )
    elif type(value) is list:
      for list_value in value:
        new_cmdline.append( argument )
        new_cmdline.append( list_value )
  new_cmdline.append( config['app_path'] )
  new_cmdline += arguments['<arguments>']
  config['cmdline'] = new_cmdline
  config['fsck'] = distutils.spawn.find_executable('fsck.{}'.format(config['fs_type']))
  config['mkfs'] = distutils.spawn.find_executable('mkfs.{}'.format(config['fs_type']))
  config['parent'] = True
  config['parent_pid'] = os.getpid()
  return config

def escalate_priviledges( config ):
  if not config['superuser']:
    logging.info('Need to escalate priviledges')
    cmdline = [ config['cmdline'][0] ]
    cmdline += [ '--int-do-mkfs', '1' if config['do_mkfs'] else '0' ]
    cmdline += config['cmdline'][1:]
    if sys.stdin.isatty() or sys.stdout.isatty() or sys.stderr.isatty():
      os.execvp( 'sudo', [ 'sudo' ] + cmdline )
    else:
      os.execvp( 'pkexec', [ 'pkexec' ] + cmdline )
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
  logging.info('LUKS opening container \"{container}\"'.format(**config))
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
  logging.info( "Creating filesystem" )
  logging.warning( "Warning: Random data caused by reading freshly created crypted container may irritate mkfs" )
  if config['quiet']: outfd=subprocess.DEVNULL
  else: outfd=sys.stdout
  returncode = subprocess.run([ config['mkfs'], config['open_container'] ], stdout=outfd, stderr=outfd).returncode
  if returncode is 0:
    logging.info('Successfully created filesystem')
  else:
    die("Mkfs failed")

def fsck_open_container( config, force=False ):
  logging.info( "Checking filesystem" )
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
      with open( config['container'], 'ab' ) as f: f.truncate( human2bytes( config['resize'] ) )
    elif new_size < current_size:
      config['resize_mode'] = 'shrink'
    else:
      config['resize_mode'] = 'auto'

def main():
  logging.basicConfig(format='[{}|%(levelname)s] %(message)s'.format(sys.argv[0]),level=logging.INFO)
  config=parse_arguments()
  logging.debug('Configuration:\n{}'.format(config))
  if not config['superuser']:
    if not config['mkfs']: logging.warning('Mkfs tool for "{}" not found. Not able to format new containers'.format(config['fs_type']))
    if not config['fsck']: logging.warning('Fsck tool for "{}" not found. Not able to check container filesystem'.format(config['fs_type']))
    if not os.path.exists( config['container'] ):
      config['do_mkfs'] = True
      create_empty_container( config )
    escalate_priviledges( config )
  if not os.path.exists( config['container'] ):
    die("Container \"{container}\" does not exist".format(**config))
  if config['do_mkfs']:
    luks_format_container( config )
  decide_about_resize( config )
  if os.path.exists( config['open_container'] ):
    logging.warning('Container already open at "{open_container}"'.format(**config))
    answer = input('Do you want to close it? [y/N] ')
    if answer.lower() not in [ 'y', 'yes' ]:
      sys.exit(2)
    if not try_close_container(config):
      die("Timed out while trying to close container")
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
      logging.info("Resizing filesystem")
      resize2fs = subprocess.run(['resize2fs',config['open_container'],new_size])
      if resize2fs.returncode is not 0:
        die("Resizing filesystem failed")
    fsck_open_container( config )
    if config['resize'] and config['resize_mode'] is 'shrink':
      logging.info("Shrinking container file")
      with open( config['container'], 'ab' ) as f: f.truncate( human2bytes( config['resize'] ) )

  # real size of sparse container file
  config['realsize']=bytes2human( os.stat(config['container']).st_blocks*512, long_names=True )
  logging.info("Container currently uses {realsize}".format(**config))

  # xauth setup
  if config['configure_xauth']:
    if 'CLONE_NEWUTS' in config['unshare_flags']:
      auth_file = False
      # find Xorg process to add a new key to it's auth file
      pgrep = subprocess.check_output(['pgrep','-a','X'])
      match = re.search(b'.* -auth (/[^ ]+)',pgrep)
      if match:
        config['xauth_file'] = match.group(1).decode()
        logging.info('Xauth adding "{net_name}/unix:0" to host auth file "{xauth_file}"'.format(**config))
        if os.path.exists(config['xauth_file']):
          subprocess.run(['xauth','-f',config['xauth_file'],'add','{net_name}/unix:0'.format(**config),'.',config['xauth_key']])
    elif config['display'] and config['display'].startswith(':'):
      # extract existing xauth cookie
      config['xauth_cookie'] = subproccess.check_output(['xauth','extract','-','{}/unix{}'.format(os.uname().nodename,config['display'])])

  # forking because we can
  child_pid = os.fork()
  if child_pid:
    def clear_cgroup_subs():
      if os.path.exists( config['cg_devices_sub'] ): os.rmdir( config['cg_devices_sub'] )
      if os.path.exists( config['cg_memory_sub'] ): os.rmdir( config['cg_memory_sub'] )
      if os.path.exists( config['cg_cpu_sub'] ): os.rmdir( config['cg_cpu_sub'] )
    atexit.register( clear_cgroup_subs )
    def revert_xauth_changes():
      if os.path.exists(config['xauth_file']):
        logging.info('Xauth removing "{net_name}/unix:0" from "{xauth_file}"'.format(**config))
        subprocess.run(['xauth','-f',config['xauth_file'],'remove','{net_name}/unix:0'.format(**config)])
    if config['configure_xauth']: atexit.register( revert_xauth_changes )
    def parent_sigterm_handler( signr, stack ):
      logging.info("Forwarding SIGTERM to child and waiting for it to finish")
      os.kill( child_pid, signal.SIGTERM )
      deadline = datetime.datetime.utcnow() + datetime.timedelta(seconds=config['teardown_timeout'])
      while True:
        pid, returncode = os.waitpid( child_pid, os.WNOHANG )
        if ( pid, returncode ) != ( 0, 0 ):
          sys.exit( returncode>>8|returncode&0xff )
        if datetime.datetime.utcnow() > deadline:
          logging.info("Timed out")
          sys.exit(1)
          break
        time.sleep(2)
    signal.signal( signal.SIGTERM, parent_sigterm_handler )
    while True:
      try:
        pid, returncode = os.waitpid( child_pid, 0 )
        sys.exit( returncode>>8|returncode&0xff )
      except KeyboardInterrupt:
        # forward CTRL+C and continue waiting
        os.kill( child_pid, signal.SIGINT )
  else:
    config['parent'] = False

    # make sure we get a signal when parent dies
    libc.prctl( PR_SET_PDEATHSIG, signal.SIGTERM, 0, 0, 0 )

    # call unshare function
    if libc.unshare( config['unshare_flags'] ) is not 0:
      die("Unshare failed")

    # keep links to parent namespaces
    parent_mnt_ns = open('/proc/{}/ns/mnt'.format(config['parent_pid']),'rb')
    parent_pid_ns = open('/proc/{}/ns/pid'.format(config['parent_pid']),'rb')
    parent_net_ns = open('/proc/{}/ns/net'.format(config['parent_pid']),'rb')
    # helper for subprocess to switch namespaces
    def set_parent_ns():
      libc.setns( parent_mnt_ns.fileno(), UNSHARE_FLAGS.flags['CLONE_NEWNS'] )
      libc.setns( parent_pid_ns.fileno(), UNSHARE_FLAGS.flags['CLONE_NEWPID'] )
      libc.setns( parent_net_ns.fileno(), UNSHARE_FLAGS.flags['CLONE_NEWNET'] )

    # unshare mountpoints
    if 'CLONE_NEWNS' in config['unshare_flags']:
      if libc.mount( b'none', b'/', ctypes.c_char_p(0), ['MS_REC','MS_PRIVATE'], ctypes.c_char_p(0) ) is not 0:
        die('Changing mount propagation of / to private failed')

    # cgroup experiment
    if 'CLONE_NEWCGROUP' in config['unshare_flags']:
      os.mkdir(config['cg_cpu_sub'])
      open( '{}/cgroup.procs'.format( config['cg_cpu_sub']), 'w' ).write(str(os.getpid()))
      os.mkdir(config['cg_devices_sub'])
      open( '{}/cgroup.procs'.format( config['cg_devices_sub']), 'w' ).write(str(os.getpid()))
      os.mkdir(config['cg_memory_sub'])
      open( '{}/cgroup.procs'.format( config['cg_memory_sub']), 'w' ).write(str(os.getpid()))
      # set cpu quota
      if config['cpu_quota']:
        period = int(open( '{}/cpu.cfs_period_us'.format( config['cg_cpu_sub']), 'r' ).read())
        quota = int( period * config['cpu_quota'] )
        open( '{}/cpu.cfs_quota_us'.format( config['cg_cpu_sub']), 'w' ).write(str(quota))
      # set memory usage limit
      if config['max_memory']:
        open( '{}/memory.limit_in_bytes'.format( config['cg_memory_sub']), 'w' ).write(str( human2bytes(config['max_memory']) ))
        open( '{}/memory.memsw.limit_in_bytes'.format( config['cg_memory_sub']), 'w' ).write(str( human2bytes(config['max_memory']) ))


    # install signal handler
    def child_sigterm_handler( signr, stack ):
      sys.exit(242)
    signal.signal( signal.SIGTERM, child_sigterm_handler )

    # start init
    initproc = subprocess.Popen(['sleep','infinity'])
    def init_exit_handler():
      if initproc.poll() is None:
        initproc.terminate()
        try:
          sys.stdout, sys.stderr = initproc.communicate( sys.stdin, timeout=2 )
        except subprocess.TimeoutExpired:
          pass
      initproc.kill()
    atexit.register( init_exit_handler )

    # hide /run
    if config['hide_run']:
      if libc.mount( b'tmpfs', b'/run', b'tmpfs', ['MS_NOSUID','MS_NOEXEC','MS_NODEV'], ctypes.c_char_p(0) ) is not 0:
        die('Could not hide "/run": {}'.format(os.strerror(ctypes.get_errno())))

    # create XDG_RUNTIME_DIR if not exists
    if config['xdg_runtime_dir']:
      if not os.path.exists( config['xdg_runtime_dir'] ):
        if not config['hide_run']:
          die('Refusing to create XDG_RUNTIME_DIR without hiding "/run"')
        os.makedirs( config['xdg_runtime_dir'] )
        os.chown( config['xdg_runtime_dir'], config['uid'], config['gid'] )
        os.chmod( config['xdg_runtime_dir'], 0o700 )
      os.environ['XDG_RUNTIME_DIR'] = config['xdg_runtime_dir']

    # get a private space for this script
    if 'CLONE_NEWNS' in config['unshare_flags']:
      private_space='/run/{}'.format(os.path.basename(sys.argv[0]))
      os.makedirs(private_space, exist_ok=True, mode=0o700)
      if libc.mount( b'tmpfs', private_space.encode(), b'tmpfs', ['MS_NOSUID','MS_NOEXEC','MS_NODEV'], ctypes.c_char_p(0) ) is not 0:
        die('Could not create a private space: {}'.format(os.strerror(ctypes.get_errno())))

    # bind dirs feature
    if 'CLONE_NEWNS' in config['unshare_flags']:
      for bind_dir in config['bind_dirs']:
        os.makedirs('{}/{}'.format(private_space,bind_dir))
        if libc.mount( 
           '{}/{}'.format(config['home'],bind_dir).encode(), 
           '{}/{}'.format(private_space,bind_dir).encode(), 
           ctypes.c_char_p(0), 
           ['MS_BIND'], ctypes.c_char_p(0) ) is not 0:
          die('Bind mount "{}" failed: {}'.format(bind_dir,os.strerror(ctypes.get_errno())))

    # uts namespace
    if 'CLONE_NEWUTS' in config['unshare_flags']:
      subprocess.run(['hostname',config['net_name']])

    # network init
    if 'CLONE_NEWNET' in config['unshare_flags']:
      subprocess.run([
        'ip','link','add',config['net_name'],
        'type','veth',
        'peer','name',config['net_name'],
        'netns','/proc/{}/ns/net'.format(config['parent_pid'])])

    # spoof MAC address
    if config['mac_address']:
      if 'CLONE_NEWNET' in config['unshare_flags']:
        subprocess.run(['ip','link','set',config['net_name'],'address',config['mac_address']])
      else:
        die('Refusing to spoof MAC address on shared network')

    # setting up network 
    if 'CLONE_NEWNET' in config['unshare_flags']:
      def change_to_parent_net_namespace():
        libc.setns( parent_net_ns.fileno(), UNSHARE_FLAGS.flags['CLONE_NEWNET'] )
      subprocess.run(['ip','link','set','lo','up'])
      subprocess.run(['ip','link','set',config['net_name'],'up'])
      subprocess.run(['ip','link','set',config['net_name'],'up'],preexec_fn=change_to_parent_net_namespace)
      random_ip_part = random.randint(0,254)
      veth_host_ip4 = '192.168.{}.1'.format(random_ip_part)
      veth_vm_ip4 = '192.168.{}.2'.format(random_ip_part)
      veth_subnet4 = '24'
      subprocess.run(['ip','address','add','{}/{}'.format(veth_vm_ip4,veth_subnet4),'dev',config['net_name']])
      subprocess.run(['ip','address','add','{}/{}'.format(veth_host_ip4,veth_subnet4),'dev',config['net_name']],preexec_fn=change_to_parent_net_namespace)
      # setting up NAT
      if config['do_nat']:
        subprocess.run(['sh','-c','echo 1 > /proc/sys/net/ipv4/conf/{net_name}/forwarding'.format(**config)],preexec_fn=set_parent_ns)
        default_route_interfaces = subprocess.check_output(['sh','-c','ip route show default |grep -o " dev [^ ]*"|cut -d" " -f3-'],preexec_fn=set_parent_ns).strip().decode().split('\n')
        for default_route_interface in default_route_interfaces:
          if not default_route_interface: continue
          logging.warning('Configuring network interface "{}" for masquerading'.format(default_route_interface))
          subprocess.run(['sh','-c','echo 1 > /proc/sys/net/ipv4/conf/{}/forwarding'.format(default_route_interface)],preexec_fn=set_parent_ns)
          cmd='iptables -t nat -C POSTROUTING -o {} -j MASQUERADE'.format(default_route_interface)
          subprocess.run(['sh','-c','{} 2>/dev/null || {}'.format(cmd,cmd.replace('-C','-A'))],preexec_fn=set_parent_ns)
        subprocess.run(['ip','route','add','default','via',veth_host_ip4,'dev',config['net_name']])

    # start tcpdump
    if config['do_tcpdump'] and 'CLONE_NEWNET' in config['unshare_flags']:
      output_filename='{}.{}.pcap'.format(config['net_name'],datetime.datetime.utcnow().strftime('%Y%m%d%H%M'))
      pathlib.Path( output_filename ).touch( mode=0o600 )
      os.chown( output_filename, config['uid'], config['gid'] )
      tcpdump = subprocess.Popen(['tcpdump','-ni',config['net_name'],'-w',output_filename,'tcp[tcpflags] & (tcp-syn|tcp-fin) != 0 or not tcp'],stderr=sys.stderr)
      atexit.register( tcpdump.wait, timeout=config['teardown_timeout']/2 )
      atexit.register( tcpdump.send_signal, signal.SIGTERM )

    # pid namespace and /proc
    if 'CLONE_NEWNS' in config['unshare_flags'] and 'CLONE_NEWPID' in config['unshare_flags']:
      if libc.mount( b'none', b'/proc', ctypes.c_char_p(0), 
                     ['MS_REC','MS_PRIVATE'], ctypes.c_char_p(0) ) is not 0:
        die('Changing mount propagation of /proc to private failed: {}'.format(os.strerror(ctypes.get_errno())))
      if libc.mount( b'proc', b'/proc', b'proc', 
                     ['MS_NOSUID','MS_NOEXEC','MS_NODEV'], ctypes.c_char_p(0) ) is not 0:
        # TODO FIXME
        workaround = subprocess.run(['mount','proc','-o','nosuid,noexec,nodev','-t','proc','/proc'])
        if workaround.returncode is not 0:
          die('Mount private /proc failed: {}'.format(os.strerror(ctypes.get_errno())))

    # hide other user homes too
    if os.path.dirname(config['home']) == '/home':
      if libc.mount( b'tmpfs', b'/home', b'tmpfs', ['MS_NOSUID','MS_NOEXEC','MS_NODEV'], ctypes.c_char_p(0) ) is not 0:
        die('Could not hide "/home": {}'.format(os.strerror(ctypes.get_errno())))
      os.mkdir( config['home'] )

    # mount home
    if libc.mount( 
         config['open_container'].encode(), 
         config['home'].encode(), 
         config['fs_type'].encode(), 
         [], ctypes.c_char_p(0) ) is not 0:
      die('Mount private home failed: {}'.format(os.strerror(ctypes.get_errno())))
    # chown&chmod fresh home
    if config['do_mkfs']:
      os.chown( config['home'], config['uid'], config['gid'] )
      os.chmod( config['home'], 0o700 )
    # change directory to new home
    os.chdir(config['home'])

    # export HOME
    os.environ['HOME'] = config['home']

    # bind dirs second part 
    if 'CLONE_NEWNS' in config['unshare_flags']:
      for bind_dir in config['bind_dirs']:
        os.makedirs('{}/{}'.format(config['home'],bind_dir),exist_ok=True)
        if libc.mount( 
           '{}/{}'.format(private_space,bind_dir).encode(), 
           '{}/{}'.format(config['home'],bind_dir).encode(), 
           ctypes.c_char_p(0), 
           ['MS_BIND'], ctypes.c_char_p(0) ) is not 0:
          logging.error('2nd Bind mount "{}" failed: {}'.format(bind_dir,os.strerror(ctypes.get_errno())))
        if libc.umount( '{}/{}'.format(private_space,bind_dir).encode() ) is not 0:
          logging.warning('Umount cleanup for bind dir "{}" failed'.format(bind_dir))
      for bind_dir in config['bind_dirs']:
        os.removedirs( '{}/{}'.format(private_space,bind_dir) )

    # cgroup device restriction
    if config['restrict_devices']:
      if 'CLONE_NEWCGROUP' not in config['unshare_flags']:
        die('Can not restrict devices access without unshared cgroup')
      open( '{}/devices.deny'.format( config['cg_devices_sub']), 'w' ).write('a')
      allow_list = [
          'c 1:3 rw', # /dev/null
          'c 1:5 rw', # /dev/zero
          'c 1:7 rw', # /dev/full
          'c 1:8 rw', # /dev/random
          'c 1:9 rw', # /dev/urandom
          'c 5:2 rw', # ptmx
          'c 136:* rw', # /dev/pts/
        ]
      for rule in allow_list:
        open( '{}/devices.allow'.format( config['cg_devices_sub']), 'w' ).write(rule)

    # hide tmp and bind .X11-unix
    if config['hide_tmp'] and ( 'CLONE_NEWNS' in config['unshare_flags'] ):
      if config['do_bind_.X11-unix']:
        private_x11_unix = '{}/.X11-unix'.format(private_space)
        if os.path.exists('/tmp/.X11-unix'):
          os.mkdir(private_x11_unix.encode())
          if libc.mount( b'/tmp/.X11-unix', private_x11_unix.encode(), ctypes.c_char_p(0), ['MS_BIND'], ctypes.c_char_p(0) ) is not 0:
            die('Could not bind "/tmp/.X11-unix" to private space: {}'.format(os.strerror(ctypes.get_errno())))
      # hide /tmp
      if libc.mount( b'tmpfs', b'/tmp', b'tmpfs', ['MS_NOSUID','MS_NOEXEC','MS_NODEV'], ctypes.c_char_p(0) ) is not 0:
        die('Could not hide "/tmp": {}'.format(os.strerror(ctypes.get_errno())))
      if config['do_bind_.X11-unix'] and os.path.exists(private_x11_unix):
        os.mkdir('/tmp/.X11-unix')
        if libc.mount( private_x11_unix.encode(), b'/tmp/.X11-unix', ctypes.c_char_p(0), ['MS_BIND'], ctypes.c_char_p(0) ) is not 0:
          die('Could not bind private space to "/tmp/.X11-unix": {}'.format(os.strerror(ctypes.get_errno())))
        if libc.umount( private_x11_unix.encode() ) is not 0:
          logging.warning('Could not unmount private space for .X11-unix')
        else:
          os.rmdir( private_x11_unix )

    # handle xauth
    if config['configure_xauth']:
      new_xauth_file = '{home}/.Xauthority-{net_name}'.format(**config)
      os.environ['XAUTHORITY'] = new_xauth_file
      open( new_xauth_file, 'wb' ).truncate( 0 )
      if 'CLONE_NEWUTS' in config['unshare_flags']:
        subprocess.run(['xauth','-f',new_xauth_file,'add','{net_name}/unix:0'.format(**config),'.',config['xauth_key']])
      elif 'xauth_cookie' in config:
        subprocess.Popen(['xauth','-f',new_xauth_file,'add','merge','-']).communicate(config['xauth_cookie'])
      atexit.register( os.unlink, new_xauth_file )
      os.chown( new_xauth_file, config['uid'], config['gid'] )

    # our su implementation
    def change_user():
      os.setgid( int(config['gid']) )
      os.setuid( int(config['uid']) )

    def application_preexec():
      change_user()
      if config['use_seccomp']:
        import libseccomp.seccomp
        f = libseccomp.seccomp.SyscallFilter(defaction=libseccomp.seccomp.LOG)
        for syscall in config['seccomp_syscalls']:
          if syscall.startswith('-'):
            f.add_rule( libseccomp.seccomp.ERRNO(126), syscall[1:] )
          elif syscall.startswith('!'):
            f.add_rule( libseccomp.seccomp.KILL, syscall[1:] )
          else:
            f.add_rule( libseccomp.seccomp.ALLOW, syscall )
        f.load()
      #libc.prctl( PR_SET_SECCOMP, SECCOMP_MODE_STRICT, 0, 0, 0 )

    # launch dbus
    if config['do_launch_dbus']:
      if not config['xdg_runtime_dir']:
        die("Can not launch dbus without faking XDG_RUNTIME_DIR")
      dbus = subprocess.Popen(['dbus-daemon','--session','--address=unix:path={xdg_runtime_dir}/bus-{net_name}'.format(**config),'--nosyslog','--print-address'],stdout=subprocess.PIPE,preexec_fn=application_preexec)
      dbus_address = dbus.stdout.readline().strip()
      os.environ['DBUS_SESSION_BUS_ADDRESS'] = dbus_address.decode()

    # export DISPLAY
    os.environ['DISPLAY'] = config['display']

    # finally launch our application ...
    application = subprocess.Popen([config['app_path']]+config['app_arguments'],preexec_fn=application_preexec )

    # teardown helper
    def application_exit_helper():
      logging.info('Teardown initiated...')
      deadline = datetime.datetime.utcnow() + datetime.timedelta(seconds=config['teardown_timeout']-2)
      while application.poll() is None:
        logging.info("Subprocess still alive ({}). Sending SIGTERM".format(application.pid))
        application.terminate()
        if datetime.datetime.utcnow() > deadline:
          logging.info("Timed out. Sending SIGKILL")
          application.kill()
          sys.exit(1)
          break
        try:
          sys.stdout, sys.stderr = application.communicate( sys.stdin, timeout=1 )
          time.sleep( 1 )
        except subprocess.TimeoutExpired:
          pass
        if not application.returncode:
          logging.info("Retrying")
      sys.exit(application.returncode)

    # connect stdin, stdout and stderr to application
    while application.poll() is None:
      try:
        sys.stdout, sys.stderr = application.communicate( sys.stdin )
      except KeyboardInterrupt:
        application.send_signal( signal.SIGINT )

    application.terminate()
    application_exit_helper()


syscalls = [
##############
# filesystem #
##############
  'open', 'openat', 'creat', # open and possibly create a file
  'name_to_handle_at', 'open_by_handle_at', # obtain handle for a pathname and open file via a handle
  'close', # close a file descriptor
  'access', 'faccessat', # determine accessibility of a file relative to directory file descriptor
  'stat', 'stat64', 'fstat', 'fstat64', 'fstatat64', 'newfstatat', 'lstat', 'lstat64', # get file status
  'statfs', 'statfs64', 'fstatfs', 'fstatfs64', # get filesystem statistics
  'ustat', # get filesystem statistics
  'flock', # apply or remove an advisory lock on an open file
  '-chmod', '-fchmod', '-fchmodat', # change permissions of a file
  '-chown', '-chown32', '-fchown', '-fchown32', '-fchownat', '-lchown', '-lchown32', # change ownership of a file
  'fcntl', 'fcntl64', # file control
  'fsync', # synchronize changes to a file
  'readlink', 'readlinkat', # read value of a symbolic link
  'rename', 'renameat', 'renameat2', # change the name or location of a file
  '-link', '-linkat', # make a new name for a file
  'unlink', 'unlinkat', # delete a name and possibly the file it refers to
  'symlink', 'symlinkat', # make a symbolic link relative to directory file descriptor
  'dup', 'dup2', 'dup3', # duplicate an open file descriptor
  '-quotactl', # manipulate disk quotas
  'umask', # set file mode creation mask
  '-mount', '-umount', '-umount2', # mount and umount filesystem
  'memfd_create', # create an anonymous file
  'utime', # set file access and modification times
  'utimensat', 'utimes', # set file access and modification times relative to directory file descriptor
  'futimesat', # change timestamps of a file relative to a directory file descriptor
#######################
# extended attributes #
#######################
  '-statx', # get file status (extended)
  '-getxattr', '-lgetxattr', '-fgetxattr', # retrieve an extended attribute value
  '-listxattr', '-llistxattr', '-flistxattr', # list extended attribute names
  '-removexattr', '-lremovexattr', '-fremovexattr', # remove an extended attribute
  '-setxattr', '-lsetxattr', '-fsetxattr', # set an extended attribute value
##########
# notify #
##########
  'inotify_init', 'inotify_init1', # initialize an inotify instance
  'inotify_add_watch', 'inotify_rm_watch', # add/remove a watch on an initialized inotify instance
  'fanotify_init', # create and initialize fanotify group
  'fanotify_mark', # add, remove, or modify an fanotify mark on a filesystem object
#################
# file contents #
#################
  'read', # read from a file descriptor
  'write', # write to a file descriptor
  'pread64', # read from to a file descriptor at a given offset
  'pwrite64', # write to a file descriptor at a given offset
  'readv', 'preadv', 'preadv2', # read data from multiple buffers
  'writev', 'pwritev', 'pwritev2', # write data into multiple buffers
  'lseek', #  move the read/write file offset
  'fallocate', # preallocate or deallocate space to a file
  'fadvise64', 'fadvise64_64', # predeclare an access pattern for file data
  'readahead', # initiate file readahead into page cache
  'truncate', 'truncate64', # truncate a file to a specified length
  'ftruncate', 'ftruncate64', # truncate a file to a specified length
  'fdatasync', # synchronize the data of a file (REALTIME)
  'copy_file_range', # Copy a range of data from one file to another
  'sendfile', 'sendfile64', # transfer data between file descriptors
  'splice', # splice data to/from a pipe
  'vmsplice', # splice user pages into a pipe
  'tee', # duplicating pipe content
  'sync', 'syncfs', # commit filesystem caches to disk
  'sync_file_range', 'sync_file_range2', # sync a file segment with disk
###########
# devices #
###########
  'ioctl', # control device
  'ioperm', # set port input/output permissions
  'iopl', # change I/O privilege level
  'ioprio_set', 'ioprio_get', # set/get I/O scheduling class and priority
  'io_cancel', # cancel an outstanding asynchronous I/O operation
  'io_destroy', # destroy an asynchronous I/O context
  'io_getevents', # read asynchronous I/O events from the completion queue
  'io_setup', # create an asynchronous I/O context
  'io_submit', # submit asynchronous I/O blocks for processing
  'mknod', 'mknodat', # create a special or ordinary file
###############
# directories #
###############
  'getdents', 'getdents64', # get directory entries
  'readdir', # read a directory
  'mkdir', 'mkdirat', # create a directory
  'rmdir', # delete a directory
  'getcwd', # get current working directory
  'chdir', 'fchdir', # change working directory
  '!chroot', # change root directory
  '!pivot_root', # change the root filesystem
###########
# sockets #
###########
  'socket', # create an endpoint for communication
  'socketpair', # create a pair of connected sockets
  'bind', # bind a name to a socket
  'listen', # listen for connections on a socket
  'connect', # set and get signal alternate stack context
  'accept', 'accept4', # accept a connection on a socket
  'send', 'sendto', 'sendmsg', # send a message on a socket
  'recv', 'recvfrom', 'recvmsg', # receive a message from a socket
  'sendmmsg', # send multiple messages on a socket
  'recvmmsg', # receive multiple messages from a socket
  'setsockopt', 'getsockopt', # set/get the socket options
  'getsockname', # get the socket name
  'getpeername', # get the name of the peer socket
  'shutdown', # shut down part of a full-duplex connection
#############
# processes #
#############
  'getpid', # get process identification
  'getsid', # get the process group ID of a session leader
  'setsid', # creates a session and sets the process group ID
  'setpgid', 'getpgid', # set/get the process group ID for a process
  'getpgrp', # get the process group ID
  'gettid', # get thread identification
  'capset', 'capget', # set/get capabilities of thread(s)
  'set_tid_address', # set pointer to thread ID
  'prctl', # operations on a process
  'arch_prctl', # set architecture-specific thread state
  'clone', # create a child process
  'execve', # execute a program
  'execveat', # execute program relative to a directory file descriptor
  'kill', # send signal to a process
  'tkill', 'tgkill', # send a signal to a thread
  'exit', # terminate the calling process
  'exit_group', # exit all threads in a process
  'pipe', 'pipe2', # create an interprocess channel
  'getppid', # get parent process identification
  '!idle', # make process 0 idle
  '!kcmp', # compare two processes to determine if they share a kernel resource
  '-process_vm_readv', '-process_vm_writev', # transfer data between process address spaces
  '!ptrace', # process trace
###################
# synchronisation #
###################
  'select', 'pselect6', '_newselect', # wait until one or more file descriptors become "ready"
  'futex', # fast user-space locking
  'set_robust_list', 'get_robust_list', # set/get list of robust futexes
  'poll', 'ppoll', # wait for some event on a file descriptor
  'wait4', # wait for process to change state, BSD style
  'epoll_create', 'epoll_create1', # open an epoll file descriptor
  'epoll_ctl', # control interface for an epoll file descriptor
  'epoll_wait', 'epoll_pwait', # wait for an I/O event on an epoll file descriptor
  'eventfd', 'eventfd2', # create a file descriptor for event notification
  'pause', # wait for signal
  'waitpid', # wait for a child process to stop or terminate
  'waitid', # wait for a child process to change state
  'semctl', # XSI semaphore control operations
  'semget', # get set of XSI semaphores
  'semop', 'semtimedop', # System V semaphore operations
##############
# scheduling #
##############
  'sched_yield', # yield the processor
  'sched_setaffinity', 'sched_getaffinity', # set and get a thread's CPU affinity mask
  'sched_get_priority_max', 'sched_get_priority_min', # get priority limits (REALTIME)
  'sched_setattr', 'sched_getattr', # set and get scheduling policy and attributes
  'sched_setparam', 'sched_getparam', # set and get scheduling parameters (REALTIME)
  'sched_setscheduler', 'sched_getscheduler', # get scheduling policy (REALTIME)
  'sched_rr_get_interval', # get execution time limits (REALTIME)
  'setpriority', 'getpriority', # get and set the nice value
  '-nice', # nice - change process priority
###########
# signals #
###########
  'signal', # signal management
  'signalfd', 'signalfd4', # create a file descriptor for accepting signals
  'sigaction', 'rt_sigaction', # examine and change a signal action
  'sigprocmask', 'rt_sigprocmask', # examine and change blocked signals
  'sigreturn', 'rt_sigreturn', # return from signal handler and cleanup stack frame
  'sigpending', 'rt_sigpending', # examine pending signals
  'sigsuspend', 'rt_sigsuspend', # wait for a signal
  'rt_sigqueueinfo', 'rt_tgsigqueueinfo', # queue a signal and data
  'rt_sigtimedwait', # synchronously wait for queued signals
  'sigaltstack', # set and get signal alternate stack context
  'alarm', # set an alarm clock for delivery of a signal
##########
# memory #
##########
  '-mbind', # set memory policy for a memory range
  'membarrier', # issue memory barriers on a set of threads
  'madvise', # give advice about use of memory
  'mmap', 'mmap2', 'munmap', # map files or devices into memory
  'remap_file_pages', # create a nonlinear file mapping
  'mprotect', 'pkey_mprotect', # set protection on a region of memory
  'pkey_alloc', 'pkey_free', # allocate or free a protection key
  '-set_mempolicy', # set default NUMA memory policy for a thread and its children
  'get_mempolicy', # retrieve NUMA memory policy for a thread
  'set_thread_area', 'get_thread_area', # set a GDT entry for thread-local storage
  '-shmctl', # XSI shared memory control operations
  'shmat', # XSI shared memory attach operation
  'shmdt', # XSI shared memory detach operation
  'shmget', # get an XSI shared memory segment
  '-cacheflush', # flush contents of instruction and/or data cache
  '-migrate_pages', # move all pages in a process to another set of nodes
  '-move_pages', # move individual pages of a process to another node
  '-mincore', # determine whether pages are resident in memory
  '-mlock', '-mlock2', '-munlock', '-mlockall', '-munlockall', # lock and unlock memory
  '-mremap', # remap a virtual memory address
  '-msync', # synchronize memory with physical storage
  '-swapon', '-swapoff', # start/stop swapping to file/device
##################
# message queues #
##################
  '-mq_open', # open a message queue
  '-mq_getsetattr', # get/set message queue attributes
  '-mq_notify', # register for notification when a message is available
  '-mq_timedreceive', # receive a message from a message queue
  '-mq_timedsend', # send a message to a message queue
  '-mq_unlink', # remove a message queue
  '-msgctl', # XSI message control operations
  '-msgget', # get the XSI message queue identifier
  '-msgrcv', # XSI message receive operation
  '-msgsnd', # XSI message send operation
########
# user #
########
  '-setuid', '-setuid32', # set user identity
  'getuid', 'getuid32', # get real user ID
  '-setgid', '-setgid32', # set group identity
  'getgid', 'getgid32', # get real group ID
  '-setreuid', '-setreuid32', # set real and/or effective user ID
  'geteuid', 'geteuid32', # get effective user ID
  '-setregid', '-setregid32', # set real and/or effective group ID
  'getegid', 'getegid32', # get effective group ID
  '-setresuid', '-setresuid32', # set real, effective and saved group IDs
  'getresuid', 'getresuid32', # get real, effective and saved group IDs
  '-setresgid', '-setresgid32', # set real, effective and saved group IDs
  'getresgid', 'getresgid32', # get real, effective and saved group IDs
  '-setfsuid', '-setfsuid32', # set user identity used for filesystem checks
  '-setfsgid', '-setfsgid32', # set group identity used for filesystem checks
  '-setgroups', '-setgroups32', # set list of supplementary group IDs
  'getgroups', 'getgroups32', # get list of supplementary group IDs
  '-swapcontext', # manipulate user context
########
# time #
########
  'time', # get time in seconds
  '-stime', # set time
  '-settimeofday', 'gettimeofday', # set/get time of day
  '-clock_settime', 'clock_gettime', # set/get the time of the specified clock
  'clock_getres', # finds the resolution (precision) of the specified clock
  'clock_nanosleep', # high resolution sleep
  '-clock_adjtime', # correct the time to synchronize the system clock
  'nanosleep', # high-resolution sleep
  '-adjtimex', # tune kernel clock
  'timer_create', # create a POSIX per-process timer
  'timer_delete', # delete a per-process timer
  'timer_getoverrun', 'timer_gettime', 'timer_settime', # per-process timers
  '-timerfd', # ?
  'timerfd_create', 'timerfd_settime', 'timerfd_gettime', # timers that notify via file descriptors
##########
# system #
##########
  '-getcpu', # determine CPU and NUMA node on which the calling thread is running
  '-sethostname', # set hostname
  '-_sysctl', # read/write system parameters
  '-setdomainname', # set NIS domain name
  'uname', # get name and information about current kernel
  'seccomp', # operate on Secure Computing state of the process
  'sysinfo', # return system information
  'getrusage', # get information about resource utilization
  'setrlimit', 'getrlimit', 'ugetrlimit', 'prlimit64', # set/get resource limits
  '!reboot', # reboot or enable/disable Ctrl-Alt-Del
  '!create_module', # create a loadable module entry
  '!init_module', '!finit_module', # load a kernel module
  '!delete_module', # unload a kernel module
  '!query_module', # query the kernel for various bits pertaining to module
  '!kexec_load', '!kexec_file_load', # load a new kernel for later execution
  '!pciconfig_read', '!pciconfig_write', '!pciconfig_iobase', # pci device information handling
  '!personality', # set the process execution domain
  '!syscall', # indirect system call
  '-syslog', # read and/or clear kernel message ring buffer; set console_loglevel
##################
# key management #
##################
  '!add_key', # add a key to the kernel's key management facility
  '!keyctl', # manipulate the kernel's key management facility
  '!request_key', # request a key from the kernel's key management facility
#############
# profiling #
#############
  '-acct', # switch process accounting on or off
  '-perf_event_open', # set up performance monitoring
  '!lookup_dcookie', # return a directory entry's path (used only by oprofile)
  'times', # get process times
##########
# others #
##########
  'getrandom', # obtain a series of random bytes
  '-restart_syscall', # restart a system call after interruption by a stop signal
  '-bpf', # perform a command on an extended BPF map or program
  '!nfsservctl', # syscall interface to kernel nfs daemon
  '-setns', # reassociate thread with a namespace
  '-unshare', # run program with some namespaces unshared from parent
  '-userfaultfd', # create a file descriptor for handling page faults in user space
  '-vhangup', # virtually hangup the current terminal
##########
# unsure #
##########
  '-breakpoint',
  '-cachectl',
  '-multiplexer',
  '-rtas',
  '-switch_endian',
  '-sys_debug_setcontext',
  '-sysmips',
  '-usr26', '-usr32',
  '-set_tls', '-get_tls', # new TLS API?
######################
# wrong architecture #
######################
  '!arm_fadvise64_64', '!arm_sync_file_range', # wrong architecture
  '!s390_runtime_instr', # enable/disable s390 CPU run-time instrumentation
  '!s390_pci_mmio_write', '!s390_pci_mmio_read', # transfer data to/from PCI MMIO memory page
  '!s390_guarded_storage',
  '!s390_sthyi', # emulate STHYI instruction
  '!spu_create', # create a new spu context
  '!spu_run', # execute an SPU context
  '!subpage_prot', # define a subpage protection for an address range
###############################
# deprecated or unimplemented #
###############################
  '!afs_syscall', '!break', '!ftime', '!getpmsg', '!gtty', '!lock', '!mpx', '!prof', '!profil', '!putpmsg', '!security', '!stty', '!tuxcall', '!ulimit', '!vserver',
  '!get_kernel_syms', # retrieve exported kernel and module symbols
  '!bdflush', # start, flush, or tune buffer-dirty-flush daemon
  '!oldstat', '!oldfstat', '!oldlstat', # get file status
  '!olduname', '!oldolduname', # get name and information about current kernel
  '!epoll_ctl_old', # control interface for an epoll file descriptor
  '!epoll_wait_old', # wait for an I/O event on an epoll file descriptor
  '!oldwait4', # wait for process to change state, BSD style
  '!socketcall', # socket system calls
  '!_llseek', # reposition read/write file offset for lage files on 32-bit platforms
  '!ipc', # System V IPC system calls
  '-fork', # create a child process
  '-vfork', # create a child process and block parent
  '-brk', # change data segment size
  '-setitimer', '-getitimer', # get and set value of interval timer
  '-modify_ldt', # get or set a per-process LDT entry
  '-ssetmask', '-sgetmask', # manipulation of signal mask (obsolete)
  '-sysfs', # get filesystem type information
  '-uselib', # load shared library
  '!vm86old', '!vm86', # enter virtual 8086 mode
]

if __name__ == "__main__":
  main()
