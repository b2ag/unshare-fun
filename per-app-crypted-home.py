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
  --max-memory=SIZE               Set memory limit for container
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
  config['uid'] = os.getuid() if os.getuid() is not 0 else int(os.getenv('uid'))
  config['gid'] = pwd.getpwuid(config['uid']).pw_gid
  config['user'] = pwd.getpwuid(config['uid']).pw_name
  config['home'] = pwd.getpwuid(config['uid']).pw_dir
  config['app_arguments'] = arguments['<arguments>']
  config['app_basename'] = os.path.basename(arguments['<application>'])
  config['unshare_flags'] = [ 'CLONE_NEWNS', 'CLONE_NEWPID', 'CLONE_NEWUTS', 'CLONE_NEWIPC', 'CLONE_NEWNET', 'CLONE_NEWCGROUP' ]
  config['hashtool'] = arguments['--hash']
  config['teardown_timeout'] = int(arguments['--teardown-timeout'])
  config['app_path_hash'] = subprocess.Popen([config['hashtool']],stdout=subprocess.PIPE,stdin=subprocess.PIPE,stderr=subprocess.DEVNULL).communicate(config['app_path'].encode()+b'\n')[0].decode().split(' ')[0] # extra newline for compability with bash script version
  config['app_id'] = arguments['--id'].replace('$BASENAME',config['app_basename']).replace('$PATHHASH',config['app_path_hash'])
  config['container'] = arguments['--container'].replace('$HOME',config['home']).replace('$APPLICATION_ID', config['app_id'])
  config['fs_type'] = arguments['--fs-type'].lower()
  config['fsck'] = distutils.spawn.find_executable('fsck.{}'.format(config['fs_type']))
  config['mkfs'] = distutils.spawn.find_executable('mkfs.{}'.format(config['fs_type']))
  config['key_file'] = arguments['--key-file']
  config['open_container'] = '/dev/mapper/{}'.format(config['app_id'])
  config['do_mkfs'] = os.getuid() is 0 and os.getenv('do_mkfs') is '1'
  config['net_name'] = config['app_id'][:8] + config['app_id'][-7:]
  config['parent'] = True
  config['parent_pid'] = os.getpid()
  config['do_nat'] = arguments['--nat']
  config['do_xhost_add'] = arguments['--xhost-add-localuser']
  config['hide_xgd_runtime_dir'] = not arguments['--skip-xdg-runtime-dir']
  config['xdg_runtime_dir'] = os.getenv('XDG_RUNTIME_DIR')
  config['mac_address'] = arguments['--mac-address']
  config['bind_dirs'] = arguments['-b']
  config['do_tcpdump'] = arguments['--tcpdump']
  config['do_launch_dbus'] = not arguments['--skip-dbus-launch']
  config['cg_memory_sub'] = '/sys/fs/cgroup/memory/{}'.format(config['net_name'])
  config['max_memory'] = arguments['--max-memory']
  if config['max_memory']:
    config['max_memory'] = config['max_memory'].upper()
    if not human2bytes(config['max_memory']):
      die("Can't parse memory limit argument \"{}\"".format(config['max_memory']))
  if arguments['--skip-ipc']:
    config['unshare_flags'].remove('CLONE_NEWIPC')
  if arguments['--skip-network']:
    config['unshare_flags'].remove('CLONE_NEWNET')
  if arguments['--skip-uts']:
    config['unshare_flags'].remove('CLONE_NEWUTS')
  config['resize'] = arguments['--resize']
  if config['resize']:
    config['resize'] = config['resize'].upper()
    if not human2bytes(config['resize']):
      die("Can't parse resize argument \"{}\"".format(config['resize']))
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
                'uid={uid}'.format(**config),
                'do_mkfs={do_mkfs:d}'.format(**config),
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
      logging.info("Resizing filesystem on opened container")
      resize2fs = subprocess.run(['resize2fs',config['open_container'],new_size])
      if resize2fs.returncode is not 0:
        die("Resizing filesystem failed")
    fsck_open_container( config )
    if config['resize'] and config['resize_mode'] is 'shrink':
      logging.info("Shrinking container file")

  # real size of sparse container file
  config['realsize']=bytes2human( os.stat(config['container']).st_blocks*512, long_names=True )
  logging.info("Container currently uses {realsize}".format(**config))

  # xhost add
  if config['do_xhost_add']:
    logging.warning('Running xhost si:localuser:{user}'.format(**config))
    subprocess.run(['xhost','si:localuser:{user}'.format(**config)])

  logging.info("Setting up virtual environment for opened container")

  # forking because we can
  child_pid = os.fork()
  if child_pid:
    def clear_cgroup_subs():
      if os.path.exists( config['cg_memory_sub'] ):
        os.rmdir( config['cg_memory_sub'] )
    atexit.register( clear_cgroup_subs )
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
    PR_SET_PDEATHSIG=1
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
      os.mkdir(config['cg_memory_sub'])
      open( '{}/cgroup.procs'.format( config['cg_memory_sub']), 'w' ).write(str( os.getpid() ))
      # set max memory usage
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

    # get a private space
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

    # setting up network 
    if 'CLONE_NEWNET' in config['unshare_flags']:
      def change_to_parent_net_namespace():
        libc.setns( parent_net_ns.fileno(), UNSHARE_FLAGS.flags['CLONE_NEWNET'] )
      subprocess.run(['ip','link','set','lo','up'])
      if config['mac_address']:
        subprocess.run(['ip','link','set',config['net_name'],'address',config['mac_address']])
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
      tcpdump = subprocess.Popen(['tcpdump','-ni',config['net_name'],'-w',output_filename,'tcp[tcpflags] & (tcp-syn|tcp-fin) != 0 or udp or icmp'],stderr=sys.stderr)
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

    # hide /run/user/<uid>
    if config['hide_xgd_runtime_dir']:
      if libc.mount( b'tmpfs', os.getenv('XDG_RUNTIME_DIR').encode(), b'tmpfs', ['MS_NOSUID','MS_NOEXEC','MS_NODEV'], ctypes.c_char_p(0) ) is not 0:
        die('Could not mount a private XDG_RUNTIME_DIR: {}'.format(os.strerror(ctypes.get_errno())))
      os.chown(os.getenv('XDG_RUNTIME_DIR'),config['uid'],config['gid'])
      os.chmod(os.getenv('XDG_RUNTIME_DIR'),0o700)
    
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

    # our su implementation
    def change_user():
      os.setgid( int(config['gid']) )
      os.setuid( int(config['uid']) )

    # launch dbus
    if config['do_launch_dbus']:
      dbus = subprocess.Popen(['dbus-daemon','--session','--address=unix:path={xdg_runtime_dir}/bus-{net_name}'.format(**config),'--nosyslog','--print-address'],stdout=subprocess.PIPE,preexec_fn=change_user)
      dbus_address = dbus.stdout.readline().strip()
      os.environ['DBUS_SESSION_BUS_ADDRESS'] = dbus_address.decode()

    # finally launch our application ...
    application = subprocess.Popen([config['app_path']]+config['app_arguments'],preexec_fn=change_user )

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

if __name__ == "__main__":
  main()
