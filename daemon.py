#  daemon.py (c) 2018 Michel Anders
#
#  proper python daemonization and sample http server implementation
#
#  This program is free software; you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation; either version 2 of the License, or
#  (at your option) any later version.
#  
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#  
#  You should have received a copy of the GNU General Public License
#  along with this program; if not, write to the Free Software
#  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
#  MA 02110-1301, USA. 

"""
Based on https://github.com/ActiveState/code/tree/master/recipes/Python/278731_Creating_a_daemon_the_Python_way
and https://github.com/thesharp/daemonize/blob/master/daemonize.py
"""

version = "201801311223"

import os
import sys
import pwd
import resource
import signal
import logging

class Daemon:
	"""
	A class that implements basic *nix daemon functionality.
	
	Sample usage:

	dm = Daemon()
	with dm:
		... do something forever ...

	note that the logging makes use of an undocumented attribute (we need
	the fileno of the stream associated with the filehandler) so this 
	might cause issues in the future.
	"""

	# make this a singleton class because a program can only daemonize
	# itself once.
	__instance = None
	def __new__(cls, **kwargs):
		if Daemon.__instance is None:
			Daemon.__instance = object.__new__(cls)
		return Daemon.__instance

	def __init__(self, user=None, rootdir=None, umask=0o27, pidfile=None, force=False, logfile=None, name="daemon"):
		self.user = user
		self.rootdir = rootdir
		self.pidfile = pidfile
		self.force = force
		self.logfile = logfile
		self.logger = None
		self.logfileno = None
		self.name = name
		self.umask = umask
		self.workdir = '/tmp'
		self.pid = None
		self.keepfilenos = []

		if self.logfile:
			logger = logging.getLogger(self.name)
			logger.setLevel(logging.INFO)
			fh = logging.FileHandler(self.logfile)
			fh.setLevel(logging.INFO)
			formatstr = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
			formatter = logging.Formatter(formatstr)
			fh.setFormatter(formatter)
			logger.addHandler(fh)
			self.logger = logger
			self.logger.log(logging.INFO, "Initializing daemon")
			self.logfileno = fh.stream.fileno()  # stream is an undocumented attribute of FileHandler

	MAXFD = 1024

	def log(self, level, message, *args, **kwargs):
		if self.logger:
			self.logger.log(level, message, *args, **kwargs)

	def getpid(self):
		try:
			with open(self.pidfile,'r') as p:
				return int(p.read().strip())
		except:
			return None

	def rm_pid(self):
		try:
			self.log(logging.INFO, "removing old PID file " +  self.pidfile)
			os.unlink(self.pidfile)
			self.log(logging.INFO, "done" +  self.pidfile)
		except FileNotFoundError:
			self.log(logging.INFO, "not found. Ignored.")
			pass  # just ignore it if pidfile gone for whatever reason

	def testpid(self):
		pid = self.getpid()
		try:
			pgid = os.getpgid(pid)  # getgpid only returns nonzero on other processes
		except ProcessLookupError:
			pgid = 0
		if pid is not None and pgid > 0:
			if self.force:
				print("Warning: process already running with pid", pid)
			else:
				raise FileExistsError("process already running with pid %s" % pid)
		self.rm_pid()  # only has effect if not chrooted

	def keep(self, fileno):
		self.keepfilenos.append(fileno)

	def stop(self):
		self.log(logging.INFO, "Sending daemon stop signal...")
		try:
			if self.pid is not None:
				os.kill(self.pid, signal.SIGTERM)
				self.log(logging.INFO, "... done.")
			else:
				pid = self.getpid()
				if pid is not None:
					os.kill(pid, signal.SIGTERM)
					self.log(logging.INFO, "... done.")
		except ProcessLookupError:
			self.log(logging.INFO,"... nothing to stop")


	def daemonize(self):
		"""Detach a process from the controlling terminal and run it in the
		background as a daemon.
		"""

		self.testpid()

		try:
			pid = os.fork()
		except OSError as e:
			raise Exception("%s [%d]" % (e.strerror, e.errno))

		if (pid == 0): # The first child
			os.setsid()
			try:
				pid = os.fork()	# Fork a second child.
			except OSError as e:
				raise Exception("%s [%d]" % (e.strerror, e.errno))

			if (pid == 0):	# The second child.
				if self.pidfile:
					open(self.pidfile,'w').write(str(os.getpid()))
				self.pid = int(os.getpid())
				os.chdir(self.workdir)
				os.umask(self.umask)
			else:
				os._exit(0)	# Exit parent (the first child) of the second child.
		else:
			os._exit(0)	# Exit parent of the first child.

		# at this point the process is daemonised
		# we close any open files except our logger
		maxfd = resource.getrlimit(resource.RLIMIT_NOFILE)[1]
		if (maxfd == resource.RLIM_INFINITY):
			maxfd = self.MAXFD
		for fd in range(0, maxfd):
			try:
				if fd != self.logfileno and fd not in self.keepfilenos:
					os.close(fd)
			except OSError:	# ERROR, fd wasn't open to begin with (ignored)
				pass

		# all fds are closed, this way we open 0,1,2 while directing
		# stin and stdout to /dev/null and stderr to the daemon log for
		# easier debugging
		os.open(os.devnull, os.O_RDWR)
		os.dup2(0, 1)
		os.dup2(self.logfileno, 2)

		if self.user:  # must get user before we chroot and cannot access /etc/passwd anymore
			user = pwd.getpwnam(self.user)
		self.log(logging.INFO, "Daemonisation finalized")
		if self.user:
			uid,gid = user[2],user[3]
			os.chown(self.pidfile, uid, gid)
		if self.rootdir:
			os.chroot(self.rootdir)
			os.chdir('/')
			self.log(logging.INFO, "Chroot executed to " + self.rootdir)
		if self.user:
			os.setgid(gid)
			os.setuid(uid)
			self.log(logging.INFO, "Credentials set to those of user " + self.user)

		def terminate(signalnum, stack):
			self.log(logging.INFO, "Terminating daemon...")
			self.rm_pid()  # only has effect if not chrooted
			os._exit(0)

		# end the daemon. Sent by stop() but can also come from outside
		signal.signal(signal.SIGTERM, terminate)

		self.log(logging.INFO,"pid = %s, ppid = %s, pgid = %s, sid = %s, uid = %s, euid = %s, gid = %s, egid = %s" 
								% (os.getpid(), os.getppid(), os.getpgrp(), os.getsid(0),
									os.getuid(), os.geteuid(), os.getgid(), os.getegid()))

	def __enter__(self):
		self.daemonize()
		return self

	def __exit__(self):
		self.rm_pid()
