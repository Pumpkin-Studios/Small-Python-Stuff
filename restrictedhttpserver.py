#  restrictedhttpserver.py  (c) 2018 Michel Anders
#
#  simple http server implementation that restricts access based on extensions
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

version = "201801311223"

from http.server import SimpleHTTPRequestHandler, HTTPServer
import re
import os
import urllib
import html
import io
from http import HTTPStatus

# simple request handler that can use the logging facilities of its
# controlling daemon and is able to restrict files based on extension
class RestrictedHTTPRequestHandler(SimpleHTTPRequestHandler):
	logfie = None
	extensions = None
	nodirlist = False

	def log_message(self, format, *args):
		if self.logfie:
			self.logfie("%s %s\n" % (self.address_string(), format%args))
		else:
			super().log_message(format, *args)

	def ext_ok(self, path):
		path = self.translate_path(path)
		if self.extensions is not None:
			if not hasattr(self, 'ext_regex'):
				self.ext_regex = re.compile('(([.](%s))|(/))$' % ("|".join( '('+e+')' for e in self.extensions)))
			return self.ext_regex.search(path)
		return True

	def send_head(self):
		if not self.ext_ok(self.path):
				self.log_message("requested path [%s] does not match regular expression", path)
				self.send_error(403)
				return None
		return super().send_head()

	def list_directory(self, path):
		if self.nodirlist:
			self.send_error(
				HTTPStatus.NOT_FOUND,
				"No permission to list directory")
			return None
		try:
			list = os.listdir(path)
		except OSError:
			self.send_error(
				HTTPStatus.NOT_FOUND,
				"No permission to list directory")
			return None
		list.sort(key=lambda a: a.lower())
		r = []
		try:
			displaypath = urllib.parse.unquote(self.path,
											   errors='surrogatepass')
		except UnicodeDecodeError:
			displaypath = urllib.parse.unquote(path)
		displaypath = html.escape(displaypath, quote=False)
		enc = sys.getfilesystemencoding()
		title = 'Directory listing for %s' % displaypath
		r.append('<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01//EN" '
				 '"http://www.w3.org/TR/html4/strict.dtd">')
		r.append('<html>\n<head>')
		r.append('<meta http-equiv="Content-Type" '
				 'content="text/html; charset=%s">' % enc)
		r.append('<title>%s</title>\n</head>' % title)
		r.append('<body>\n<h1>%s</h1>' % title)
		r.append('<hr>\n<ul>')
		for name in list:
			fullname = os.path.join(path, name)
			displayname = linkname = name
			# Append / for directories or @ for symbolic links
			if os.path.isdir(fullname):
				displayname = name + "/"
				linkname = name + "/"
			if os.path.islink(fullname):
				displayname = name + "@"
				# Note: a link to a directory displays with @ and links with /
			if (os.path.isdir(fullname) or self.ext_ok(fullname)) and not name.startswith('.'):
				r.append('<li><a href="%s">%s</a></li>'
						% (urllib.parse.quote(linkname,
											  errors='surrogatepass'),
						   html.escape(displayname, quote=False)))
		r.append('</ul>\n<hr>\n</body>\n</html>\n')
		encoded = '\n'.join(r).encode(enc, 'surrogateescape')
		f = io.BytesIO()
		f.write(encoded)
		f.seek(0)
		self.send_response(HTTPStatus.OK)
		self.send_header("Content-type", "text/html; charset=%s" % enc)
		self.send_header("Content-Length", str(len(encoded)))
		self.end_headers()
		return f

if __name__ == "__main__":

	from time import sleep, time
	import argparse
	import logging
	import sys
	from daemon import Daemon

	parser = argparse.ArgumentParser(description="Example HTTP Server")

	# daemonization arguments
	parser.add_argument('-p', '--pid-file', default='/var/run/daemon.pid')
	parser.add_argument('-l', '--log-file', default='/var/log/daemon.log')
	parser.add_argument('-r', '--root-dir', default='/tmp')
	parser.add_argument('-n', '--name', default=sys.argv[0], help='name of the server used in log lines')
	parser.add_argument('-u', '--user', default=None, type=str, help='drop privileges of running server to those of user')
	parser.add_argument('-f', '--force', action='store_true', help='start a server even if pid file is present already')
	parser.add_argument('-s', '--stop', action='store_true', help='stop a running server')

	# http server specific arguments
	parser.add_argument('-d', '--debug', action='store_true', help='Run http server in foreground mode')
	parser.add_argument('--bind', '-b', default='', metavar='ADDRESS',
                        help='Specify alternate bind address '
                             '[default: all interfaces]')
	parser.add_argument('port', action='store',
                        default=8000, type=int,
                        nargs='?',
                        help='Specify alternate port [default: 8000]')
	parser.add_argument('-x', '--nodirlist', action='store_true', help='never show a directory listing')
	parser.add_argument('-e','--ext', action='append', help='allowed file extensions (without .) May occur more than once')

	args = parser.parse_args()

	dm = Daemon(user=args.user, rootdir=args.root_dir, pidfile=args.pid_file, force=args.force, logfile=args.log_file, name=args.name)

	if args.stop:
		dm.stop()
	else:
		server_address = (args.bind, args.port)
		RestrictedHTTPRequestHandler.protocol_version = "HTTP/1.0"
		RestrictedHTTPRequestHandler.logfie = lambda self, msg: dm.log(logging.INFO, msg)
		RestrictedHTTPRequestHandler.extensions = args.ext if args.ext is not None else None
		RestrictedHTTPRequestHandler.nodirlist = args.nodirlist

		with HTTPServer(server_address, RestrictedHTTPRequestHandler) as httpd:
			sa = httpd.socket.getsockname()
			serve_message = "Serving HTTP on {host} port {port} (http://{host}:{port}/) ..."
			dm.log(logging.INFO, serve_message.format(host=sa[0], port=sa[1]))
			dm.keep(httpd.socket.fileno())
			if args.debug:
				print("running in foreground")
				httpd.serve_forever()
			else:
				# at this point all imports should have been done because entering the context 
				# does a chroot, unless of course you take care to replicate part of
				# sys.path to the chrooted environment. This means that is a bad idea to have
				# methods import stuff: best practice is to have all imports at the start of
				# a module.
				with dm as d:
					httpd.serve_forever()
