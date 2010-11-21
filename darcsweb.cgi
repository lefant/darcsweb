#!/usr/bin/env python

"""
darcsweb - A web interface for darcs
Alberto Bertogli (albertito@blitiri.com.ar)

Inspired on gitweb (as of 28/Jun/2005), which is written by Kay Sievers
<kay.sievers@vrfy.org> and Christian Gierke <ch@gierke.de>
"""

import time
time_begin = time.time()
import sys
import os
import string
import stat
import cgi
import cgitb; cgitb.enable()
import urllib
import xml.sax
from xml.sax.saxutils import escape as xml_escape
time_imports = time.time() - time_begin

iso_datetime = '%Y-%m-%dT%H:%M:%SZ'

# In order to be able to store the config file in /etc/darcsweb, it has to be
# added to sys.path. It's mainly used by distributions, which place the
# default configuration there. Add it second place, so it goes after '.' but
# before the normal path. This allows per-directory config files (desirable
# for multiple darcsweb installations on the same machin), and avoids name
# clashing if there's a config.py in the standard path.
sys.path.insert(1, '/etc/darcsweb')

# Similarly, when hosting multiple darcsweb instrances on the same
# server, you can just 'SetEnv DARCSWEB_CONFPATH' in the httpd config,
# and this will have a bigger priority than the system-wide
# configuration file.
if 'DARCSWEB_CONFPATH' in os.environ:
	sys.path.insert(1, os.environ['DARCSWEB_CONFPATH'])

# empty configuration class, we will fill it in later depending on the repo
class config:
	pass

# list of run_darcs() invocations, for performance measures
darcs_runs = []

# exception handling
def exc_handle(t, v, tb):
	try:
		cache.cancel()
	except:
		pass
	cgitb.handler((t, v, tb))
sys.excepthook = exc_handle

#
# utility functions
#

def filter_num(s):
	l = [c for c in s if c in string.digits]
	return ''.join(l)


allowed_in_action = string.ascii_letters + string.digits + '_'
def filter_act(s):
	l = [c for c in s if c in allowed_in_action]
	return ''.join(l)


allowed_in_hash = string.ascii_letters + string.digits + '-.'
def filter_hash(s):
	l = [c for c in s if c in allowed_in_hash]
	return ''.join(l)


def filter_file(s):
	if '..' in s or '"' in s:
		raise 'FilterFile FAILED'
	if s == '/':
		return s

	# remove extra "/"s
	r = s[0]
	last = s[0]
	for c in s[1:]:
		if c == last and c == '/':
			continue
		r += c
		last = c
	return r


def printd(*params):
	print ' '.join(params), '<br/>'


# I _hate_ this.
def fixu8(s):
	"""Calls _fixu8(), which does the real work, line by line. Otherwise
	we choose the wrong encoding for big buffers and end up messing
	output."""
	n = []
	for i in s.split('\n'):
		n.append(_fixu8(i))
	return '\n'.join(n)

def _fixu8(s):
	if type(s) == unicode:
		return s.encode('utf8', 'replace')
	for e in config.repoencoding:
		try:
			return s.decode(e).encode('utf8', 'replace')
		except UnicodeDecodeError:
			pass
	raise 'DecodingError', config.repoencoding


def escape(s):
	s = xml_escape(s)
	s = s.replace('"', '&quot;')
	return s

def how_old(epoch):
	if config.cachedir:
		# when we have a cache, the how_old() becomes a problem since
		# the cached entries will have old data; so in this case just
		# return a nice string
		t = time.localtime(epoch)
		s = time.strftime("%d %b %H:%M", t)
		return s
	age = int(time.time()) - int(epoch)
	if age > 60*60*24*365*2:
		s = str(age/60/60/24/365)
		s += " years ago"
	elif age > 60*60*24*(365/12)*2:
		s = str(age/60/60/24/(365/12))
		s += " months ago"
	elif age > 60*60*24*7*2:
		s = str(age/60/60/24/7)
		s += " weeks ago"
	elif age > 60*60*24*2:
		s = str(age/60/60/24)
		s += " days ago"
	elif age > 60*60*2:
		s = str(age/60/60)
		s += " hours ago"
	elif age > 60*2:
		s = str(age/60)
		s += " minutes ago"
	elif age > 2:
		s = str(age)
		s += " seconds ago"
	else:
		s = "right now"
	return s

def shorten_str(s, max = 60):
	if len(s) > max:
		s = s[:max - 4] + ' ...'
	return s

def replace_tabs(s):
	pos = s.find("\t")
	while pos != -1:
		count = 8 - (pos % 8)
		if count:
			spaces = ' ' * count
			s = s.replace('\t', spaces, 1)
		pos = s.find("\t")
	return s

def replace_links(s):
	"""Replace user defined strings with links, as specified in the
	configuration file."""
	import re

	vardict = {
		"myreponame": config.myreponame,
		"reponame": config.reponame,
	}

	for link_pat, link_dst in config.url_links:
		s = re.sub(link_pat, link_dst % vardict, s)

	return s


def highlight(s, l):
	"Highlights appearences of s in l"
	import re
	# build the regexp by leaving "(s)", replacing '(' and ') first
	s = s.replace('\\', '\\\\')
	s = s.replace('(', '\\(')
	s = s.replace(')', '\\)')
	s = '(' + escape(s) + ')'
	try:
		pat = re.compile(s, re.I)
		repl = '<span style="color:#e00000">\\1</span>'
		l = re.sub(pat, repl, l)
	except:
		pass
	return l

def fperms(fname):
	m = os.stat(fname)[stat.ST_MODE]
	m = m & 0777
	s = []
	if os.path.isdir(fname): s.append('d')
	else: s.append('-')

	if m & 0400: s.append('r')
	else: s.append('-')
	if m & 0200: s.append('w')
	else: s.append('-')
	if m & 0100: s.append('x')
	else: s.append('-')

	if m & 0040: s.append('r')
	else: s.append('-')
	if m & 0020: s.append('w')
	else: s.append('-')
	if m & 0010: s.append('x')
	else: s.append('-')

	if m & 0004: s.append('r')
	else: s.append('-')
	if m & 0002: s.append('w')
	else: s.append('-')
	if m & 0001: s.append('x')
	else: s.append('-')

	return ''.join(s)

def fsize(fname):
	s = os.stat(fname)[stat.ST_SIZE]
	if s < 1024:
		return "%s" % s
	elif s < 1048576:
		return "%sK" % (s / 1024)
	elif s < 1073741824:
		return "%sM" % (s / 1048576)

def isbinary(fname):
	import re
	bins = open(config.repodir + '/_darcs/prefs/binaries').readlines()
	bins = [b[:-1] for b in bins if b and b[0] != '#']
	for b in bins:
		if re.compile(b).search(fname):
			return 1
	return 0

def realpath(fname):
	realf = filter_file(config.repodir + '/_darcs/pristine/' + fname)
	if os.path.exists(realf):
		return realf
	realf = filter_file(config.repodir + '/_darcs/current/' + fname)
	if os.path.exists(realf):
		return realf
	realf = filter_file(config.repodir + '/' + fname)
	return realf

def log_times(cache_hit, repo = None, event = None):
	if not config.logtimes:
		return

	time_total = time.time() - time_begin
	processing = time_total - time_imports
	if not event:
		event = action
	if cache_hit:
		event = event + " (hit)"
	s = '%s\n' % event

	if repo:
		s += '\trepo: %s\n' % repo

	s += """\
	total: %.3f
	processing: %.3f
	imports: %.3f\n""" % (time_total, processing, time_imports)

	if darcs_runs:
		s += "\truns:\n"
		for params in darcs_runs:
			s += '\t\t%s\n' % params
	s += '\n'

	lf = open(config.logtimes, 'a')
	lf.write(s)
	lf.close()


def parse_darcs_time(s):
	"Try to convert a darcs' time string into a Python time tuple."
	try:
		return time.strptime(s, "%Y%m%d%H%M%S")
	except ValueError:
		# very old darcs commits use a different format, for example:
		# "Wed May 21 19:39:10 CEST 2003"
		# we can't parse the "CEST" part reliably, so we leave it out
		fmt = "%a %b %d %H:%M:%S %Y"
		parts = s.split()
		ns = ' '.join(parts[0:4]) + ' ' + parts[5]
		return time.strptime(ns, fmt)



#
# generic html functions
#

def print_header():
	print "Content-type: text/html; charset=utf-8"
	print """
<?xml version="1.0" encoding="utf-8"?>
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN"
		"http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
<html xmlns="http://www.w3.org/1999/xhtml" xml:lang="en-US" lang="en-US">
<!-- darcsweb 1.1
     Alberto Bertogli (albertito@blitiri.com.ar).

     Based on gitweb, which is written by Kay Sievers <kay.sievers@vrfy.org>
     and Christian Gierke <ch@gierke.de>
-->
<head>
<meta http-equiv="content-type" content="text/html; charset=utf-8"/>
<meta name="robots" content="index, nofollow"/>
<title>darcs - %(reponame)s</title>
<link rel="stylesheet" type="text/css" href="%(css)s"/>
<link rel="alternate" title="%(reponame)s" href="%(url)s;a=rss"
		type="application/rss+xml"/>
<link rel="alternate" title="%(reponame)s" href="%(url)s;a=atom"
		type='application/atom+xml'/>
<link rel="shortcut icon" href="%(fav)s"/>
<link rel="icon" href="%(fav)s"/>
</head>

<body>
<div class="page_header">
  <div class="search_box">
    <form action="%(myname)s" method="get"><div>
      <input type="hidden" name="r" value="%(reponame)s"/>
      <input type="hidden" name="a" value="search"/>
      <input type="text" name="s" size="20" class="search_text"/>
      <input type="submit" value="search" class="search_button"/>
      <a href="http://darcs.net" title="darcs">
        <img src="%(logo)s" alt="darcs logo" class="logo"/>
      </a>
    </div></form>
  </div>
  <a href="%(myname)s">repos</a> /
  <a href="%(myreponame)s;a=summary">%(reponame)s</a> /
  %(action)s
</div>
	""" % {
		'reponame': config.reponame,
		'css': config.cssfile,
		'url': config.myurl + '/' + config.myreponame,
		'fav': config.darcsfav,
		'logo': config.darcslogo,
		'myname': config.myname,
		'myreponame': config.myreponame,
		'action': action
	}


def print_footer(put_rss = 1):
	print """
<div class="page_footer">
<div class="page_footer_text">%s</div>
	""" % config.footer
	if put_rss:
		print '<a class="rss_logo" href="%s;a=rss">RSS</a>' % \
				(config.myurl + '/' + config.myreponame)
	print "</div>\n</body>\n</html>"


def print_navbar(h = "", f = ""):
	print """
<div class="page_nav">
<a href="%(myreponame)s;a=summary">summary</a>
| <a href="%(myreponame)s;a=shortlog">shortlog</a>
| <a href="%(myreponame)s;a=log">log</a>
| <a href="%(myreponame)s;a=tree">tree</a>
	""" % { "myreponame": config.myreponame }

	if h:
		print """
| <a href="%(myreponame)s;a=commit;h=%(hash)s">commit</a>
| <a href="%(myreponame)s;a=commitdiff;h=%(hash)s">commitdiff</a>
| <a href="%(myreponame)s;a=headdiff;h=%(hash)s">headdiff</a>
		""" % { "myreponame": config.myreponame, 'hash': h }

	realf = realpath(f)
	f = urllib.quote(f)

	if f and h:
		print """
| <a href="%(myreponame)s;a=annotate_shade;f=%(fname)s;h=%(hash)s">annotate</a>
		""" % {
			'myreponame': config.myreponame,
			'hash': h,
			'fname': f
		}
	elif f:
		print """
| <a href="%(myreponame)s;a=annotate_shade;f=%(fname)s">annotate</a>
		""" % { "myreponame": config.myreponame, 'fname': f }

	if f and os.path.isfile(realf):
		print """
| <a href="%(myreponame)s;a=headblob;f=%(fname)s">headblob</a>
		""" % { "myreponame": config.myreponame, 'fname': f }

	if f and os.path.isdir(realf):
		print """
| <a href="%(myreponame)s;a=tree;f=%(fname)s">headtree</a>
		"""  % { "myreponame": config.myreponame, 'fname': f }

	if h and f and (os.path.isfile(realf) or os.path.isdir(realf)):
		print """
| <a href="%(myreponame)s;a=headfilediff;h=%(hash)s;f=%(fname)s">headfilediff</a>
		""" % { "myreponame": config.myreponame, 'hash': h, 'fname': f }

	if f:
		print """
| <a class="link" href="%(myreponame)s;a=filehistory;f=%(fname)s">filehistory</a>
		""" % { "myreponame": config.myreponame, 'fname': f }

	print "<br/>"

	efaction = action
	if '_' in action:
		# action is composed as "format_action", like
		# "darcs_commitdiff"; so we get the "effective action" to
		# decide if we need to present the "alternative formats" menu
		pos = action.find('_')
		fmt = action[:pos]
		efaction = action[pos + 1:]
	if efaction in ("commit", "commitdiff", "filediff", "headdiff",
			"headfilediff"):

		# in order to show the small bar in the commit page too, we
		# accept it here and change efaction to commitdiff, because
		# that's what we're really intrested in
		if efaction == "commit":
			efaction = "commitdiff"

		params = 'h=%s;' % h
		if f:
			params += 'f=%s;' % f

		# normal (unified)
		print """
<a class="link" href="%(myreponame)s;a=%(act)s;%(params)s">unified</a>
		""" % { "myreponame": config.myreponame, "act": efaction,
			"params": params }

		# plain
		print """
| <a class="link" href="%(myreponame)s;a=plain_%(act)s;%(params)s">plain</a>
		""" % { "myreponame": config.myreponame, "act": efaction,
			"params": params }

		# darcs, htmlized
		print """
| <a class="link" href="%(myreponame)s;a=darcs_%(act)s;%(params)s">darcs</a>
		""" % { "myreponame": config.myreponame, "act": efaction,
			"params": params }

		# darcs, raw, if available; and only for commitdiff
		realf = filter_file(config.repodir + '/_darcs/patches/' + h)
		if efaction == "commitdiff" and os.path.isfile(realf):
			print """
| <a class="link" href="%(myreponame)s;a=raw_%(act)s;%(params)s">raw</a>
			""" % { "myreponame": config.myreponame,
				"act": efaction, "params": params }

	elif f and action == "headblob":
		# show the only alternative format: plain
		print """
<a class="link" href="%(myreponame)s;a=plainblob;f=%(fname)s">plain</a>
		""" % { "myreponame": config.myreponame, "fname": f }

	elif f and h and action.startswith("annotate"):
		# same for annotate
		print """
<a href="%(myreponame)s;a=annotate_normal;f=%(fname)s;h=%(hash)s">normal</a>
| <a href="%(myreponame)s;a=annotate_plain;f=%(fname)s;h=%(hash)s">plain</a>
| <a href="%(myreponame)s;a=annotate_shade;f=%(fname)s;h=%(hash)s">shade</a>
| <a href="%(myreponame)s;a=annotate_zebra;f=%(fname)s;h=%(hash)s">zebra</a>
		""" % {
			"myreponame": config.myreponame,
			"fname": f,
			"hash": h
		}

	print '<br/>'
	print '</div>'

def print_plain_header():
	print "Content-type: text/plain; charset=utf-8\n"

def print_binary_header(fname = None):
	import mimetypes
	if fname :
		(mime, enc) = mimetypes.guess_type(fname)
	else :
		mime = None
	if mime :
		print "Content-type: %s" % mime
	else :
		print "Content-type: application/octet-stream"
	if fname:
		print "Content-Disposition:attachment;filename=%s" % fname
	print

def gen_authorlink(author, shortauthor=None):
	if not config.author_links:
		if shortauthor:
			return shortauthor
		else:
			return author
	if not shortauthor:
		shortauthor = author
	return '<a href="' + config.author_links % { 'author': author } + '">%s</a>' % shortauthor

#
# basic caching
#

class Cache:
	def __init__(self, basedir, url):
		import sha
		self.basedir = basedir
		self.url = url
		self.fname = sha.sha(repr(url)).hexdigest()
		self.file = None
		self.mode = None
		self.real_stdout = sys.stdout

	def open(self):
		"Returns 1 on hit, 0 on miss"
		fname = self.basedir + '/' + self.fname

		if not os.access(fname, os.R_OK):
			# the file doesn't exist, direct miss
			pid = str(os.getpid())
			fname = self.basedir + '/.' + self.fname + '-' + pid
			self.file = open(fname, 'w')
			self.mode = 'w'
			os.chmod(fname, stat.S_IRUSR | stat.S_IWUSR)

			# step over stdout so when "print" tries to write
			# output, we get it first
			sys.stdout = self
			return 0

		inv = config.repodir + '/_darcs/patches'
		cache_lastmod = os.stat(fname).st_mtime
		repo_lastmod = os.stat(inv).st_mtime
		dw_lastmod = os.stat(sys.argv[0]).st_mtime

		if repo_lastmod > cache_lastmod or dw_lastmod > cache_lastmod:
			# the entry is too old, remove it and return a miss
			os.unlink(fname)

			pid = str(os.getpid())
			fname = self.basedir + '/.' + self.fname + '-' + pid
			self.file = open(fname, 'w')
			self.mode = 'w'
			sys.stdout = self
			return 0

		# the entry is still valid, hit!
		self.file = open(fname, 'r')
		self.mode = 'r'
		return 1


	def dump(self):
		for l in self.file:
			self.real_stdout.write(l)

	def write(self, s):
		# this gets called from print, because we replaced stdout with
		# ourselves
		self.file.write(s)
		self.real_stdout.write(s)

	def close(self):
		if self.file:
			self.file.close()
		sys.stdout = self.real_stdout
		if self.mode == 'w':
			pid = str(os.getpid())
			fname1 = self.basedir + '/.' + self.fname + '-' + pid
			fname2 = self.basedir + '/' + self.fname
			os.rename(fname1, fname2)
			self.mode = 'c'

	def cancel(self):
		"Like close() but don't save the entry."
		if self.file:
			self.file.close()
		sys.stdout = self.real_stdout
		if self.mode == 'w':
			pid = str(os.getpid())
			fname = self.basedir + '/.' + self.fname + '-' + pid
			os.unlink(fname)
			self.mode = 'c'


#
# darcs repo manipulation
#

def repo_get_owner():
	try:
		fd = open(config.repodir + '/_darcs/prefs/author')
		author = fd.readlines()[0].strip()
	except:
		author = None
	return author

def run_darcs(params):
	"""Runs darcs on the repodir with the given params, return a file
	object with its output."""
	os.chdir(config.repodir)
	try:
		original_8bit_setting = os.environ['DARCS_DONT_ESCAPE_8BIT']
	except KeyError:
		original_8bit_setting = None
	os.environ['DARCS_DONT_ESCAPE_8BIT'] = '1'
	cmd = config.darcspath + "darcs " + params
	inf, outf = os.popen4(cmd, 't')
	darcs_runs.append(params)
	if original_8bit_setting == None:
		del(os.environ['DARCS_DONT_ESCAPE_8BIT'])
	else:
		os.environ['DARCS_DONT_ESCAPE_8BIT'] = original_8bit_setting
	return outf


class Patch:
	"Represents a single patch/record"
	def __init__(self):
		self.hash = ''
		self.author = ''
		self.shortauthor = ''
		self.date = 0
		self.local_date = 0
		self.name = ''
		self.comment = ''
		self.inverted = False;
		self.adds = []
		self.removes = []
		self.modifies = {}
		self.diradds = []
		self.dirremoves = []
		self.replaces = {}
		self.moves = {}

	def tostr(self):
		s = "%s\n\tAuthor: %s\n\tDate: %s\n\tHash: %s\n" % \
			(self.name, self.author, self.date, self.hash)
		return s

	def getdiff(self):
		"""Returns a list of lines from the diff -u corresponding with
		the patch."""
		params = 'diff -u --match "hash %s"' % self.hash
		f = run_darcs(params)
		return f.readlines()

	def matches(self, s):
		"Defines if the patch matches a given string"
		if s.lower() in self.comment.lower():
			return self.comment
		elif s.lower() in self.name.lower():
			return self.name
		elif s.lower() in self.author.lower():
			return self.author
		elif s == self.hash:
			return self.hash

		s = s.lower()
		for l in (self.adds, self.removes, self.modifies,
				self.diradds, self.dirremoves,
				self.replaces.keys(), self.moves.keys(),
				self.moves.keys() ):
			for i in l:
				if s in i.lower():
					return i
		return ''

class XmlInputWrapper:
	def __init__(self, fd):
		self.fd = fd
		self.times = 0
		self._read = self.read

	def read(self, *args, **kwargs):
		self.times += 1
		if self.times == 1:
			return '<?xml version="1.0" encoding="utf-8"?>\n'
		s = self.fd.read(*args, **kwargs)
		if not s:
			return s
		return fixu8(s)

	def close(self, *args, **kwargs):
		return self.fd.close(*args, **kwargs)


# patch parsing, we get them through "darcs changes --xml-output"
class BuildPatchList(xml.sax.handler.ContentHandler):
	def __init__(self):
		self.db = {}
		self.list = []
		self.cur_hash = ''
		self.cur_elem = None
		self.cur_val = ''
		self.cur_file = ''

	def startElement(self, name, attrs):
		# When you ask for changes to a given file, the xml output
		# begins with the patch that creates it is enclosed in a
		# "created_as" tag; then, later, it gets shown again in its
		# usual place. The following two "if"s take care of ignoring
		# everything inside the "created_as" tag, since we don't care.
		if name == 'created_as':
			self.cur_elem = 'created_as'
			return
		if self.cur_elem == 'created_as':
			return

		# now parse the tags normally
		if name == 'patch':
			p = Patch()
			p.hash = fixu8(attrs.get('hash'))

			au = attrs.get('author', None)
			p.author = fixu8(escape(au))
			if au.find('<') != -1:
				au = au[:au.find('<')].strip()
			p.shortauthor = fixu8(escape(au))

			td = parse_darcs_time(attrs.get('date', None))
			p.date = time.mktime(td)
			p.date_str = time.strftime("%a, %d %b %Y %H:%M:%S", td)

			td = time.strptime(attrs.get('local_date', None),
					"%a %b %d %H:%M:%S %Z %Y")
			p.local_date = time.mktime(td)
			p.local_date_str = \
				time.strftime("%a, %d %b %Y %H:%M:%S", td)

			inverted = attrs.get('inverted', None)
			if inverted and inverted == 'True':
				p.inverted = True

			self.db[p.hash] = p
			self.current = p.hash
			self.list.append(p.hash)
		elif name == 'name':
			self.db[self.current].name = ''
			self.cur_elem = 'name'
		elif name == 'comment':
			self.db[self.current].comment = ''
			self.cur_elem = 'comment'
		elif name == 'add_file':
			self.cur_elem = 'add_file'
		elif name == 'remove_file':
			self.cur_elem = 'remove_file'
		elif name == 'add_directory':
			self.cur_elem = 'add_directory'
		elif name == 'remove_directory':
			self.cur_elem = 'remove_dir'
		elif name == 'modify_file':
			self.cur_elem = 'modify_file'
		elif name == 'removed_lines':
			if self.cur_val:
				self.cur_file = fixu8(self.cur_val.strip())
			cf = self.cur_file
			p = self.db[self.current]
			# the current value holds the file name at this point
			if not p.modifies.has_key(cf):
				p.modifies[cf] = { '+': 0, '-': 0 }
			p.modifies[cf]['-'] = int(attrs.get('num', None))
		elif name == 'added_lines':
			if self.cur_val:
				self.cur_file = fixu8(self.cur_val.strip())
			cf = self.cur_file
			p = self.db[self.current]
			if not p.modifies.has_key(cf):
				p.modifies[cf] = { '+': 0, '-': 0 }
			p.modifies[cf]['+'] = int(attrs.get('num', None))
		elif name == 'move':
			src = fixu8(attrs.get('from', None))
			dst = fixu8(attrs.get('to', None))
			p = self.db[self.current]
			p.moves[src] = dst
		elif name == 'replaced_tokens':
			if self.cur_val:
				self.cur_file = fixu8(self.cur_val.strip())
			cf = self.cur_file
			p = self.db[self.current]
			if not p.replaces.has_key(cf):
				p.replaces[cf] = 0
			p.replaces[cf] = int(attrs.get('num', None))
		else:
			self.cur_elem = None

	def characters(self, s):
		if not self.cur_elem:
			return
		self.cur_val += s

	def endElement(self, name):
		# See the comment in startElement()
		if name == 'created_as':
			self.cur_elem = None
			self.cur_val = ''
			return
		if self.cur_elem == 'created_as':
			return
		if name == 'replaced_tokens':
			return

		if name == 'name':
			p = self.db[self.current]
			p.name = fixu8(self.cur_val)
			if p.inverted:
				p.name = 'UNDO: ' + p.name
		elif name == 'comment':
			self.db[self.current].comment = fixu8(self.cur_val)
		elif name == 'add_file':
			scv = fixu8(self.cur_val.strip())
			self.db[self.current].adds.append(scv)
		elif name == 'remove_file':
			scv = fixu8(self.cur_val.strip())
			self.db[self.current].removes.append(scv)
		elif name == 'add_directory':
			scv = fixu8(self.cur_val.strip())
			self.db[self.current].diradds.append(scv)
		elif name == 'remove_directory':
			scv = fixu8(self.cur_val.strip())
			self.db[self.current].dirremoves.append(scv)

		elif name == 'modify_file':
			if not self.cur_file:
				# binary modification appear without a line
				# change summary, so we add it manually here
				f = fixu8(self.cur_val.strip())
				p = self.db[self.current]
				p.modifies[f] = { '+': 0, '-': 0, 'b': 1 }
			self.cur_file = ''

		self.cur_elem = None
		self.cur_val = ''

	def get_list(self):
		plist = []
		for h in self.list:
			plist.append(self.db[h])
		return plist

	def get_db(self):
		return self.db

	def get_list_db(self):
		return (self.list, self.db)

def get_changes_handler(params):
	"Returns a handler for the changes output, run with the given params"
	parser = xml.sax.make_parser()
	handler = BuildPatchList()
	parser.setContentHandler(handler)

	# get the xml output and parse it
	xmlf = run_darcs("changes --xml-output " + params)
	parser.parse(XmlInputWrapper(xmlf))
	xmlf.close()

	return handler

def get_last_patches(last = 15, topi = 0, fname = None):
	"""Gets the last N patches from the repo, returns a patch list. If
	"topi" is specified, then it will return the N patches that preceeded
	the patch number topi in the list. It sounds messy but it's quite
	simple. You can optionally pass a filename and only changes that
	affect it will be returned. FIXME: there's probably a more efficient
	way of doing this."""

	# darcs calculate last first, and then filters the filename,
	# so it's not so simple to combine them; that's why we do so much
	# special casing here
	toget = last + topi

	if fname:
		if fname[0] == '/': fname = fname[1:]
		s = '-s "%s"' % fname
	else:
		s = "-s --last=%d" % toget

	handler = get_changes_handler(s)

	# return the list of all the patch objects
	return handler.get_list()[topi:toget]

def get_patch(hash):
	handler = get_changes_handler('-s --match "hash %s"' % hash)
	patch = handler.db[handler.list[0]]
	return patch

def get_diff(hash):
	return run_darcs('diff -u --match "hash %s"' % hash)

def get_file_diff(hash, fname):
	return run_darcs('diff -u --match "hash %s" "%s"' % (hash, fname))

def get_file_headdiff(hash, fname):
	return run_darcs('diff -u --from-match "hash %s" "%s"' % (hash, fname))

def get_patch_headdiff(hash):
	return run_darcs('diff -u --from-match "hash %s"' % hash)

def get_raw_diff(hash):
	import gzip
	realf = filter_file(config.repodir + '/_darcs/patches/' + hash)
	if not os.path.isfile(realf):
		return None
	file = open(realf, 'rb')
	if file.read(2) == '\x1f\x8b':
		# file begins with gzip magic
		file.close()
		dsrc = gzip.open(realf)
	else:
		file.seek(0)
		dsrc = file
	return dsrc

def get_darcs_diff(hash, fname = None):
	cmd = 'changes -v --matches "hash %s"' % hash
	if fname:
		cmd += ' "%s"' % fname
	return run_darcs(cmd)

def get_darcs_headdiff(hash, fname = None):
	cmd = 'changes -v --from-match "hash %s"' % hash
	if fname:
		cmd += ' "%s"' % fname
	return run_darcs(cmd)


class Annotate:
	def __init__(self):
		self.fname = ""
		self.creator_hash = ""
		self.created_as = ""
		self.lastchange_hash = ""
		self.lastchange_author = ""
		self.lastchange_name = ""
		self.lastchange_date = None
		self.firstdate = None
		self.lastdate = None
		self.lines = []
		self.patches = {}

	class Line:
		def __init__(self):
			self.text = ""
			self.phash = None
			self.pauthor = None
			self.pdate = None

def parse_annotate(src):
	import xml.dom.minidom

	annotate = Annotate()

	# FIXME: convert the source to UTF8; it _has_ to be a way to let
	# minidom know the source encoding
	s = ""
	for i in src:
		s += fixu8(i)

	dom = xml.dom.minidom.parseString(s)

	file = dom.getElementsByTagName("file")[0]
	annotate.fname = fixu8(file.getAttribute("name"))

	createinfo = dom.getElementsByTagName("created_as")[0]
	annotate.created_as = fixu8(createinfo.getAttribute("original_name"))

	creator = createinfo.getElementsByTagName("patch")[0]
	annotate.creator_hash = fixu8(creator.getAttribute("hash"))

	mod = dom.getElementsByTagName("modified")[0]
	lastpatch = mod.getElementsByTagName("patch")[0]
	annotate.lastchange_hash = fixu8(lastpatch.getAttribute("hash"))
	annotate.lastchange_author = fixu8(lastpatch.getAttribute("author"))

	lastname = lastpatch.getElementsByTagName("name")[0]
	lastname = lastname.childNodes[0].wholeText
	annotate.lastchange_name = fixu8(lastname)

	lastdate = parse_darcs_time(lastpatch.getAttribute("date"))
	annotate.lastchange_date = lastdate

	annotate.patches[annotate.lastchange_hash] = annotate.lastchange_date

	# these will be overriden by the real dates later
	annotate.firstdate = lastdate
	annotate.lastdate = 0

	file = dom.getElementsByTagName("file")[0]

	for l in file.childNodes:
		# we're only intrested in normal and added lines
		if l.nodeName not in ["normal_line", "added_line"]:
			continue
		line = Annotate.Line()

		if l.nodeName == "normal_line":
			patch = l.getElementsByTagName("patch")[0]
			phash = patch.getAttribute("hash")
			pauthor = patch.getAttribute("author")
			pdate = patch.getAttribute("date")
			pdate = parse_darcs_time(pdate)
		else:
			# added lines inherit the creation from the annotate
			# patch
			phash = annotate.lastchange_hash
			pauthor = annotate.lastchange_author
			pdate = annotate.lastchange_date

		text = ""
		for node in l.childNodes:
			if node.nodeType == node.TEXT_NODE:
				text += node.wholeText

		# strip all "\n"s at the beginning; because the way darcs
		# formats the xml output it makes the DOM parser to add "\n"s
		# in front of it
		text = text.lstrip("\n")

		line.text = fixu8(text)
		line.phash = fixu8(phash)
		line.pauthor = fixu8(pauthor)
		line.pdate = pdate
		annotate.lines.append(line)
		annotate.patches[line.phash] = line.pdate

		if pdate > annotate.lastdate:
			annotate.lastdate = pdate
		if pdate < annotate.firstdate:
			annotate.firstdate = pdate

	return annotate

def get_annotate(fname, hash = None):
	if config.disable_annotate:
		return None

	cmd = 'annotate --xml-output'
	if hash:
		cmd += ' --match="hash %s"' % hash

	if fname.startswith('/'):
		# darcs 2 doesn't like files starting with /, and darcs 1
		# doesn't really care
		fname = fname[1:]
	cmd += ' "%s"' % fname

	return parse_annotate(run_darcs(cmd))



#
# specific html functions
#

def print_diff(dsrc):
	for l in dsrc:
		l = fixu8(l)

		# remove the trailing newline
		if len(l) > 1:
			l = l[:-1]

		if l.startswith('diff'):
			# file lines, they have their own class
			print '<div class="diff_info">%s</div>' % escape(l)
			continue

		color = ""
		if l[0] == '+':
			color = 'style="color:#008800;"'
		elif l[0] == '-':
			color = 'style="color:#cc0000;"'
		elif l[0] == '@':
			color = 'style="color:#990099; '
			color += 'border: solid #ffe0ff; '
			color += 'border-width: 1px 0px 0px 0px; '
			color += 'margin-top: 2px;"'
		elif l.startswith('Files'):
			# binary differences
			color = 'style="color:#666;"'
		print '<div class="pre" %s>' % color + escape(l) + '</div>'


def print_darcs_diff(dsrc):
	for l in dsrc:
		l = fixu8(l)

		if not l.startswith("    "):
			# comments and normal stuff
			print '<div class="pre">' + escape(l) + "</div>"
			continue

		l = l.strip()
		if not l:
			continue

		if l[0] == '+':
			cl = 'class="pre" style="color:#008800;"'
		elif l[0] == '-':
			cl = 'class="pre" style="color:#cc0000;"'
		else:
			cl = 'class="diff_info"'
		print '<div %s>' % cl + escape(l) + '</div>'


def print_shortlog(last = 50, topi = 0, fname = None):
	ps = get_last_patches(last, topi, fname)

	if fname:
		title = '<a class="title" href="%s;a=filehistory;f=%s">' % \
				(config.myreponame, fname)
		title += 'History for path %s' % escape(fname)
		title += '</a>'
	else:
		title = '<a class="title" href="%s;a=shortlog">shortlog</a>' \
				% config.myreponame

	print '<div>%s</div>' % title
	print '<table cellspacing="0">'

	if topi != 0:
		# put a link to the previous page
		ntopi = topi - last
		if ntopi < 0:
			ntopi = 0
		print '<tr><td>'
		if fname:
			print '<a href="%s;a=filehistory;topi=%d;f=%s">...</a>' \
				% (config.myreponame, ntopi, fname)
		else:
			print '<a href="%s;a=shortlog;topi=%d">...</a>' \
				% (config.myreponame, ntopi)
		print '</td></tr>'

	alt = True
	for p in ps:
		if p.name.startswith("TAG "):
			print '<tr class="tag">'
		elif alt:
			print '<tr class="dark">'
		else:
			print '<tr class="light">'
		alt = not alt

		print """
  <td><i>%(age)s</i></td>
  <td>%(author)s</td>
  <td>
    <a class="list" title="%(fullname)s" href="%(myrname)s;a=commit;h=%(hash)s">
      <b>%(name)s</b>
    </a>
  </td>
  <td class="link">
    <a href="%(myrname)s;a=commit;h=%(hash)s">commit</a> |
    <a href="%(myrname)s;a=commitdiff;h=%(hash)s">commitdiff</a>
  </td>
		""" % {
			'age': how_old(p.local_date),
			'author': gen_authorlink(p.author, shorten_str(p.shortauthor, 26)),
			'myrname': config.myreponame,
			'hash': p.hash,
			'name': escape(shorten_str(p.name)),
			'fullname': escape(p.name),
		}
		print "</tr>"

	if len(ps) >= last:
		# only show if we've not shown them all already
		print '<tr><td>'
		if fname:
			print '<a href="%s;a=filehistory;topi=%d;f=%s">...</a>' \
				% (config.myreponame, topi + last, fname)
		else:
			print '<a href="%s;a=shortlog;topi=%d">...</a>' \
				% (config.myreponame, topi + last)
		print '</td></tr>'
	print "</table>"


def print_log(last = 50, topi = 0):
	ps = get_last_patches(last, topi)

	if topi != 0:
		# put a link to the previous page
		ntopi = topi - last
		if ntopi < 0:
			ntopi = 0
		print '<p/><a href="%s;a=log;topi=%d">&lt;- Prev</a><p/>' % \
				(config.myreponame, ntopi)

	for p in ps:
		if p.comment:
			comment = replace_links(escape(p.comment))
			fmt_comment = comment.replace('\n', '<br/>') + '\n'
			fmt_comment += '<br/><br/>'
		else:
			fmt_comment = ''
		print """
<div><a class="title" href="%(myreponame)s;a=commit;h=%(hash)s">
    <span class="age">%(age)s</span>%(desc)s
</a></div>
<div class="title_text">
  <div class="log_link">
    <a href="%(myreponame)s;a=commit;h=%(hash)s">commit</a> |
    <a href="%(myreponame)s;a=commitdiff;h=%(hash)s">commitdiff</a><br/>
  </div>
  <i>%(author)s [%(date)s]</i><br/>
</div>
<div class="log_body">
  %(desc)s<br/>
  <br/>
  %(comment)s
</div>

		""" % {
			'myreponame': config.myreponame,
			'age': how_old(p.local_date),
			'date': p.local_date_str,
			'author': gen_authorlink(p.author, p.shortauthor),
			'hash': p.hash,
			'desc': escape(p.name),
			'comment': fmt_comment
		}

	if len(ps) >= last:
		# only show if we've not shown them all already
		print '<p><a href="%s;a=log;topi=%d">Next -&gt;</a></p>' % \
				(config.myreponame, topi + last)


def print_blob(fname):
	print '<div class="page_path"><b>%s</b></div>' % escape(fname)
	if isbinary(fname):
		print """
<div class="page_body">
<i>This is a binary file and its contents will not be displayed.</i>
</div>
		"""
		return

	try:
		import pygments
	except ImportError:
		pygments = False

	if not pygments:
		print_blob_simple(fname)
		return
	else:
		try:
			print_blob_highlighted(fname)
		except ValueError:
			# pygments couldn't guess a lexer to highlight the code, try
			# another method with sampling the file contents.
			try:
				print_blob_highlighted(fname, sample_code=True)
			except ValueError:
				# pygments really could not find any lexer for this file.
				print_blob_simple(fname)

def print_blob_simple(fname):
	print '<div class="page_body">'

	f = open(realpath(fname), 'r')
	count = 1
	for l in f:
		l = fixu8(escape(l))
		if l and l[-1] == '\n':
			l = l[:-1]
		l = replace_tabs(l)

		print """\
<div class="pre">\
<a id="l%(c)d" href="#l%(c)d" class="linenr">%(c)4d</a> %(l)s\
</div>\
		""" % {
			'c': count,
			'l': l
		}
		count += 1
	print '</div>'

def print_blob_highlighted(fname, sample_code=False):
	import pygments
	import pygments.lexers
	import pygments.formatters

	code = open(realpath(fname), 'r').read()
	if sample_code:
		lexer = pygments.lexers.guess_lexer(code[:200],
				encoding=config.repoencoding[0])
	else:
		lexer = pygments.lexers.guess_lexer_for_filename(fname, code[:200],
				encoding=config.repoencoding[0])

	pygments_version = map(int, pygments.__version__.split('.'))
	if pygments_version >= [0, 7]:
		linenos_method = 'inline'
	else:
		linenos_method = True
	formatter = pygments.formatters.HtmlFormatter(linenos=linenos_method,
				cssclass='page_body')

	print pygments.highlight(code, lexer, formatter)

def print_annotate(ann, style):
	print '<div class="page_body">'
	if isbinary(ann.fname):
		print """
<i>This is a binary file and its contents will not be displayed.</i>
</div>
		"""
		return

	if style == 'shade':
		# here's the idea: we will assign to each patch a shade of
		# color from its date (newer gets darker)
		max = 0xff
		min = max - 80

		# to do that, we need to get a list of the patch hashes
		# ordered by their dates
		l = [ (date, hash) for (hash, date) in ann.patches.items() ]
		l.sort()
		l = [ hash for (date, hash) in l ]

		# now we have to map each element to a number in the range
		# min-max, with max being close to l[0] and min l[len(l) - 1]
		lenn = max - min
		lenl = len(l)
		shadetable = {}
		for i in range(0, lenl):
			hash = l[i]
			n = float(i * lenn) / lenl
			n = max - int(round(n))
			shadetable[hash] = n
	elif style == "zebra":
		lineclass = 'dark'

	count = 1
	prevhash = None
	for l in ann.lines:
		text = escape(l.text)
		text = text.rstrip()
		text = replace_tabs(text)
		plongdate = time.strftime("%Y-%m-%d %H:%M:%S", l.pdate)
		title = "%s by %s" % (plongdate, escape(l.pauthor) )

		link = "%(myrname)s;a=commit;h=%(hash)s" % {
			'myrname': config.myreponame,
			'hash': l.phash
		}

		if style == "shade":
			linestyle = 'style="background-color:#ffff%.2x"' % \
					shadetable[l.phash]
			lineclass = ''
		elif style == "zebra":
			linestyle = ''
			if l.phash != prevhash:
				if lineclass == 'dark':
					lineclass = 'light'
				else:
					lineclass = 'dark'
		else:
			linestyle = ''
			lineclass = ''

		if l.phash != prevhash:
			pdate = time.strftime("%Y-%m-%d", l.pdate)

			left = l.pauthor.find('<')
			right = l.pauthor.find('@')
			if left != -1 and right != -1:
				shortau = l.pauthor[left + 1:right]
			elif l.pauthor.find(" ") != -1:
				shortau = l.pauthor[:l.pauthor.find(" ")]
			elif right != -1:
				shortau = l.pauthor[:right]
			else:
				shortau = l.pauthor

			desc = "%12.12s" % shortau
			date = "%-10.10s" % pdate
			prevhash = l.phash
			line = 1
		else:
			if line == 1 and style in ["shade", "zebra"]:
				t = "%s  " % time.strftime("%H:%M:%S", l.pdate)
				desc = "%12.12s" % "'"
				date = "%-10.10s" % t
			else:
				desc = "%12.12s" % "'"
				date = "%-10.10s" % ""
			line += 1

		print """\
<div class="pre %(class)s" %(style)s>\
<a href="%(link)s" title="%(title)s" class="annotate_desc">%(date)s %(desc)s</a> \
<a href="%(link)s" title="%(title)s" class="linenr">%(c)4d</a> \
<a href="%(link)s" title="%(title)s" class="line">%(text)s</a>\
</div>\
		""" % {
			'class': lineclass,
			'style': linestyle,
			'date': date,
			'desc': escape(desc),
			'c': count,
			'text': text,
			'title': title,
			'link': link
		}

		count += 1

	print '</div>'


#
# available actions
#

def do_summary():
	print_header()
	print_navbar()
	owner = repo_get_owner()

	# we should optimize this, it's a pity to go in such a mess for just
	# one hash
	ps = get_last_patches(1)

	print '<div class="title">&nbsp;</div>'
	print '<table cellspacing="0">'
	print '  <tr><td>description</td><td>%s</td></tr>' % \
			escape(config.repodesc)
	if owner:
		print '  <tr><td>owner</td><td>%s</td></tr>' % escape(owner)
	if len(ps) > 0:
		print '  <tr><td>last change</td><td>%s</td></tr>' % \
			ps[0].local_date_str
	print '  <tr><td>url</td><td><a href="%(url)s">%(url)s</a></td></tr>' %\
			{ 'url': config.repourl }
	if config.repoprojurl:
		print '  <tr><td>project url</td>'
		print '  <td><a href="%(url)s">%(url)s</a></td></tr>' % \
			{ 'url': config.repoprojurl }
	print '</table>'

	print_shortlog(15)
	print_footer()


def do_commitdiff(phash):
	print_header()
	print_navbar(h = phash)
	p = get_patch(phash)
	print """
<div>
  <a class="title" href="%(myreponame)s;a=commit;h=%(hash)s">%(name)s</a>
</div>
	""" % {
		'myreponame': config.myreponame,
		'hash': p.hash,
		'name': escape(p.name),
	}

	dsrc = p.getdiff()
	print_diff(dsrc)
	print_footer()

def do_plain_commitdiff(phash):
	print_plain_header()
	dsrc = get_diff(phash)
	for l in dsrc:
		sys.stdout.write(fixu8(l))

def do_darcs_commitdiff(phash):
	print_header()
	print_navbar(h = phash)
	p = get_patch(phash)
	print """
<div>
  <a class="title" href="%(myreponame)s;a=commit;h=%(hash)s">%(name)s</a>
</div>
	""" % {
		'myreponame': config.myreponame,
		'hash': p.hash,
		'name': escape(p.name),
	}

	dsrc = get_darcs_diff(phash)
	print_darcs_diff(dsrc)
	print_footer()

def do_raw_commitdiff(phash):
	print_plain_header()
	dsrc = get_raw_diff(phash)
	if not dsrc:
		print "Error opening file!"
		return
	for l in dsrc:
		sys.stdout.write(l)


def do_headdiff(phash):
	print_header()
	print_navbar(h = phash)
	p = get_patch(phash)
	print """
<div>
  <a class="title" href="%(myreponame)s;a=commit;h=%(hash)s">
    %(name)s --&gt; to head</a>
</div>
	""" % {
		'myreponame': config.myreponame,
		'hash': p.hash,
		'name': escape(p.name),
	}

	dsrc = get_patch_headdiff(phash)
	print_diff(dsrc)
	print_footer()

def do_plain_headdiff(phash):
	print_plain_header()
	dsrc = get_patch_headdiff(phash)
	for l in dsrc:
		sys.stdout.write(fixu8(l))

def do_darcs_headdiff(phash):
	print_header()
	print_navbar(h = phash)
	p = get_patch(phash)
	print """
<div>
  <a class="title" href="%(myreponame)s;a=commit;h=%(hash)s">
    %(name)s --&gt; to head</a>
</div>
	""" % {
		'myreponame': config.myreponame,
		'hash': p.hash,
		'name': escape(p.name),
	}

	dsrc = get_darcs_headdiff(phash)
	print_darcs_diff(dsrc)
	print_footer()

def do_raw_headdiff(phash):
	print_plain_header()
	dsrc = get_darcs_headdiff(phash)
	for l in dsrc:
		sys.stdout.write(l)


def do_filediff(phash, fname):
	print_header()
	print_navbar(h = phash, f = fname)
	p = get_patch(phash)
	dsrc = get_file_diff(phash, fname)
	print """
<div>
  <a class="title" href="%(myreponame)s;a=commit;h=%(hash)s">%(name)s</a>
</div>
<div class="page_path"><b>%(fname)s</b></div>
	""" % {
		'myreponame': config.myreponame,
		'hash': p.hash,
		'name': escape(p.name),
		'fname': escape(fname),
	}

	print_diff(dsrc)
	print_footer()

def do_plain_filediff(phash, fname):
	print_plain_header()
	dsrc = get_file_diff(phash, fname)
	for l in dsrc:
		sys.stdout.write(fixu8(l))

def do_darcs_filediff(phash, fname):
	print_header()
	print_navbar(h = phash, f = fname)
	p = get_patch(phash)
	print """
<div>
  <a class="title" href="%(myreponame)s;a=commit;h=%(hash)s">%(name)s</a>
</div>
<div class="page_path"><b>%(fname)s</b></div>
	""" % {
		'myreponame': config.myreponame,
		'hash': p.hash,
		'name': escape(p.name),
		'fname': escape(fname),
	}

	dsrc = get_darcs_diff(phash, fname)
	print_darcs_diff(dsrc)
	print_footer()


def do_file_headdiff(phash, fname):
	print_header()
	print_navbar(h = phash, f = fname)
	p = get_patch(phash)
	dsrc = get_file_headdiff(phash, fname)
	print """
<div>
  <a class="title" href="%(myreponame)s;a=commit;h=%(hash)s">
    %(name)s --&gt; to head</a>
</div>
<div class="page_path"><b>%(fname)s</b></div>
	""" % {
		'myreponame': config.myreponame,
		'hash': p.hash,
		'name': escape(p.name),
		'fname': escape(fname),
	}

	print_diff(dsrc)
	print_footer()

def do_plain_fileheaddiff(phash, fname):
	print_plain_header()
	dsrc = get_file_headdiff(phash, fname)
	for l in dsrc:
		sys.stdout.write(fixu8(l))

def do_darcs_fileheaddiff(phash, fname):
	print_header()
	print_navbar(h = phash, f = fname)
	p = get_patch(phash)
	print """
<div>
  <a class="title" href="%(myreponame)s;a=commit;h=%(hash)s">
    %(name)s --&gt; to head</a>
</div>
<div class="page_path"><b>%(fname)s</b></div>
	""" % {
		'myreponame': config.myreponame,
		'hash': p.hash,
		'name': escape(p.name),
		'fname': escape(fname),
	}

	dsrc = get_darcs_headdiff(phash, fname)
	print_darcs_diff(dsrc)
	print_footer()

	print_plain_header()
	print "Not yet implemented"


def do_commit(phash):
	print_header()
	print_navbar(h = phash)
	p = get_patch(phash)

	print """
<div>
  <a class="title" href="%(myreponame)s;a=commitdiff;h=%(hash)s">%(name)s</a>
</div>

<div class="title_text">
<table cellspacing="0">
<tr><td>author</td><td>%(author)s</td></tr>
<tr><td>local date</td><td>%(local_date)s</td></tr>
<tr><td>date</td><td>%(date)s</td></tr>
<tr><td>hash</td><td style="font-family: monospace">%(hash)s</td></tr>
</table>
</div>
	""" % {
		'myreponame': config.myreponame,
		'author': gen_authorlink(p.author),
		'local_date': p.local_date_str,
		'date': p.date_str,
		'hash': p.hash,
		'name': escape(p.name),
	}
	if p.comment:
		comment = replace_links(escape(p.comment))
		c = comment.replace('\n', '<br/>\n')
		print '<div class="page_body">'
		print replace_links(escape(p.name)), '<br/><br/>'
		print c
		print '</div>'

	changed = p.adds + p.removes + p.modifies.keys() + p.moves.keys() + \
			p.diradds + p.dirremoves + p.replaces.keys()

	if changed or p.moves:
		n = len(changed)
		print '<div class="list_head">%d file(s) changed:</div>' % n

	print '<table cellspacing="0">'
	changed.sort()
	alt = True
	for f in changed:
		if alt:
			print '<tr class="dark">'
		else:
			print '<tr class="light">'
		alt = not alt

		show_diff = 1
		if p.moves.has_key(f):
			# don't show diffs for moves, they're broken as of
			# darcs 1.0.3
			show_diff = 0

		if show_diff:
			print """
<td>
  <a class="list" href="%(myreponame)s;a=filediff;h=%(hash)s;f=%(file)s">
    %(fname)s</a>
</td>
			""" % {
				'myreponame': config.myreponame,
				'hash': p.hash,
				'file': urllib.quote(f),
				'fname': escape(f),
			}
		else:
			print "<td>%s</td>" % f

		show_diff = 1
		if f in p.adds:
			print '<td><span style="color:#008000">',
			print '[added]',
			print '</span></td>'
		elif f in p.diradds:
			print '<td><span style="color:#008000">',
			print '[added dir]',
			print '</span></td>'
		elif f in p.removes:
			print '<td><span style="color:#800000">',
			print '[removed]',
			print '</span></td>'
		elif f in p.dirremoves:
			print '<td><span style="color:#800000">',
			print '[removed dir]',
			print '</span></td>'
		elif p.replaces.has_key(f):
			print '<td><span style="color:#800000">',
			print '[replaced %d tokens]' % p.replaces[f],
			print '</span></td>'
		elif p.moves.has_key(f):
			print '<td><span style="color:#000080">',
			print '[moved to "%s"]' % p.moves[f]
			print '</span></td>'
			show_diff = 0
		else:
			print '<td><span style="color:#000080">',
			if p.modifies[f].has_key('b'):
				# binary modification
				print '(binary)'
			else:
				print '+%(+)d  -%(-)d' % p.modifies[f],
			print '</span></td>'

		if show_diff:
			print """
<td class="link">
  <a href="%(myreponame)s;a=filediff;h=%(hash)s;f=%(file)s">diff</a> |
  <a href="%(myreponame)s;a=filehistory;f=%(file)s">history</a> |
  <a href="%(myreponame)s;a=annotate_shade;h=%(hash)s;f=%(file)s">annotate</a>
</td>
			""" % {
				'myreponame': config.myreponame,
				'hash': p.hash,
				'file': urllib.quote(f)
			}
		print '</tr>'
	print '</table>'
	print_footer()


def do_tree(dname):
	print_header()
	print_navbar()

	# the head
	print """
<div><a class="title" href="%s;a=tree">Current tree</a></div>
<div class="page_path"><b>
	""" % config.myreponame

	# and the linked, with links
	parts = dname.split('/')
	print '/ '
	sofar = '/'
	for p in parts:
		if not p: continue
		sofar += '/' + p
		print '<a href="%s;a=tree;f=%s">%s</a> /' % \
				(config.myreponame, urllib.quote(sofar), p)

	print """
  </b></div>
<div class="page_body">
<table cellspacing="0">
	"""

	path = realpath(dname) + '/'

	alt = True
	files = os.listdir(path)
	files.sort()

	# list directories first
	dlist = []
	flist = []
	for f in files:
		if f == "_darcs":
			continue
		realfile = path + f
		if os.path.isdir(realfile):
			dlist.append(f)
		else:
			flist.append(f)
	files = dlist + flist

	for f in files:
		if alt:
			print '<tr class="dark">'
		else:
			print '<tr class="light">'
		alt = not alt
		realfile = path + f
		fullf = filter_file(dname + '/' + f)
		print '<td style="font-family:monospace">', fperms(realfile),
		print '</td>'
		print '<td style="font-family:monospace">', fsize(realfile),
		print '</td>'

		if f in dlist:
			print """
  <td>
    <a class="link" href="%(myrname)s;a=tree;f=%(fullf)s">%(f)s/</a>
  </td>
  <td class="link">
    <a href="%(myrname)s;a=filehistory;f=%(fullf)s">history</a> |
    <a href="%(myrname)s;a=tree;f=%(fullf)s">tree</a>
  </td>
			""" % {
				'myrname': config.myreponame,
				'f': escape(f),
				'fullf': urllib.quote(fullf),
			}
		else:
			print """
  <td><a class="list" href="%(myrname)s;a=headblob;f=%(fullf)s">%(f)s</a></td>
  <td class="link">
    <a href="%(myrname)s;a=filehistory;f=%(fullf)s">history</a> |
    <a href="%(myrname)s;a=headblob;f=%(fullf)s">headblob</a> |
    <a href="%(myrname)s;a=annotate_shade;f=%(fullf)s">annotate</a>
  </td>
			""" % {
				'myrname': config.myreponame,
				'f': escape(f),
				'fullf': urllib.quote(fullf),
			}
		print '</tr>'
	print '</table></div>'
	print_footer()


def do_headblob(fname):
	print_header()
	print_navbar(f = fname)
	filepath = os.path.dirname(fname)

	if filepath == '/':
		print '<div><a class="title" href="%s;a=tree">/</a></div>' % \
			(config.myreponame)
	else:
		print '<div class="title"><b>'

		# and the linked, with links
		parts = filepath.split('/')
		print '/ '
		sofar = '/'
		for p in parts:
			if not p: continue
			sofar += '/' + p
			print '<a href="%s;a=tree;f=%s">%s</a> /' % \
					(config.myreponame, sofar, p)

		print '</b></div>'

	print_blob(fname)
	print_footer()


def do_plainblob(fname):
	f = open(realpath(fname), 'r')

	if isbinary(fname):
		print_binary_header(os.path.basename(fname))
		for l in f:
			sys.stdout.write(l)
	else:
		print_plain_header()
		for l in f:
			sys.stdout.write(fixu8(l))


def do_annotate(fname, phash, style):
	print_header()
	ann = get_annotate(fname, phash)
	if not ann:
		print """
<i>The annotate feature has been disabled</i>
</div>
		"""
		print_footer()
		return
	print_navbar(f = fname, h = ann.lastchange_hash)

	print """
<div>
  <a class="title" href="%(myreponame)s;a=commit;h=%(hash)s">%(name)s</a>
</div>
<div class="page_path"><b>
  Annotate for file %(fname)s
</b></div>
	""" % {
		'myreponame': config.myreponame,
		'hash': ann.lastchange_hash,
		'name': escape(ann.lastchange_name),
		'fname': escape(fname),
	}

	print_annotate(ann, style)
	print_footer()

def do_annotate_plain(fname, phash):
	print_plain_header()
	ann = get_annotate(fname, phash)
	for l in ann.lines:
		sys.stdout.write(l.text)


def do_shortlog(topi):
	print_header()
	print_navbar()
	print_shortlog(topi = topi)
	print_footer()

def do_filehistory(topi, f):
	print_header()
	print_navbar(f = fname)
	print_shortlog(topi = topi, fname = fname)
	print_footer()

def do_log(topi):
	print_header()
	print_navbar()
	print_log(topi = topi)
	print_footer()

def do_atom():
	print "Content-type: application/atom+xml; charset=utf-8\n"
	print '<?xml version="1.0" encoding="utf-8"?>'
	inv = config.repodir + '/_darcs/patches'
	repo_lastmod = os.stat(inv).st_mtime
	str_lastmod = time.strftime(iso_datetime,
			time.localtime(repo_lastmod))

	print """
<feed xmlns="http://www.w3.org/2005/Atom">
  <title>%(reponame)s darcs repository</title>
  <link rel="alternate" type="text/html" href="%(url)s"/>
  <link rel="self" type="application/atom+xml" href="%(url)s;a=atom"/>
  <id>%(url)s</id> <!-- TODO: find a better <id>, see RFC 4151 -->
  <author><name>darcs repository (several authors)</name></author>
  <generator>darcsweb.cgi</generator>
  <updated>%(lastmod)s</updated> 
  <subtitle>%(desc)s</subtitle>
  	""" % {
		'reponame': config.reponame,
		'url': config.myurl + '/' + config.myreponame,
		'desc': escape(config.repodesc),
		'lastmod': str_lastmod,
	}

	ps = get_last_patches(20)
	for p in ps:
		title = time.strftime('%d %b %H:%M', time.localtime(p.date))
		title += ' - ' + p.name
		pdate = time.strftime(iso_datetime,
				time.localtime(p.date))
		link = '%s/%s;a=commit;h=%s' % (config.myurl,
				config.myreponame, p.hash)

		import email.Utils
		addr, author = email.Utils.parseaddr(p.author)
		if not addr:
			addr = "unknown_email@example.com"
		if not author:
			author = addr

		print """
  <entry>
    <title>%(title)s</title>
    <author>
      <name>%(author)s</name>
      <email>%(email)s</email>
    </author>
    <updated>%(pdate)s</updated>
    <id>%(link)s</id>
    <link rel="alternate" href="%(link)s"/>
    <summary>%(desc)s</summary>
    <content type="xhtml"><div xmlns="http://www.w3.org/1999/xhtml"><p>
	   	""" % {
			'title': escape(title),
			'author': author,
			'email': addr,
			'url': config.myurl + '/' + config.myreponame,
			'pdate': pdate,
			'myrname': config.myreponame,
			'hash': p.hash,
			'pname': escape(p.name),
			'link': link,
			'desc': escape(p.name),
		}

                # TODO: allow to get plain text, not HTML?
		print escape(p.name) + '<br/>'
		if p.comment:
			print '<br/>'
			print escape(p.comment).replace('\n', '<br/>\n')
			print '<br/>'
		print '<br/>'
		changed = p.adds + p.removes + p.modifies.keys() + \
				p.moves.keys() + p.diradds + p.dirremoves + \
				p.replaces.keys()
		for i in changed: # TODO: link to the file 
			print '<code>%s</code><br/>' % i
		print '</p></div>'
		print '</content></entry>'
	print '</feed>'

def do_rss():
	print "Content-type: text/xml; charset=utf-8\n"
	print '<?xml version="1.0" encoding="utf-8"?>'
	print """
<rss version="2.0" xmlns:content="http://purl.org/rss/1.0/modules/content/">
<channel>
 <title>%(reponame)s</title>
  <link>%(url)s</link>
  <description>%(desc)s</description>
  <language>en</language>
  	""" % {
		'reponame': config.reponame,
		'url': config.myurl + '/' + config.myreponame,
		'desc': escape(config.repodesc),
	}

	ps = get_last_patches(20)
	for p in ps:
		title = time.strftime('%d %b %H:%M', time.localtime(p.date))
		title += ' - ' + p.name
		pdate = time.strftime("%a, %d %b %Y %H:%M:%S +0000",
				time.localtime(p.date))
		link = '%s/%s;a=commit;h=%s' % (config.myurl,
				config.myreponame, p.hash)

		# the author field is tricky because the standard requires it
		# has an email address; so we need to check that and lie
		# otherwise; there's more info at
		# http://feedvalidator.org/docs/error/InvalidContact.html
		if "@" in p.author:
			author = p.author
		else:
			author = "%s &lt;unknown@email&gt;" % p.author

		print """
  <item>
    <title>%(title)s</title>
    <author>%(author)s</author>
    <pubDate>%(pdate)s</pubDate>
    <link>%(link)s</link>
    <description>%(desc)s</description>
	   	""" % {
			'title': escape(title),
			'author': author,
			'pdate': pdate,
			'link': link,
			'desc': escape(p.name),
		}
		print '    <content:encoded><![CDATA['
		print escape(p.name) + '<br/>'
		if p.comment:
			print '<br/>'
			print escape(p.comment).replace('\n', '<br/>\n')
			print '<br/>'
		print '<br/>'
		changed = p.adds + p.removes + p.modifies.keys() + \
				p.moves.keys() + p.diradds + p.dirremoves + \
				p.replaces.keys()
		for i in changed:
			print '%s<br/>' % i
		print ']]>'
		print '</content:encoded></item>'

	print '</channel></rss>'


def do_search(s):
	print_header()
	print_navbar()
	ps = get_last_patches(config.searchlimit)

	print '<div class="title">Search last %d commits for "%s"</div>' \
			% (config.searchlimit, escape(s))
	print '<table cellspacing="0">'

	alt = True
	for p in ps:
		match = p.matches(s)
		if not match:
			continue

		if alt:
			print '<tr class="dark">'
		else:
			print '<tr class="light">'
		alt = not alt

		print """
  <td><i>%(age)s</i></td>
  <td>%(author)s</td>
  <td>
    <a class="list" title="%(fullname)s" href="%(myrname)s;a=commit;h=%(hash)s">
      <b>%(name)s</b>
    </a><br/>
    %(match)s
  </td>
  <td class="link">
    <a href="%(myrname)s;a=commit;h=%(hash)s">commit</a> |
    <a href="%(myrname)s;a=commitdiff;h=%(hash)s">commitdiff</a>
  </td>
		""" % {
			'age': how_old(p.local_date),
			'author': gen_authorlink(p.author, shorten_str(p.shortauthor, 26)),
			'myrname': config.myreponame,
			'hash': p.hash,
			'name': escape(shorten_str(p.name)),
			'fullname': escape(p.name),
			'match': highlight(s, shorten_str(match)),
		}
		print "</tr>"

	print '</table>'
	print_footer()


def do_die():
	print_header()
	print "<p><font color=red>Error! Malformed query</font></p>"
	print_footer()


def do_listrepos():
	import config as all_configs
	expand_multi_config(all_configs)

	# the header here is special since we don't have a repo
	print "Content-type: text/html; charset=utf-8\n"
	print '<?xml version="1.0" encoding="utf-8"?>'
	print """
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN"
		"http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
<html xmlns="http://www.w3.org/1999/xhtml" xml:lang="en-US" lang="en-US">
<head>
<meta http-equiv="content-type" content="text/html; charset=utf-8"/>
<meta name="robots" content="index, nofollow"/>
<title>darcs - Repositories</title>
<link rel="stylesheet" type="text/css" href="%(css)s"/>
<link rel="shortcut icon" href="%(fav)s"/>
<link rel="icon" href="%(fav)s"/>
</head>

<body>
<div class="page_header">
<a href="http://darcs.net" title="darcs">
<img src="%(logo)s" alt="darcs logo" style="float:right; border-width:0px;"/>
</a>
<a href="%(myname)s">repos</a> / index
</div>
<div class="index_include">
%(summary)s
</div>
<table cellspacing="0">
<tr>
<th>Project</th>
<th>Description</th>
<th></th>
</tr>
	""" % {
		'myname': config.myname,
		'css': config.cssfile,
		'fav': config.darcsfav,
		'logo': config.darcslogo,
		'summary': config.summary
	}

	# some python magic
	alt = True
	for conf in dir(all_configs):
		if conf.startswith('__'):
			continue
		c = all_configs.__getattribute__(conf)
		if 'reponame' not in dir(c):
			continue
		name = escape(c.reponame)
		desc = escape(c.repodesc)

		if alt: print '<tr class="dark">'
		else: print '<tr class="light">'
		alt = not alt
		print """
<td><a class="list" href="%(myname)s?r=%(name)s;a=summary">%(dname)s</a></td>
<td>%(desc)s</td>
<td class="link"><a href="%(myname)s?r=%(name)s;a=summary">summary</a> |
<a href="%(myname)s?r=%(name)s;a=shortlog">shortlog</a> |
<a href="%(myname)s?r=%(name)s;a=log">log</a> |
<a href="%(myname)s?r=%(name)s;a=tree">tree</a>
</td>
</tr>
		""" % {
			'myname': config.myname,
			'dname': name,
			'name': urllib.quote(name),
			'desc': shorten_str(desc, 60)
		}
	print "</table>"
	print_footer(put_rss = 0)

def expand_multi_config(config):
	"""Expand configuration entries that serve as "template" to others;
	this make it easier to have a single directory with all the repos,
	because they don't need specific entries in the configuration anymore.
	"""

	for conf in dir(config):
		if conf.startswith('__'):
			continue
		c = config.__getattribute__(conf)
		if 'multidir' not in dir(c):
			continue

		if not os.path.isdir(c.multidir):
			continue

		if 'exclude' not in dir(c):
			c.exclude = []

		entries = []
		if 'multidir_deep' in dir(c) and c.multidir_deep:
			for (root, dirs, files) in os.walk(c.multidir):
				# do not visit hidden directories
				dirs[:] = [d for d in dirs \
						if not d.startswith('.')]
				if '_darcs' in dirs:
					p = root[1 + len(c.multidir):]
					entries.append(p)
		else:
			entries = os.listdir(c.multidir)

		entries.sort()
		for name in entries:
			name = name.replace('\\', '/')
			if name.startswith('.'):
				continue
			fulldir = c.multidir + '/' + name
			if not os.path.isdir(fulldir + '/_darcs'):
				continue
			if name in c.exclude:
				continue

			# set the display name at the beginning, so it can be
			# used by the other replaces
			if 'displayname' in dir(c):
				dname = c.displayname % { 'name': name }
			else:
				dname = name

			rep_dict = { 'name': name, 'dname': dname }

			if 'autoexclude' in dir(c) and c.autoexclude:
				dpath = fulldir + \
					'/_darcs/third_party/darcsweb'
				if not os.path.isdir(dpath):
					continue

			if 'autodesc' in dir(c) and c.autodesc:
				dpath = fulldir + \
					'/_darcs/third_party/darcsweb/desc'
				if os.access(dpath, os.R_OK):
					desc = open(dpath).readline().rstrip("\n")
				else:
					desc = c.repodesc % rep_dict
			else:
				desc = c.repodesc % rep_dict

			if 'autourl' in dir(c) and c.autourl:
				dpath = fulldir + \
					'/_darcs/third_party/darcsweb/url'
				if os.access(dpath, os.R_OK):
					url = open(dpath).readline().rstrip("\n")
				else:
					url = c.repourl % rep_dict
			else:
				url = c.repourl % rep_dict

			if 'autoprojurl' in dir(c) and c.autoprojurl:
				dpath = fulldir + \
					'/_darcs/third_party/darcsweb/projurl'
				if os.access(dpath, os.R_OK):
					projurl = open(dpath).readline().rstrip("\n")
				elif 'repoprojurl' in dir(c):
					projurl = c.repoprojurl % rep_dict
				else:
					projurl = None
			elif 'repoprojurl' in dir(c):
				projurl = c.repoprojurl % rep_dict
			else:
				projurl = None

			rdir = fulldir
			class tmp_config:
				reponame = dname
				repodir = rdir
				repodesc = desc
				repourl = url
				repoencoding = c.repoencoding
				repoprojurl = projurl

				if 'footer' in dir(c):
					footer = c.footer

			# index by display name to avoid clashes
			config.__setattr__(dname, tmp_config)

def fill_config(name = None):
	import config as all_configs
	expand_multi_config(all_configs)

	if name:
		# we only care about setting some configurations if a repo was
		# specified; otherwise we only set the common configuration
		# directives
		for conf in dir(all_configs):
			if conf.startswith('__'):
				continue
			c = all_configs.__getattribute__(conf)
			if 'reponame' not in dir(c):
				continue
			if c.reponame == name:
				break
		else:
			# not found
			raise "RepoNotFound", name

	# fill the configuration
	base = all_configs.base
	if 'myname' not in dir(base):
		# SCRIPT_NAME has the full path, we only take the file name
		config.myname = os.path.basename(os.environ['SCRIPT_NAME'])
	else:
		config.myname = base.myname

	if 'myurl' not in dir(base) and 'cachedir' not in dir(base):
		n = os.environ['SERVER_NAME']
		p = os.environ['SERVER_PORT']
		s = os.path.dirname(os.environ['SCRIPT_NAME'])
		u = os.environ.get('HTTPS', 'off') in ('on', '1')
		if not u and p == '80' or u and p == '443':
			p = ''
		else:
			p = ':' + p
		config.myurl = 'http%s://%s%s%s' % (u and 's' or '', n, p, s)
	else:
		config.myurl = base.myurl

	config.darcslogo = base.darcslogo
	config.darcsfav = base.darcsfav
	config.cssfile = base.cssfile
	if name:
		config.myreponame = config.myname + '?r=' + urllib.quote(name)
		config.reponame = c.reponame
		config.repodesc = c.repodesc
		config.repodir = c.repodir
		config.repourl = c.repourl

		config.repoprojurl = None
		if 'repoprojurl' in dir(c):
			config.repoprojurl = c.repoprojurl

		# repoencoding must be a tuple
		if isinstance(c.repoencoding, str):
			config.repoencoding = (c.repoencoding, )
		else:
			config.repoencoding = c.repoencoding

	# optional parameters
	if "darcspath" in dir(base):
		config.darcspath = base.darcspath + '/'
	else:
		config.darcspath = ""

	if "summary" in dir(base):
		config.summary = base.summary
	else:
		config.summary = """
This is the repository index for a darcsweb site.<br/>
These are all the available repositories.<br/>
		"""

	if "cachedir" in dir(base):
		config.cachedir = base.cachedir
	else:
		config.cachedir = None

	if "searchlimit" in dir(base):
		config.searchlimit = base.searchlimit
	else:
		config.searchlimit = 100

	if "logtimes" in dir(base):
		config.logtimes = base.logtimes
	else:
		config.logtimes = None

	if "url_links" in dir(base):
		config.url_links = base.url_links
	else:
		config.url_links = ()

	if name and "footer" in dir(c):
		config.footer = c.footer
	elif "footer" in dir(base):
		config.footer = base.footer
	else:
		config.footer = "Crece desde el pueblo el futuro / " \
				+ "crece desde el pie"
	if "author_links" in dir(base):
		config.author_links = base.author_links
	else:
		config.author_links = None
	if "disable_annotate" in dir(base):
		config.disable_annotate = base.disable_annotate
	else:
		config.disable_annotate = False



#
# main
#

if sys.version_info < (2, 3):
	print "Sorry, but Python 2.3 or above is required to run darcsweb."
	sys.exit(1)

form = cgi.FieldStorage()

# if they don't specify a repo, print the list and exit
if not form.has_key('r'):
	fill_config()
	do_listrepos()
	log_times(cache_hit = 0, event = 'index')
	sys.exit(0)

# get the repo configuration and fill the config class
current_repo = urllib.unquote(form['r'].value)
fill_config(current_repo)


# get the action, or default to summary
if not form.has_key("a"):
	action = "summary"
else:
	action = filter_act(form["a"].value)

# check if we have the page in the cache
if config.cachedir:
	url_request = os.environ['QUERY_STRING']
	# create a string representation of the request, ignoring all the
	# unused parameters to avoid DoS
	params = ['r', 'a', 'f', 'h', 'topi']
	params = [ x for x in form.keys() if x in params ]
	url_request = [ (x, form[x].value) for x in params ]
	url_request.sort()
	cache = Cache(config.cachedir, url_request)
	if cache.open():
		# we have a hit, dump and run
		cache.dump()
		cache.close()
		log_times(cache_hit = 1, repo = config.reponame)
		sys.exit(0)
	# if there is a miss, the cache will step over stdout, intercepting
	# all "print"s and writing them to the cache file automatically


# see what should we do according to the received action
if action == "summary":
	do_summary()

elif action == "commit":
	phash = filter_hash(form["h"].value)
	do_commit(phash)
elif action == "commitdiff":
	phash = filter_hash(form["h"].value)
	do_commitdiff(phash)
elif action == "plain_commitdiff":
	phash = filter_hash(form["h"].value)
	do_plain_commitdiff(phash)
elif action == "darcs_commitdiff":
	phash = filter_hash(form["h"].value)
	do_darcs_commitdiff(phash)
elif action == "raw_commitdiff":
	phash = filter_hash(form["h"].value)
	do_raw_commitdiff(phash)

elif action == 'headdiff':
	phash = filter_hash(form["h"].value)
	do_headdiff(phash)
elif action == "plain_headdiff":
	phash = filter_hash(form["h"].value)
	do_plain_headdiff(phash)
elif action == "darcs_headdiff":
        phash = filter_hash(form["h"].value)
        do_darcs_headdiff(phash)

elif action == "filediff":
	phash = filter_hash(form["h"].value)
	fname = filter_file(form["f"].value)
	do_filediff(phash, fname)
elif action == "plain_filediff":
	phash = filter_hash(form["h"].value)
	fname = filter_file(form["f"].value)
	do_plain_filediff(phash, fname)
elif action == "darcs_filediff":
        phash = filter_hash(form["h"].value)
	fname = filter_file(form["f"].value)
	do_darcs_filediff(phash, fname)

elif action == 'headfilediff':
	phash = filter_hash(form["h"].value)
	fname = filter_file(form["f"].value)
	do_file_headdiff(phash, fname)
elif action == "plain_headfilediff":
	phash = filter_hash(form["h"].value)
	fname = filter_file(form["f"].value)
	do_plain_fileheaddiff(phash, fname)
elif action == "darcs_headfilediff":
        phash = filter_hash(form["h"].value)
	fname = filter_file(form["f"].value)
        do_darcs_fileheaddiff(phash, fname)

elif action == "annotate_normal":
	fname = filter_file(form["f"].value)
	if form.has_key("h"):
		phash = filter_hash(form["h"].value)
	else:
		phash = None
	do_annotate(fname, phash, "normal")
elif action == "annotate_plain":
	fname = filter_file(form["f"].value)
	if form.has_key("h"):
		phash = filter_hash(form["h"].value)
	else:
		phash = None
        do_annotate_plain(fname, phash)
elif action == "annotate_zebra":
	fname = filter_file(form["f"].value)
	if form.has_key("h"):
		phash = filter_hash(form["h"].value)
	else:
		phash = None
	do_annotate(fname, phash, "zebra")
elif action == "annotate_shade":
	fname = filter_file(form["f"].value)
	if form.has_key("h"):
		phash = filter_hash(form["h"].value)
	else:
		phash = None
	do_annotate(fname, phash, "shade")

elif action == "shortlog":
	if form.has_key("topi"):
		topi = int(filter_num(form["topi"].value))
	else:
		topi = 0
	do_shortlog(topi)

elif action == "filehistory":
	if form.has_key("topi"):
		topi = int(filter_num(form["topi"].value))
	else:
		topi = 0
	fname = filter_file(form["f"].value)
	do_filehistory(topi, fname)

elif action == "log":
	if form.has_key("topi"):
		topi = int(filter_num(form["topi"].value))
	else:
		topi = 0
	do_log(topi)

elif action == 'headblob':
	fname = filter_file(form["f"].value)
	do_headblob(fname)

elif action == 'plainblob':
	fname = filter_file(form["f"].value)
	do_plainblob(fname)

elif action == 'tree':
	if form.has_key('f'):
		fname = filter_file(form["f"].value)
	else:
		fname = '/'
	do_tree(fname)

elif action == 'rss':
	do_rss()

elif action == 'atom':
	do_atom()

elif action == 'search':
	if form.has_key('s'):
		s = form["s"].value
	else:
		s = ''
	do_search(s)
	if config.cachedir:
		cache.cancel()

else:
	action = "invalid query"
	do_die()
	if config.cachedir:
		cache.cancel()


if config.cachedir:
	cache.close()

log_times(cache_hit = 0, repo = config.reponame)


