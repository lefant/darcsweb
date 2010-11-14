#!/usr/bin/env python

"""
A darcsweb configuration generator
----------------------------------

This is a small utility that generates configuration files for darcsweb, in
case you're lazy and/or have many repositories.

It receives four parameters: the base URL for your repositories, the base
description, the encoding and the directory to get the repositories from.
It replaces the string "NAME" with the name of the directory that holds the
repository, so you can specify urls and descriptions with the name in them.

Then, it generates an appropiate configuration for each repository in the
directory. It outputs the configuration to stdout, so you can redirect it to
config.py. For example:

$ mkconf.py "http://example.com/darcs/NAME" "Repo for NAME" latin1 \\
	~/devel/repos/ >> config.py

Remember that you still need to do the base configuration by hand. You can do
that by copying the sample included with darcsweb.
"""


import sys
import os
import string
import urllib


def help():
	print "Error: wrong parameter count"
	print __doc__

def filter_class(s):
	"Filter s so the new string can be used as a class name."
	allowed = string.ascii_letters + string.digits + '_'
	l = [c for c in s if c in allowed]
	return string.join(l, "")

def filter_url(s):
	"Filter s so the new string can be used in a raw url."
	return urllib.quote_plus(s, ':/')


# check parameters
if len(sys.argv) != 5:
	help()
	sys.exit(0)

myself, baseurl, basedesc, baseencoding, basepath = sys.argv

dirs = os.listdir(basepath)
for d in dirs:
	path = basepath + '/' + d
	if not os.path.isdir(path + '/_darcs'):
		# not a repo, skip
		continue
	s = \
"""
class %(classname)s:
	reponame = '%(name)s'
	repodesc = '%(desc)s'
	repodir = '%(dir)s'
	repourl = '%(url)s'
	repoencoding = '%(encoding)s'
""" % {
		'classname': filter_class(d),
		'name': d,
		'desc': basedesc.replace('NAME', d),
		'dir': os.path.abspath(basepath + '/' + d),
		'url': filter_url(baseurl.replace('NAME', d)),
		'encoding': baseencoding,
	}
	print s

