#!/usr/bin/python

# Author: Ethan Sutin

from lxml import etree
import urllib2,re
from distutils.version import LooseVersion

response = urllib2.urlopen('https://github.com/boot2docker/boot2docker/tags.atom')
ns_map = {'ns': 'http://www.w3.org/2005/Atom'}
data = etree.fromstring(response.read())
release_nodes = data.xpath('//ns:feed/ns:entry/ns:title', namespaces=ns_map)

for release in release_nodes:
  version = release.text
  if ':' in version:
    version = version[:version.index(':')]
  # tracepoints only enabled >= 1.7.0
  if LooseVersion(version[1:]) >= LooseVersion('1.7'):
    dockerFile = urllib2.urlopen('https://raw.githubusercontent.com/boot2docker/boot2docker/%s/Dockerfile' % (version)).read()
    for line in dockerFile.split('\n'):
      if re.search('ENV KERNEL_VERSION', line):
            kernel_version = line.split()[-1]
      if re.search('ENV AUFS_BRANCH', line):
            aufs_branch = line.split()[-1]
      if re.search('ENV AUFS_COMMIT', line):
            aufs_commit = line.split()[-1]
    print 'boot2docker-%s %s-boot2docker https://www.kernel.org/pub/linux/kernel/v4.x/linux-%s.tar.xz https://raw.githubusercontent.com/boot2docker/boot2docker/%s/kernel_config https://github.com/sfjro/aufs4-standalone %s %s' % \
      (version[1:],kernel_version,kernel_version,version,aufs_branch,aufs_commit)
