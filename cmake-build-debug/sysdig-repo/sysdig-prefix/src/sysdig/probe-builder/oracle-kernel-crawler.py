#!/usr/bin/python
#
# Copyright (C) 2013-2018 Draios Inc dba Sysdig.
#
# This file is part of sysdig .
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

import sys

try:
    from urllib2 import urlopen, unquote
except ImportError:
	from urllib.request import urlopen
	from urllib.parse import unquote

from lxml import html

#
# Copied from kernel-crawler.py and hacked up for oracle linux
# because they don't use a normal directory structure.
#
repos = {
    # Oracle only puts full isos with unhelpful names on mirrors.kernel.org, so skip it
    "OL6-UEK": [
        {
            # yum.oracle.com has a bad cert, so use http instead of https
            "root": "http://yum.oracle.com/",
            "discovery_pattern": "/html/body//h3/a[regex:test(@href, 'oracle-linux-6\.html')]/@href",
            "sub_discovery_pattern": "/html/body//h3[regex:test(., '^UEK Release [3-9]:')]/a[regex:test(@href, 'x86_64/index.html')]/@href",
            "page_pattern": "/html/body//a[regex:test(@href, '^getPackage/kernel-uek-(devel-)?[0-9].*\.rpm$')]/@href",
        }
    ],

    "OL7-UEK": [
        {
            "root": "http://yum.oracle.com/",
            "discovery_pattern": "/html/body//h3/a[regex:test(@href, 'oracle-linux-7\.html')]/@href",
            "sub_discovery_pattern": "/html/body//h3[regex:test(., '^UEK Release [3-9]:')]/a[regex:test(@href, 'x86_64/index.html')]/@href",
            "page_pattern": "/html/body//a[regex:test(@href, '^getPackage/kernel-uek-(devel-)?[0-9].*\.rpm$')]/@href",
        }
    ],

    "Oracle-RHCK": [
        {
            "root": "http://yum.oracle.com/",
            "discovery_pattern": "/html/body//h3/a[regex:test(@href, 'oracle-linux-[6-7]+\.html')]/@href",
            "sub_discovery_pattern": "/html/body//h3[regex:test(., '^Latest:')]/a[regex:test(@href, 'x86_64/index.html')]/@href",
            "page_pattern": "/html/body//a[regex:test(@href, '^getPackage/kernel-(devel-)?[0-9].*\.rpm$')]/@href",
        }
    ]
}

def progress(distro, current, total, package):
    sys.stderr.write('\r{} {}/{} {}               '.format(distro, current, total, package))

#
# In our design you are not supposed to modify the code. The whole script is
# created so that you just have to add entry to the `repos` array and new
# links will be found automagically without needing to write any single line of
# code.
#
urls = set()
URL_TIMEOUT=30

if len(sys.argv) < 2 or not sys.argv[1] in repos:
    sys.stderr.write("Usage: " + sys.argv[0] + " <distro>\n")
    sys.exit(1)

#
# Navigate the `repos` tree and look for packages we need that match the
# patterns given. Save the result in `packages`.
#
for repo in repos[sys.argv[1]]:
    try:
        root = urlopen(repo["root"],timeout=URL_TIMEOUT).read()
    except:
        continue
    versions = html.fromstring(root).xpath(repo["discovery_pattern"], namespaces = {"regex": "http://exslt.org/regular-expressions"})
    vid = 0
    for version in versions:
        vid += 1
        ver_url = repo["root"] + version
        progress(repo["root"], vid, len(versions), version)
        try:
            subroot = urlopen(ver_url,timeout=URL_TIMEOUT).read()
        except:
            continue
        sub_vers = html.fromstring(subroot).xpath(repo["sub_discovery_pattern"], namespaces = {"regex": "http://exslt.org/regular-expressions"})
        for sub_ver in sub_vers:
            sub_ver = sub_ver.lstrip('/')
            # The try - except block is used because 404 errors and similar
            # might happen (and actually happen because not all repos have
            # packages we need)
            try:
                source = repo["root"] + sub_ver
                page = urlopen(source,timeout=URL_TIMEOUT).read()
                rpms = html.fromstring(page).xpath(repo["page_pattern"], namespaces = {"regex": "http://exslt.org/regular-expressions"})

                source = source.replace("index.html", "")
                for rpm in rpms:
                    urls.add(source + str(unquote(rpm)))
            except:
                continue

#
# Print URLs to stdout
#
for url in urls:
    print(url)
