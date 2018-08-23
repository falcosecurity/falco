#!/usr/bin/env python

# Author: Samuele Pilleri
# Date: August 17th, 2015

import bz2
import re
import sqlite3
import sys
import tempfile
import time
import urllib2
import zlib

from lxml import html

#
# This is the main configuration tree for easily analyze Linux repositories
# hunting packages. When adding repos or so be sure to respect the same data
# structure
#
repos = {
    "CentOS" : [
        {
            # This is the root path of the repository in which the script will
            # look for distros (HTML page)
            "root" : "http://mirrors.kernel.org/centos/",

            # This is the XPath + Regex (optional) for analyzing the `root`
            # page and discover possible distro versions. Use the regex if you
            # want to limit the version release
            "discovery_pattern" : "/html/body//pre/a[regex:test(@href, '^6|^7.*$')]/@href",

            # Once we have found every version available, we need to know were
            # to go inside the tree to find packages we need (HTML pages)
            "subdirs" : [
                "os/x86_64/Packages/",
                "updates/x86_64/Packages/"
            ],

            # Finally, we need to inspect every page for packages we need.
            # Again, this is a XPath + Regex query so use the regex if you want
            # to limit the number of packages reported.
            "page_pattern" : "/html/body//a[regex:test(@href, '^kernel-(devel-)?[0-9].*\.rpm$')]/@href"
        },

        {
            "root" : "http://vault.centos.org/",
            "discovery_pattern" : "//body//table/tr/td/a[regex:test(@href, '^6|^7.*$')]/@href",
            "subdirs" : [
                "os/x86_64/Packages/",
                "updates/x86_64/Packages/"
            ],
            "page_pattern" : "//body//table/tr/td/a[regex:test(@href, '^kernel-(devel-)?[0-9].*\.rpm$')]/@href"
        },

        {
            "root" : "http://vault.centos.org/centos/",
            "discovery_pattern" : "//body//table/tr/td/a[regex:test(@href, '^6|^7.*$')]/@href",
            "subdirs" : [
                "os/x86_64/Packages/",
                "updates/x86_64/Packages/"
            ],
            "page_pattern" : "//body//table/tr/td/a[regex:test(@href, '^kernel-(devel-)?[0-9].*\.rpm$')]/@href"
        }
    ],

    "Ubuntu" : [
        {
            # Had to split the URL because, unlikely other repos for which the
            # script was first created, Ubuntu puts everything into a single
            # folder. The real URL is be:
            # http://mirrors.us.kernel.org/ubuntu/pool/main/l/linux/
            "root" : "https://mirrors.kernel.org/ubuntu/pool/main/l/",
            "discovery_pattern" : "/html/body//a[@href = 'linux/']/@href",
            "subdirs" : [""],
            "page_pattern" : "/html/body//a[regex:test(@href, '^linux-(image|headers)-[3-9].*-generic.*amd64.deb$')]/@href"
        },

        {
            "root" : "https://mirrors.kernel.org/ubuntu/pool/main/l/",
            "discovery_pattern" : "/html/body//a[@href = 'linux/']/@href",
            "subdirs" : [""],
            "page_pattern" : "/html/body//a[regex:test(@href, '^linux-headers-[3-9].*_all.deb$')]/@href"
        },

        {
            "root" : "http://security.ubuntu.com/ubuntu/pool/main/l/",
            "discovery_pattern" : "/html/body//a[@href = 'linux/']/@href",
            "subdirs" : [""],
            "page_pattern" : "/html/body//a[regex:test(@href, '^linux-(image|headers)-[3-9].*-generic.*amd64.deb$')]/@href"
        },

        {
            "root" : "http://security.ubuntu.com/ubuntu/pool/main/l/",
            "discovery_pattern" : "/html/body//a[@href = 'linux/']/@href",
            "subdirs" : [""],
            "page_pattern" : "/html/body//a[regex:test(@href, '^linux-headers-[3-9].*_all.deb$')]/@href"
        }
    ],

    "Fedora" : [
        {
            "root" : "https://mirrors.kernel.org/fedora/releases/",
            "discovery_pattern": "/html/body//a[regex:test(@href, '^2[2-9]/$')]/@href",
            "subdirs" : [
                "Everything/x86_64/os/Packages/k/"
            ],
            "page_pattern" : "/html/body//a[regex:test(@href, '^kernel-(core|devel)-[0-9].*\.rpm$')]/@href"
        },

        {
            "root" : "https://mirrors.kernel.org/fedora/updates/",
            "discovery_pattern": "/html/body//a[regex:test(@href, '^2[2-9]/$')]/@href",
            "subdirs" : [
                "x86_64/Packages/k/"
            ],
            "page_pattern" : "/html/body//a[regex:test(@href, '^kernel-(core|devel)-[0-9].*\.rpm$')]/@href"
        },

        {
            "root" : "https://mirrors.kernel.org/fedora/updates/",
            "discovery_pattern": "/html/body//a[regex:test(@href, '^2[2-9]/$')]/@href",
            "subdirs" : [
                "Everything/x86_64/Packages/k/"
            ],
            "page_pattern" : "/html/body//a[regex:test(@href, '^kernel-(core|devel)-[0-9].*\.rpm$')]/@href"
        },

        # {
        # 	"root" : "https://mirrors.kernel.org/fedora/development/",
        # 	"discovery_pattern": "/html/body//a[regex:test(@href, '^2[2-9]/$')]/@href",
        # 	"subdirs" : [
        # 		"x86_64/os/Packages/k/"
        # 	],
        # 	"page_pattern" : "/html/body//a[regex:test(@href, '^kernel-(core|devel)-[0-9].*\.rpm$')]/@href"
        # }
    ],

    #
    # Fedora Atomic repo is hard-coded to get the 4.17.x and 4.18.x (excluding rc) for now.
    #
    "Fedora-Atomic" : [
        {
            "root" : "https://kojipkgs.fedoraproject.org/packages/kernel/",
            "version_discovery_pattern": "/html/body//a[regex:test(@href, '^4\.1[78].*/$')]/@href",
            "build_discovery_pattern": "/html/body//a[regex:test(@href, '^[0-9]+\.[^r].*/$')]/@href",
            "subdirs" : [
                "x86_64/"
            ],
            "page_pattern" : "/html/body//a[regex:test(@href, '^kernel-(core|devel)-[0-9].*\.rpm$')]/@href",
         },
    ],

    "CoreOS" : [
        {
            "root" : "http://alpha.release.core-os.net/",
            "discovery_pattern": "/html/body//a[regex:test(@href, 'amd64-usr')]/@href",
            "subdirs" : [
                ""
            ],
            "page_pattern" : "/html/body//a[regex:test(@href, '^[5-9][0-9][0-9]|current|[1][0-9]{3}')]/@href",
            "exclude_patterns": ["^15\d\d\."]
        },

        {
            "root" : "http://beta.release.core-os.net/",
            "discovery_pattern": "/html/body//a[regex:test(@href, 'amd64-usr')]/@href",
            "subdirs" : [
                ""
            ],
            "page_pattern" : "/html/body//a[regex:test(@href, '^[5-9][0-9][0-9]|current|[1][0-9]{3}')]/@href"
        },

        {
            "root" : "http://stable.release.core-os.net/",
            "discovery_pattern": "/html/body//a[regex:test(@href, 'amd64-usr')]/@href",
            "subdirs" : [
                ""
            ],
            "page_pattern" : "/html/body//a[regex:test(@href, '^[4-9][0-9][0-9]|current|[1][0-9]{3}')]/@href"
        }
    ],

    "Debian": [
        {
            "root": "https://mirrors.kernel.org/debian/pool/main/l/",
            "discovery_pattern": "/html/body/pre/a[@href = 'linux/']/@href",
            "subdirs": [""],
            "page_pattern": "/html/body//a[regex:test(@href, '^linux-(image|headers)-[3-9]\.[0-9]+\.[0-9]+.*amd64.deb$')]/@href",
            "exclude_patterns": ["-rt", "dbg", "trunk", "all", "exp", "unsigned", "cloud-amd64"]
        },
        {
            "root": "http://security.debian.org/pool/updates/main/l/",
            "discovery_pattern": "/html/body/table//tr/td/a[@href = 'linux/']/@href",
            "subdirs": [""],
            "page_pattern": "/html/body//a[regex:test(@href, '^linux-(image|headers)-[3-9]\.[0-9]+\.[0-9]+.*amd64.deb$')]/@href",
            "exclude_patterns": ["-rt", "dbg", "trunk", "all", "exp", "unsigned", "cloud-amd64"]
        },
        {
            "root": "http://mirrors.kernel.org/debian/pool/main/l/",
            "discovery_pattern": "/html/body/pre/a[@href = 'linux-tools/']/@href",
            "subdirs": [""],
            "page_pattern": "/html/body//a[regex:test(@href, '^linux-kbuild-.*amd64.deb$')]/@href",
            "exclude_patterns": ["-rt", "dbg", "trunk", "all", "exp", "unsigned", "cloud-amd64"]
        }
    ]
}

# Build static list, check here for the last Amazon Linux AMI release: https://aws.amazon.com/amazon-linux-2/faqs/
amazon_linux_builder = [('latest', 'updates'), ('latest', 'main'), ('2017.03', 'updates'), ('2017.03', 'main'), ('2017.09', 'updates'), ('2017.09', 'main'), ('2018.03', 'updates'), ('2018.03', 'main')]
amazon_repos = []
for repo_release, release_type in amazon_linux_builder:
    amazon_repos.append({
        "root": "http://repo.us-east-1.amazonaws.com/" + repo_release + "/" + release_type + "/mirror.list",
        "discovery_pattern": "SELECT * FROM packages WHERE name LIKE 'kernel%'",
        "subdirs": [""],
        "page_pattern": "",
        "exclude_patterns": ["doc", "tools", "headers"]
    })
repos['AmazonLinux'] = amazon_repos

prev_months = 24
now = time.localtime()
check_months = [time.localtime(time.mktime((now.tm_year, now.tm_mon - n, 1, 0, 0, 0, 0, 0, 0)))[:2] for n in range(prev_months)]
amazon_linux2 = []
for year, month in check_months[:-1]:
    amazon_linux2.append({
        "root": "http://amazonlinux.us-east-1.amazonaws.com/" + str(year) + "." + str(month).zfill(2) + "/core/latest/x86_64/mirror.list",
        "discovery_pattern": "SELECT * FROM packages WHERE name LIKE 'kernel%'",
        "subdirs": [""],
        "page_pattern": "",
        "exclude_patterns": ["doc", "tools", "headers"]
        })

repos['AmazonLinux2'] = amazon_linux2

def exclude_patterns(repo, packages, base_url, urls):
    for rpm in packages:
        if "exclude_patterns" in repo and any(re.search(x, rpm) for x in repo["exclude_patterns"]):
            continue
        else:
            urls.add(base_url + str(urllib2.unquote(rpm)))

def process_al_distro(al_distro_name, current_repo):
    get_url = urllib2.urlopen(current_repo["root"]).readline()
    if get_url:
        if al_distro_name == "AmazonLinux":
            base_mirror_url = get_url.replace('$basearch','x86_64').replace('\n','') + '/'
            db_path = "repodata/primary.sqlite.bz2"
        elif al_distro_name == "AmazonLinux2":
            base_mirror_url = get_url.replace('\n','') + '/'
            db_path = "repodata/primary.sqlite.gz"
        
        response = urllib2.urlopen(base_mirror_url + db_path)

        if al_distro_name == "AmazonLinux":
            decompressed_data = bz2.decompress(response.read())
        elif al_distro_name == "AmazonLinux2":
            decompressed_data = zlib.decompress(response.read(), 16+zlib.MAX_WBITS)

        db_file = tempfile.NamedTemporaryFile()
        db_file.write(decompressed_data)
        conn = sqlite3.connect(db_file.name)
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        al_rpms = [r["location_href"] for r in c.execute(current_repo["discovery_pattern"])]
        exclude_patterns(current_repo, al_rpms, base_mirror_url, urls)
        conn.close()
        db_file.close()

        return True

    else:
        return False

#
# Fedora Atomic needs 2 levels of discovery(for version, and build id, respectively)
#
def process_atomic_distro(current_repos):
    for repo in current_repos["Fedora-Atomic"]:
        try:
            root = urllib2.urlopen(repo["root"],timeout=URL_TIMEOUT).read()
        except:
            continue
        versions = html.fromstring(root).xpath(repo["version_discovery_pattern"], namespaces = {"regex": "http://exslt.org/regular-expressions"})
        for version in versions:
            version_url=repo["root"] + version
            try:
                version_page=urllib2.urlopen(version_url,timeout=URL_TIMEOUT).read()
            except:
                continue
            builds = html.fromstring(version_page).xpath(repo["build_discovery_pattern"], namespaces = {"regex": "http://exslt.org/regular-expressions"})
            for build in builds:
                for subdir in repo["subdirs"]:
                    source = version_url + build + subdir
                    try:
                        page = urllib2.urlopen(source,timeout=URL_TIMEOUT).read()
                    except:
                        continue
                    rpms = html.fromstring(page).xpath(repo["page_pattern"], namespaces = {"regex": "http://exslt.org/regular-expressions"})
                    exclude_patterns(repo, rpms, source, urls)


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

distro = sys.argv[1]

#
# Navigate the `repos` tree and look for packages we need that match the
# patterns given. Save the result in `packages`.
#

al2_repo_count = 0

for repo in repos[distro]:
    if distro == 'AmazonLinux':
        try:
            process_al_distro(distro, repo)
        except:
            continue
    elif distro == 'AmazonLinux2':
        try:
            # Brute force finding the repositories and only grab the most recent two, then skip the rest.
            if al2_repo_count < 2:
                if process_al_distro(distro, repo):
                    al2_repo_count += 1
        except:
            continue
    elif distro == "Fedora-Atomic":
        try:
            process_atomic_distro(repos)
        except:
            continue
    else:
        try:
            root = urllib2.urlopen(repo["root"],timeout=URL_TIMEOUT).read()
        except:
            continue

        versions = html.fromstring(root).xpath(repo["discovery_pattern"], namespaces = {"regex": "http://exslt.org/regular-expressions"})
        for version in versions:
            for subdir in repo["subdirs"]:
                # The try - except block is used because 404 errors and similar
                # might happen (and actually happen because not all repos have
                # packages we need)
                try:
                    source = repo["root"] + version + subdir
                    page = urllib2.urlopen(source,timeout=URL_TIMEOUT).read()
                    rpms = html.fromstring(page).xpath(repo["page_pattern"], namespaces = {"regex": "http://exslt.org/regular-expressions"})
                    exclude_patterns(repo, rpms, source, urls)
                except:
                    continue

#
# Print URLs to stdout
#
for url in urls:
    print(url)
