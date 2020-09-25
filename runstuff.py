import re
import mechanize
import os
import subprocess
import sys
import ssl

try:
    _create_unverified_https_context = ssl._create_unverified_context
except AttributeError:
    # Legacy Python that doesn't verify HTTPS certificates by default
    pass
else:
    # Handle target environment that doesn't support HTTPS verification
    ssl._create_default_https_context = _create_unverified_https_context

try:
    url = os.environ['URL']
    username = os.environ['USERNAME']
    password = os.environ['PASSWORD']
except KeyError:
    print("Environment not configured for testing")
    sys.exit(1)

br = mechanize.Browser()
br.set_handle_robots(False)
br.add_password(url, username, password)
br.open(url)

link = [x for x in br.links() if x.url[-4:] == '.exe'][0]

remotedir, filename = os.path.split(link.url)

print("Downloading file")

try:
    fh = open("C:\\npcap.exe", mode = "wb")
    dat = br.follow_link(link).read()
    fh.write(dat)
    fh.close()
except (mechanize.HTTPError, mechanize.URLError) as e:
    print("error in download")

print("Downloaded file")

