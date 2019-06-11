#!/usr/bin/python

import os
import sys
import jinja2

p = {}

p['policy_name'] = "Nginx psp"
p['image_list'] = "[nginx]"
p['allow_privileged'] = True
p['allow_host_pid'] = True
p['allow_host_ipc'] = True
p['allow_host_network'] = True
p['host_network_ports'] = ""
p['allowed_volume_types'] = []
p['allowed_host_paths'] = []
p['must_run_fs_groups'] = []
p['may_run_fs_groups'] = []
p['read_only_root_filesystem'] = True

yaml_str = ""

with open(os.path.join(os.path.dirname(os.path.realpath(__file__)), 'k8s_psp_rules.yaml.tmpl'),'r') as f:
    yaml_str = f.read()

template = jinja2.Template(yaml_str, trim_blocks=True)
yaml_psp = template.render(p=p)
sys.stdout.write(yaml_psp)
