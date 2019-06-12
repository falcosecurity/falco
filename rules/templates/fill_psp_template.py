#!/usr/bin/python

import os
import sys
import jinja2

p = {}

p['policy_name'] = "Nginx psp"
p['image_list'] = "[nginx]"
p['allow_privileged'] = False
p['allow_host_pid'] = False
p['allow_host_ipc'] = False
p['allow_host_network'] = False
p['host_network_ports'] = [[10,20],[30,40]]
p['allowed_volume_types'] = ["configMap","emptyDir"]
p['allowed_host_paths'] = ["/etc", "/usr/bin"]
p['must_run_fs_groups'] = [[0,10],[20,30]]
p['may_run_fs_groups'] = [[0,10],[25,35]]
p['must_run_as_users'] = [[10,20],[25,34]]
p['must_run_as_non_root'] = True
p['must_run_as_groups'] = [[1,2],[5,6]]
p['may_run_as_groups'] = [[3,4],[7,8]]
p['read_only_root_filesystem'] = True

# These are derived from the above
p['host_network_ports_str'] = ",".join(['{}:{}'.format(pair[0],pair[1]) for pair in p['host_network_ports']])
p['must_run_fs_groups_str'] = ",".join(['{}:{}'.format(pair[0],pair[1]) for pair in p['must_run_fs_groups']])
p['may_run_fs_groups_str'] = ",".join(['{}:{}'.format(pair[0],pair[1]) for pair in p['may_run_fs_groups']])
p['must_run_as_users_str'] = ",".join(['{}:{}'.format(pair[0],pair[1]) for pair in p['must_run_as_users']])
p['must_run_as_groups_str'] = ",".join(['{}:{}'.format(pair[0],pair[1]) for pair in p['must_run_as_groups']])
p['may_run_as_groups_str'] = ",".join(['{}:{}'.format(pair[0],pair[1]) for pair in p['may_run_as_groups']])

yaml_str = ""

with open(os.path.join(os.path.dirname(os.path.realpath(__file__)), 'k8s_psp_rules.yaml.tmpl'),'r') as f:
    yaml_str = f.read()

template = jinja2.Template(yaml_str, trim_blocks=True)
yaml_psp = template.render(p=p)
sys.stdout.write(yaml_psp)
