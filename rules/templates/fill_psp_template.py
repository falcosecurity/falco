#!/usr/bin/python

import os
import sys
import jinja2

p = {}

p['policy_name'] = "Mysql psp"
p['image_list'] = "[mysql]"
p['privileged'] = "True"

yaml_str = ""

with open(os.path.join(os.path.dirname(os.path.realpath(__file__)), 'k8s_psp_rules.yaml.tmpl'),'r') as f:
    yaml_str = f.read()

template = jinja2.Template(yaml_str, trim_blocks=True)
yaml_psp = template.render(p=p)
sys.stdout.write(yaml_psp)
