#!/usr/bin/env python
#
# Copyright (C) 2016-2018 Draios Inc dba Sysdig.
#
# This file is part of falco.
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
import os
import re
import json
import sets
import glob
import shutil
import subprocess

from avocado import Test
from avocado.utils import process
from avocado.utils import linux_modules

class FalcoTest(Test):

    def setUp(self):
        """
        Load the sysdig kernel module if not already loaded.
        """
        build_type = "Release"
        if 'BUILD_TYPE' in os.environ:
            build_type = os.environ['BUILD_TYPE']

        build_dir = os.path.join('/build', build_type)
        self.falcodir = self.params.get('falcodir', '/', default=os.path.join(self.basedir, build_dir))

        self.stdout_contains = self.params.get('stdout_contains', '*', default='')

        if not isinstance(self.stdout_contains, list):
            self.stdout_contains = [self.stdout_contains]

        self.stderr_contains = self.params.get('stderr_contains', '*', default='')

        if not isinstance(self.stderr_contains, list):
            self.stderr_contains = [self.stderr_contains]

        self.stdout_not_contains = self.params.get('stdout_not_contains', '*', default='')

        if not isinstance(self.stdout_not_contains, list):
            if self.stdout_not_contains == '':
                self.stdout_not_contains = []
            else:
                self.stdout_not_contains = [self.stdout_not_contains]

        self.stderr_not_contains = self.params.get('stderr_not_contains', '*', default='')

        if not isinstance(self.stderr_not_contains, list):
            if self.stderr_not_contains == '':
                self.stderr_not_contains = []
            else:
                self.stderr_not_contains = [self.stderr_not_contains]

        self.exit_status = self.params.get('exit_status', '*', default=0)
        self.should_detect = self.params.get('detect', '*', default=False)
        self.trace_file = self.params.get('trace_file', '*', default='')

        if self.trace_file and not os.path.isabs(self.trace_file):
            self.trace_file = os.path.join(build_dir, "test", self.trace_file)

        self.json_output = self.params.get('json_output', '*', default=False)
        self.json_include_output_property = self.params.get('json_include_output_property', '*', default=True)
        self.all_events = self.params.get('all_events', '*', default=False)
        self.priority = self.params.get('priority', '*', default='debug')
        self.rules_file = self.params.get('rules_file', '*', default=os.path.join(self.basedir, '../rules/falco_rules.yaml'))

        if not isinstance(self.rules_file, list):
            self.rules_file = [self.rules_file]

        self.rules_args = ""

        for file in self.rules_file:
            if not os.path.isabs(file):
                file = os.path.join(self.basedir, file)
            self.rules_args = self.rules_args + "-r " + file + " "

        self.conf_file = self.params.get('conf_file', '*', default=os.path.join(self.basedir, '../falco.yaml'))
        if not os.path.isabs(self.conf_file):
            self.conf_file = os.path.join(self.basedir, self.conf_file)

        self.run_duration = self.params.get('run_duration', '*', default='')

        self.disabled_rules = self.params.get('disabled_rules', '*', default='')

        if self.disabled_rules == '':
            self.disabled_rules = []

        if not isinstance(self.disabled_rules, list):
            self.disabled_rules = [self.disabled_rules]

        self.disabled_args = ""

        for rule in self.disabled_rules:
            self.disabled_args = self.disabled_args + "-D " + rule + " "

        self.detect_counts = self.params.get('detect_counts', '*', default=False)
        if self.detect_counts == False:
            self.detect_counts = {}
        else:
            detect_counts = {}
            for item in self.detect_counts:
                for key, value in item.items():
                    detect_counts[key] = value
            self.detect_counts = detect_counts

        self.rules_warning = self.params.get('rules_warning', '*', default=False)
        if self.rules_warning == False:
            self.rules_warning = sets.Set()
        else:
            self.rules_warning = sets.Set(self.rules_warning)

        # Maps from rule name to set of evttypes
        self.rules_events = self.params.get('rules_events', '*', default=False)
        if self.rules_events == False:
            self.rules_events = {}
        else:
            events = {}
            for item in self.rules_events:
                for item2 in item:
                    events[item2[0]] = sets.Set(item2[1])
            self.rules_events = events

        if self.should_detect:
            self.detect_level = self.params.get('detect_level', '*')

            if not isinstance(self.detect_level, list):
                self.detect_level = [self.detect_level]

        self.package = self.params.get('package', '*', default='None')

        self.addl_docker_run_args = self.params.get('addl_docker_run_args', '*', default='')

        self.copy_local_driver = self.params.get('copy_local_driver', '*', default=False)

        # Used by possibly_copy_local_driver as well as docker run
        self.module_dir = os.path.expanduser("~/.sysdig")

        self.outputs = self.params.get('outputs', '*', default='')

        if self.outputs == '':
            self.outputs = {}
        else:
            outputs = []
            for item in self.outputs:
                for key, value in item.items():
                    output = {}
                    output['file'] = key
                    output['line'] = value
                    outputs.append(output)
                    filedir = os.path.dirname(output['file'])
                    # Create the parent directory for the trace file if it doesn't exist.
                    if not os.path.isdir(filedir):
                        os.makedirs(filedir)
            self.outputs = outputs

        self.disable_tags = self.params.get('disable_tags', '*', default='')

        if self.disable_tags == '':
            self.disable_tags=[]

        self.run_tags = self.params.get('run_tags', '*', default='')

        if self.run_tags == '':
            self.run_tags=[]

        self.time_iso_8601 = self.params.get('time_iso_8601', '*', default=False)

    def tearDown(self):
        if self.package != 'None':
            self.uninstall_package()

    def check_rules_warnings(self, res):

        found_warning = sets.Set()

        for match in re.finditer('Rule ([^:]+): warning \(([^)]+)\):', res.stderr):
            rule = match.group(1)
            warning = match.group(2)
            found_warning.add(rule)

        self.log.debug("Expected warning rules: {}".format(self.rules_warning))
        self.log.debug("Actual warning rules: {}".format(found_warning))

        if found_warning != self.rules_warning:
            self.fail("Expected rules with warnings {} does not match actual rules with warnings {}".format(self.rules_warning, found_warning))

    def check_rules_events(self, res):

        found_events = {}

        for match in re.finditer('Event types for rule ([^:]+): (\S+)', res.stderr):
            rule = match.group(1)
            events = sets.Set(match.group(2).split(","))
            found_events[rule] = events

        self.log.debug("Expected events for rules: {}".format(self.rules_events))
        self.log.debug("Actual events for rules: {}".format(found_events))

        for rule in found_events.keys():
            if found_events.get(rule) != self.rules_events.get(rule):
                self.fail("rule {}: expected events {} differs from actual events {}".format(rule, self.rules_events.get(rule), found_events.get(rule)))

    def check_detections(self, res):
        # Get the number of events detected.
        match = re.search('Events detected: (\d+)', res.stdout)
        if match is None:
            self.fail("Could not find a line 'Events detected: <count>' in falco output")

        events_detected = int(match.group(1))

        if not self.should_detect and events_detected > 0:
            self.fail("Detected {} events when should have detected none".format(events_detected))

        if self.should_detect:
            if events_detected == 0:
                self.fail("Detected {} events when should have detected > 0".format(events_detected))

            for level in self.detect_level:
                level_line = '(?i){}: (\d+)'.format(level)
                match = re.search(level_line, res.stdout)

                if match is None:
                    self.fail("Could not find a line '{}: <count>' in falco output".format(level))

                    events_detected = int(match.group(1))

                    if not events_detected > 0:
                        self.fail("Detected {} events at level {} when should have detected > 0".format(events_detected, level))

    def check_detections_by_rule(self, res):
        # Get the number of events detected for each rule. Must match the expected counts.
        match = re.search('Triggered rules by rule name:(.*)', res.stdout, re.DOTALL)
        if match is None:
            self.fail("Could not find a block 'Triggered rules by rule name: ...' in falco output")

        triggered_rules = match.group(1)

        for rule, count in self.detect_counts.iteritems():
            expected = '\s{}: (\d+)'.format(rule)
            match = re.search(expected, triggered_rules)

            if match is None:
                actual_count = 0
            else:
                actual_count = int(match.group(1))

            if actual_count != count:
                self.fail("Different counts for rule {}: expected={}, actual={}".format(rule, count, actual_count))
            else:
                self.log.debug("Found expected count for rule {}: {}".format(rule, count))

    def check_outputs(self):
        for output in self.outputs:
            # Open the provided file and match each line against the
            # regex in line.
            file = open(output['file'], 'r')
            found = False
            for line in file:
                match = re.search(output['line'], line)

                if match is not None:
                    found = True

            if found == False:
                self.fail("Could not find a line '{}' in file '{}'".format(output['line'], output['file']))

        return True

    def check_json_output(self, res):
        if self.json_output:
            # Just verify that any lines starting with '{' are valid json objects.
            # Doesn't do any deep inspection of the contents.
            for line in res.stdout.splitlines():
                if line.startswith('{'):
                    obj = json.loads(line)
                    if self.json_include_output_property:
                        attrs = ['time', 'rule', 'priority', 'output']
                    else:
                        attrs = ['time', 'rule', 'priority']
                    for attr in attrs:
                        if not attr in obj:
                            self.fail("Falco JSON object {} does not contain property \"{}\"".format(line, attr))

    def install_package(self):

        if self.package.startswith("docker:"):

            image = self.package.split(":", 1)[1]
            # Remove an existing falco-test container first. Note we don't check the output--docker rm
            # doesn't have an -i equivalent.
            res = process.run("docker rm falco-test", ignore_status=True)

            rules_dir = os.path.abspath(os.path.join(self.basedir, "./rules"))
            conf_dir = os.path.abspath(os.path.join(self.basedir, "../"))
            traces_dir = os.path.abspath(os.path.join(self.basedir, "./trace_files"))
            self.falco_binary_path = "docker run --rm --name falco-test --privileged " \
                                     "-v /var/run/docker.sock:/host/var/run/docker.sock " \
                                     "-v /dev:/host/dev -v /proc:/host/proc:ro -v /boot:/host/boot:ro " \
                                     "-v /lib/modules:/host/lib/modules:ro -v {}:/root/.sysdig:ro -v " \
                                     "/usr:/host/usr:ro {} {} falco".format(
                                         self.module_dir, self.addl_docker_run_args, image)

        elif self.package.endswith(".deb"):
            self.falco_binary_path = '/usr/bin/falco';

            package_glob = "{}/{}".format(self.falcodir, self.package)

            matches = glob.glob(package_glob)

            if len(matches) != 1:
                self.fail("Package path {} did not match exactly 1 file. Instead it matched: {}", package_glob, ",".join(matches))

            package_path = matches[0]

            cmdline = "dpkg -i {}".format(package_path)
            self.log.debug("Installing debian package via \"{}\"".format(cmdline))
            res = process.run(cmdline, timeout=120, sudo=True)

        elif self.package.endswith(".rpm"):
            self.falco_binary_path = '/usr/bin/falco';

            package_glob = "{}/{}".format(self.falcodir, self.package)

            matches = glob.glob(package_glob)

            if len(matches) != 1:
                self.fail("Package path {} did not match exactly 1 file. Instead it matched: {}", package_glob, ",".join(matches))

            package_path = matches[0]

            cmdline = "rpm -i --nodeps --noscripts {}".format(package_path)
            self.log.debug("Installing centos package via \"{}\"".format(cmdline))
            res = process.run(cmdline, timeout=120, sudo=True)

    def uninstall_package(self):

        if self.package.startswith("docker:"):
            self.log.debug("Nothing to do, docker run with --rm")

        elif self.package.endswith(".rpm"):
            cmdline = "rpm -e --noscripts --nodeps falco"
            self.log.debug("Uninstalling centos package via \"{}\"".format(cmdline))
            res = process.run(cmdline, timeout=120, sudo=True)

        elif self.package.endswith(".deb"):
            cmdline = "dpkg --purge falco"
            self.log.debug("Uninstalling debian package via \"{}\"".format(cmdline))
            res = process.run(cmdline, timeout=120, sudo=True)

    def possibly_copy_driver(self):
        # Remove the contents of ~/.sysdig regardless of
        # copy_local_driver.
        self.log.debug("Checking for module dir {}".format(self.module_dir))
        if os.path.isdir(self.module_dir):
            self.log.info("Removing files below directory {}".format(self.module_dir))
            for rmfile in glob.glob(self.module_dir + "/*"):
                self.log.debug("Removing file {}".format(rmfile))
                os.remove(rmfile)

        if self.copy_local_driver:
            verstr = subprocess.check_output([self.falco_binary_path, "--version"]).rstrip()
            self.log.info("verstr {}".format(verstr))
            falco_version = verstr.split(" ")[2]
            self.log.info("falco_version {}".format(falco_version))
            arch = subprocess.check_output(["uname", "-m"]).rstrip()
            self.log.info("arch {}".format(arch))
            kernel_release = subprocess.check_output(["uname", "-r"]).rstrip()
            self.log.info("kernel release {}".format(kernel_release))

            # sysdig-probe-loader has a more comprehensive set of ways to
            # find the config hash. We only look at /boot/config-<kernel release>
            md5_output = subprocess.check_output(["md5sum", "/boot/config-{}".format(kernel_release)]).rstrip()
            config_hash = md5_output.split(" ")[0]

            probe_filename = "falco-probe-{}-{}-{}-{}.ko".format(falco_version, arch, kernel_release, config_hash)
            driver_path = os.path.join(self.falcodir, "driver", "falco-probe.ko")
            module_path = os.path.join(self.module_dir, probe_filename)
            self.log.debug("Copying {} to {}".format(driver_path, module_path))
            shutil.copyfile(driver_path, module_path)

    def test(self):
        self.log.info("Trace file %s", self.trace_file)

        self.falco_binary_path = '{}/userspace/falco/falco'.format(self.falcodir)

        self.possibly_copy_driver()

        if self.package != 'None':
            # This sets falco_binary_path as a side-effect.
            self.install_package()

        trace_arg = self.trace_file

        if self.trace_file:
            trace_arg = "-e {}".format(self.trace_file)

        # Run falco
        cmd = '{} {} {} -c {} {} -o json_output={} -o json_include_output_property={} -o priority={} -v'.format(
            self.falco_binary_path, self.rules_args, self.disabled_args, self.conf_file, trace_arg, self.json_output, self.json_include_output_property, self.priority)

        for tag in self.disable_tags:
            cmd += ' -T {}'.format(tag)

        for tag in self.run_tags:
            cmd += ' -t {}'.format(tag)

        if self.run_duration:
            cmd += ' -M {}'.format(self.run_duration)

        if self.all_events:
            cmd += ' -A'

        if self.time_iso_8601:
            cmd += ' -o time_format_iso_8601=true'

        self.falco_proc = process.SubProcess(cmd)

        res = self.falco_proc.run(timeout=180, sig=9)

        for pattern in self.stderr_contains:
            match = re.search(pattern, res.stderr)
            if match is None:
                self.fail("Stderr of falco process did not contain content matching {}".format(pattern))

        for pattern in self.stdout_contains:
            match = re.search(pattern, res.stdout)
            if match is None:
                self.fail("Stdout of falco process '{}' did not contain content matching {}".format(res.stdout, pattern))

        for pattern in self.stderr_not_contains:
            match = re.search(pattern, res.stderr)
            if match is not None:
                self.fail("Stderr of falco process contained content matching {} when it should have not".format(pattern))

        for pattern in self.stdout_not_contains:
            match = re.search(pattern, res.stdout)
            if match is not None:
                self.fail("Stdout of falco process '{}' did contain content matching {} when it should have not".format(res.stdout, pattern))

        if res.exit_status != self.exit_status:
            self.error("Falco command \"{}\" exited with unexpected return value {} (!= {})".format(
                cmd, res.exit_status, self.exit_status))

        # No need to check any outputs if the falco process exited abnormally.
        if res.exit_status != 0:
            return

        self.check_rules_warnings(res)
        if len(self.rules_events) > 0:
            self.check_rules_events(res)
        self.check_detections(res)
        if len(self.detect_counts) > 0:
            self.check_detections_by_rule(res)
        self.check_json_output(res)
        self.check_outputs()
        pass


if __name__ == "__main__":
    main()
