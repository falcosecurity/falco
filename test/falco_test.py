#!/usr/bin/env python

import os
import re
import json
import sets

from avocado import Test
from avocado.utils import process
from avocado.utils import linux_modules

class FalcoTest(Test):

    def setUp(self):
        """
        Load the sysdig kernel module if not already loaded.
        """
        self.falcodir = self.params.get('falcodir', '/', default=os.path.join(self.basedir, '../build'))

        self.stdout_contains = self.params.get('stdout_contains', '*', default='')
        self.stderr_contains = self.params.get('stderr_contains', '*', default='')
        self.exit_status = self.params.get('exit_status', '*', default=0)
        self.should_detect = self.params.get('detect', '*', default=False)
        self.trace_file = self.params.get('trace_file', '*')

        if not os.path.isabs(self.trace_file):
            self.trace_file = os.path.join(self.basedir, self.trace_file)

        self.json_output = self.params.get('json_output', '*', default=False)
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
                for item2 in item:
                    detect_counts[item2[0]] = item2[1]
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

        # Doing this in 2 steps instead of simply using
        # module_is_loaded to avoid logging lsmod output to the log.
        lsmod_output = process.system_output("lsmod", verbose=False)

        if linux_modules.parse_lsmod_for_module(lsmod_output, 'sysdig_probe') == {}:
            self.log.debug("Loading sysdig kernel module")
            process.run('sudo insmod {}/driver/sysdig-probe.ko'.format(self.falcodir))

        self.str_variant = self.trace_file

        self.outputs = self.params.get('outputs', '*', default='')

        if self.outputs == '':
            self.outputs = {}
        else:
            outputs = []
            for item in self.outputs:
                for item2 in item:
                    output = {}
                    output['file'] = item2[0]
                    output['line'] = item2[1]
                    outputs.append(output)
            self.outputs = outputs

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
            expected_line = '{}: {}'.format(rule, count)
            match = re.search(expected_line, triggered_rules)

            if match is None:
                self.fail("Could not find a line '{}' in triggered rule counts '{}'".format(expected_line, triggered_rules))
            else:
                self.log.debug("Found expected count for {}: {}".format(rule, match.group()))

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
                    for attr in ['time', 'rule', 'priority', 'output']:
                        if not attr in obj:
                            self.fail("Falco JSON object {} does not contain property \"{}\"".format(line, attr))

    def test(self):
        self.log.info("Trace file %s", self.trace_file)

        # Run the provided trace file though falco
        cmd = '{}/userspace/falco/falco {} {} -c {} -e {} -o json_output={} -v'.format(
            self.falcodir, self.rules_args, self.disabled_args, self.conf_file, self.trace_file, self.json_output)

        self.falco_proc = process.SubProcess(cmd)

        res = self.falco_proc.run(timeout=180, sig=9)

        if self.stderr_contains != '':
            match = re.search(self.stderr_contains, res.stderr)
            if match is None:
                self.fail("Stderr of falco process did not contain content matching {}".format(self.stderr_contains))

        if self.stdout_contains != '':
            match = re.search(self.stdout_contains, res.stdout)
            if match is None:
                self.fail("Stdout of falco process '{}' did not contain content matching {}".format(res.stdout, self.stdout_contains))

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
