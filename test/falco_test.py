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

        self.should_detect = self.params.get('detect', '*', default=False)
        self.trace_file = self.params.get('trace_file', '*')

        if not os.path.isabs(self.trace_file):
            self.trace_file = os.path.join(self.basedir, self.trace_file)

        self.json_output = self.params.get('json_output', '*', default=False)
        self.rules_file = self.params.get('rules_file', '*', default=os.path.join(self.basedir, '../rules/falco_rules.yaml'))

        if not os.path.isabs(self.rules_file):
            self.rules_file = os.path.join(self.basedir, self.rules_file)

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

        # Doing this in 2 steps instead of simply using
        # module_is_loaded to avoid logging lsmod output to the log.
        lsmod_output = process.system_output("lsmod", verbose=False)

        if linux_modules.parse_lsmod_for_module(lsmod_output, 'sysdig_probe') == {}:
            self.log.debug("Loading sysdig kernel module")
            process.run('sudo insmod {}/driver/sysdig-probe.ko'.format(self.falcodir))

        self.str_variant = self.trace_file

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

            level_line = '(?i){}: (\d+)'.format(self.detect_level)
            match = re.search(level_line, res.stdout)

            if match is None:
                self.fail("Could not find a line '{}: <count>' in falco output".format(self.detect_level))

            events_detected = int(match.group(1))

            if not events_detected > 0:
                self.fail("Detected {} events at level {} when should have detected > 0".format(events_detected, self.detect_level))

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
        cmd = '{}/userspace/falco/falco -r {} -c {}/../falco.yaml -e {} -o json_output={} -v'.format(
            self.falcodir, self.rules_file, self.falcodir, self.trace_file, self.json_output)

        self.falco_proc = process.SubProcess(cmd)

        res = self.falco_proc.run(timeout=180, sig=9)

        if res.exit_status != 0:
            self.error("Falco command \"{}\" exited with non-zero return value {}".format(
                cmd, res.exit_status))

        self.check_rules_warnings(res)
        if len(self.rules_events) > 0:
            self.check_rules_events(res)
        self.check_detections(res)
        self.check_json_output(res)
        pass


if __name__ == "__main__":
    main()
