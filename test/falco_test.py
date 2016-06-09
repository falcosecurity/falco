#!/usr/bin/env python

import os
import re
import json

from avocado import Test
from avocado.utils import process
from avocado.utils import linux_modules

class FalcoTest(Test):

    def setUp(self):
        """
        Load the sysdig kernel module if not already loaded.
        """
        self.falcodir = self.params.get('falcodir', '/', default=os.path.join(self.basedir, '../build'))

        self.should_detect = self.params.get('detect', '*')
        self.trace_file = self.params.get('trace_file', '*')
        self.json_output = self.params.get('json_output', '*')

        if self.should_detect:
            self.detect_level = self.params.get('detect_level', '*')

        # Doing this in 2 steps instead of simply using
        # module_is_loaded to avoid logging lsmod output to the log.
        lsmod_output = process.system_output("lsmod", verbose=False)

        if linux_modules.parse_lsmod_for_module(lsmod_output, 'sysdig_probe') == {}:
            self.log.debug("Loading sysdig kernel module")
            process.run('sudo insmod {}/driver/sysdig-probe.ko'.format(self.falcodir))

        self.str_variant = self.trace_file

    def test(self):
        self.log.info("Trace file %s", self.trace_file)

        # Run the provided trace file though falco
        cmd = '{}/userspace/falco/falco -r {}/../rules/falco_rules.yaml -c {}/../falco.yaml -e {} -o json_output={}'.format(
            self.falcodir, self.falcodir, self.falcodir, self.trace_file, self.json_output)

        self.falco_proc = process.SubProcess(cmd)

        res = self.falco_proc.run(timeout=60, sig=9)

        if res.exit_status != 0:
            self.error("Falco command \"{}\" exited with non-zero return value {}".format(
                cmd, res.exit_status))

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

            level_line = '{}: (\d+)'.format(self.detect_level)
            match = re.search(level_line, res.stdout)

            if match is None:
                self.fail("Could not find a line '{}: <count>' in falco output".format(self.detect_level))

            events_detected = int(match.group(1))

            if not events_detected > 0:
                self.fail("Detected {} events at level {} when should have detected > 0".format(events_detected, self.detect_level))

        if self.json_output:
            # Just verify that any lines starting with '{' are valid json objects.
            # Doesn't do any deep inspection of the contents.
            for line in res.stdout.splitlines():
                if line.startswith('{'):
                    obj = json.loads(line)
                    for attr in ['time', 'rule', 'priority', 'output']:
                        if not attr in obj:
                            self.fail("Falco JSON object {} does not contain property \"{}\"".format(line, attr))
        pass


if __name__ == "__main__":
    main()
