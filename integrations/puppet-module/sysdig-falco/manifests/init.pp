class falco (
          $rules_file = [
              '/etc/falco/falco_rules.yaml',
              '/etc/falco/falco_rules.local.yaml'
          ],
          $json_output = 'false',
          $log_stderr = 'false',
          $log_syslog = 'true',
          $log_level = 'info',
          $priority = 'debug',
          $buffered_outputs = 'true',
          $outputs_rate = 1,
          $outputs_max_burst = 1000,
          $syslog_output = {
              'enabled' => 'true'
          },
          $file_output = {
              'enabled' => 'false',
              'keep_alive' => 'false',
              'filename' => '/tmp/falco_events.txt'
          },
          $program_output = {
              'enabled' => 'false',
              'keep_alive' => 'false',
              'program' => 'curl http://some-webhook.com'
          },
      ) {
  include falco::install
  include falco::config
  include falco::service
}
