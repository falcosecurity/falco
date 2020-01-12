# == Class falco::params
#
class falco::params {
  # Configuration parameters
  $rules_file = [
    '/etc/falco/falco_rules.yaml',
    '/etc/falco/falco_rules.local.yaml',
    '/etc/falco/k8s_audit_rules.yaml',
    '/etc/falco/rules.d',
  ]

  $json_output = false
  $json_include_output_property = true

  $log_stderr = true
  $log_syslog = true
  $log_level = 'info'
  $priority = 'debug'

  $buffered_outputs = false
  $outputs_rate = 1
  $outputs_max_burst = 1000

  $syslog_output = {
    'enabled' => true
  }
  $file_output = {
    'enabled'    => false,
    'keep_alive' => false,
    'filename'   => '/var/log/falco-events.log'
  }
  $stdout_output = {
    'enabled' => true
  }
  $webserver = {
    'enabled'            => false,
    'listen_port'        => 8765,
    'k8s_audit_endpoint' => '/k8s_audit',
    'ssl_enabled'        => false,
    'ssl_certificate'    => '/etc/falco/falco.pem'
  }
  $program_output = {
    'enabled'    => false,
    'keep_alive' => false,
    'program'    => 'curl http://some-webhook.com'
  }
  $http_output = {
    'enabled' => false,
    'url'     => 'http://some.url'
  }

  # Installation parameters
  $package_ensure = 'installed'

  # Service parameters
  $service_ensure = 'running'
  $service_enable = true
  $service_restart = true
}
