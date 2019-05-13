# == Class: falco
class falco (
  # Configuration parameters
  $rules_file                   = $falco::params::rules_file,
  $json_output                  = $falco::params::json_output,
  $json_include_output_property = $falco::params::json_include_output_property,

  $log_stderr                   = $falco::params::log_stderr,
  $log_syslog                   = $falco::params::log_syslog,
  $log_level                    = $falco::params::log_level,
  $priority                     = $falco::params::priority,

  $buffered_outputs             = $falco::params::buffered_outputs,
  $outputs_rate                 = $falco::params::outputs_rate,
  $outputs_max_burst            = $falco::params::outputs_max_burst,

  $syslog_output                = $falco::params::syslog_output,
  $file_output                  = $falco::params::file_output,
  $stdout_output                = $falco::params::stdout_output,
  $webserver                    = $falco::params::webserver,
  $program_output               = $falco::params::program_output,
  $http_output                  = $falco::params::http_output,

  # Installation parameters
  $package_ensure               = $falco::params::package_ensure,

  # Service parameters
  $service_ensure               = $falco::params::service_ensure,
  $service_enable               = $falco::params::service_enable,
  $service_restart              = $falco::params::service_restart,
) inherits falco::params {

  class { 'falco::repo': }
  -> class { 'falco::install': }
  -> class { 'falco::config': }
  ~> class { 'falco::service': }

  contain falco::install
  contain falco::config

}
