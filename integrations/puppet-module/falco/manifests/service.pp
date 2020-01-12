# == Class: falco::service
class falco::service inherits falco {
  validate_bool($falco::service_enable)

  case $falco::service_ensure {
    true, false, 'running', 'stopped': {
      $_service_ensure = $falco::service_ensure
    }
    default: {
      $_service_ensure = undef
    }
  }

  service { 'falco':
    ensure     => $_service_ensure,
    enable     => $falco::service_enable,
    hasstatus  => true,
    hasrestart => $falco::service_restart,
  }
}
