# == Class: falco::service
class falco::service inherits falco {

  service { 'falco':
    ensure     => running,
    enable     => true,
    hasstatus  => true,
    hasrestart => true,
    require => Package['falco'],
  }
}
