# == Class: falco::config
class falco::config inherits falco {
  file { '/etc/falco/falco.yaml':
    ensure  => file,
    require => Class['falco::install'],
    notify  => Service['falco'],
    owner   => 'root',
    group   => 'root',
    mode    => '0644',
    content => template('falco/falco.yaml.erb'),
  }
}
