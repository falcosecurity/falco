# == Class: falco::config
class falco::config inherits falco {

  file { '/etc/falco/falco.yaml':
    notify  => Service['falco'],
    ensure  => file,
    owner   => 'root',
    group   => 'root',
    mode    => '0644',
    content => template('falco/falco.yaml.erb'),
  }

}