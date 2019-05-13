# == Class: falco::install
class falco::install inherits falco {
  package { 'falco':
    ensure => $::falco::package_ensure,
  }

  if ($::falco::file_output != undef) {
    logrotate::rule { 'falco_output':
      path          => $::falco::file_output[filename],
      rotate        => 5,
      rotate_every  => 'day',
      size          => '1M',
      missingok     => true,
      compress      => true,
      sharedscripts => true,
      postrotate    => '/usr/bin/killall -USR1 falco'
    }
  }
}
