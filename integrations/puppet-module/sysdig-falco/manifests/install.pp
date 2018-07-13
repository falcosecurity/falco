# == Class: falco::install
class falco::install inherits falco {
  package { 'falco':
      ensure => installed,
  }
}