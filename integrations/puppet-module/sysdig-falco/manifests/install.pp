# == Class: falco::install
class falco::install inherits falco {
  case $::osfamily {
    'Debian': {
      apt::source { 'sysdig':
        location          => 'http://download.draios.com/stable/deb',
        release           => 'stable-$(ARCH)/',
        repos             => '',
        required_packages => 'debian-keyring debian-archive-keyring',
        key               => 'EC51E8C4',
        key_source        => 'https://s3.amazonaws.com/download.draios.com/DRAIOS-GPG-KEY.public',
        include_src       => false,
      }

      ensure_packages(["linux-headers-${::kernelrelease}"])

      $dependencies = [
        Apt::Source['sysdig'],
        Package["linux-headers-${::kernelrelease}"],
      ]
    }
    'RedHat': {
      include 'epel'

      yumrepo { 'sysdig':
        baseurl  => 'http://download.draios.com/stable/rpm/$basearch',
        descr    => 'Sysdig repository by Draios',
        enabled  => 1,
        gpgcheck => 0,
      }

      ensure_packages(["kernel-devel-${::kernelrelease}"])

      $dependencies = [
        Yumrepo['sysdig'],
        Class['epel']
      ]
    }
    default: {
      $dependencies = []
    }
  }

  package { 'falco':
    ensure  => $::falco::package_ensure,
    require => $dependencies,
  }

  if ($::falco::file_output != undef) {
    logrotate::rule { 'falco_output':
      path          => $::falco::file_output['filename'],
      rotate        => '5',
      rotate_every  => 'day',
      size          => '1M',
      missingok     => true,
      compress      => true,
      sharedscripts => true,
      postrotate    => '/usr/bin/killall -USR1 falco'
    }
  }
}
