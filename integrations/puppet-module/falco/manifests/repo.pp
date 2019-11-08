# == Class: falco::repo
class falco::repo inherits falco {
  case $::osfamily {
    'Debian': {
      include apt::update

      Apt::Source [ 'sysdig' ]
      -> Class [ 'apt::update' ]

      apt::source { 'sysdig':
        location => 'http://download.draios.com/stable/deb',
        release  => 'stable-$(ARCH)/',
        repos    => '',
        key      => {
          source => 'https://s3.amazonaws.com/download.draios.com/DRAIOS-GPG-KEY.public',
          id     => 'D27A72F32D867DF9300A241574490FD6EC51E8C4'
        },
      }

      ensure_packages(["linux-headers-${::kernelrelease}"])
    }
    'RedHat': {
      include 'epel'

      Yumrepo [ 'sysdig' ]
      -> Class [ 'epel' ]

      yumrepo { 'sysdig':
        baseurl  => 'http://download.draios.com/stable/rpm/$basearch',
        descr    => 'Sysdig repository by Draios',
        enabled  => 1,
        gpgcheck => 0,
      }

      ensure_packages(["kernel-devel-${::kernelrelease}"])
    }
    default: {
      fail("\"${module_name}\" provides no repository information for OSfamily \"${::osfamily}\"")
    }
  }
}
