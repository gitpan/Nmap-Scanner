package Nmap::Scanner::Backend::Results;

use Nmap::Scanner::Host;
use Nmap::Scanner::HostList;
use Nmap::Scanner::Port;
use File::Spec;

use strict;

sub new {
    my $class = shift;
    my $you = {};
    return bless $you, $class;
}

sub debug {
    $_[0]->{'DEBUG'} = $_[1];
}

sub add_host {
    $_[0]->{HOSTS}->{$_[1]->ip()} = $_[1];
}

sub get_host {
    return $_[0]->{HOSTS}->{$_[1]};
}

sub get_all_hosts {
    return $_[0]->{HOSTS};
}

sub get_host_list {
    return new Nmap::Scanner::HostList($_[0]->{HOSTS});
}

1;
