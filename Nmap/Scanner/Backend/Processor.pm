package Nmap::Scanner::Backend::Processor;

use strict;

sub new {
    my $class = shift;
    my $you = {};
    return bless $you, $class;
}

#  Function pointer that receives host object as argument
sub register_scan_complete_event {
    $_[0]->{'SCAN_COMPLETE_EVENT'} = $_[1];
}

#  Function pointer that receives host name, IP, and status
sub register_scan_started_event {
    $_[0]->{'SCAN_STARTED_EVENT'} = $_[1];
}

#  Function pointer that receives host name and IP address
sub register_host_closed_event {
    $_[0]->{'SCAN_STARTED_EVENT'} = $_[1];
}

#  Function pointer that receives host name, IP, and port object
sub register_port_found_event {
    $_[0]->{'PORT_FOUND_EVENT'} = $_[1];
}

#  Function pointer that receives host name, IP, and status of all ports
sub register_no_ports_open_event {
    $_[0]->{'NO_PORTS_OPEN_EVENT'} = $_[1];
}

sub results {
    (defined $_[1]) ? ($_[0]->{RESULTS} = $_[1]) : return $_[0]->{RESULTS};
}

sub debug {
    (defined $_[1]) ? ($_[0]->{DEBUG} = $_[1]) : return $_[0]->{DEBUG};
}

#  Process implemented in sub-classes
#  sub process {}

#  ARGS: hostname, ip, hoststatus
sub notify_scan_started {
    &{$_[0]->{'SCAN_STARTED_EVENT'}->[1]}(
        $_[0]->{'SCAN_STARTED_EVENT'}->[0],
        $_[1], $_[2], $_[3]
    ) if (defined $_[0]->{'SCAN_STARTED_EVENT'}->[1]);
}

#  ARGS: host object reference
sub notify_scan_complete {
    &{$_[0]->{'SCAN_COMPLETE_EVENT'}->[1]}(
        $_[0]->{'SCAN_COMPLETE_EVENT'}->[0],
        $_[1]
    ) if (defined $_[0]->{'SCAN_COMPLETE_EVENT'}->[1]);
}

#  ARGS: hostname, ip, port object reference
sub notify_port_found {
    &{$_[0]->{'PORT_FOUND_EVENT'}->[1]}(
        $_[0]->{'PORT_FOUND_EVENT'}->[0],
        $_[1], $_[2], $_[3]
    ) if (defined $_[0]->{'PORT_FOUND_EVENT'}->[1]);
}

#  ARGS: hostname, ip, status of ports
sub notify_no_ports_open {
    &{$_[0]->{'NO_PORTS_OPEN_EVENT'}->[1]}(
        $_[0]->{'NO_PORTS_OPEN_EVENT'}->[0],
        $_[1], $_[2], $_[3]
    ) if (defined $_[0]->{'NO_PORTS_OPEN_EVENT'}->[1]);
}

1;
