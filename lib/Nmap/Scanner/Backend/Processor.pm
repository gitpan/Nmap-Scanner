package Nmap::Scanner::Backend::Processor;

=pod

=head1 NAME - Nmap::Scanner::Processor

This is the base class for output processors for Nmap::Scanner.  

=cut

use strict;

sub new {
    my $class = shift;
    my $you = {};
    return bless $you, $class;
}

=pod

=head1 register_scan_complete_event()

Use this to tell the backend processor you want
to be notified when the scan of a HOST is 
complete.  

Pass in a reference to a function that will
receive two arguments when called:  A reference
to the calling object and a reference to an
Nmap::Scanner::Host instance.

=cut

sub register_scan_complete_event {
    $_[0]->{'SCAN_COMPLETE_EVENT'} = $_[1];
}

=pod

=head1 register_scan_started_event()

Use this to tell the backend processor you want
to be notified when the scan of a HOST has
started.  

Pass in a reference to a function that will
receive two arguments when called:  A reference
to the calling object and a reference to an
Nmap::Scanner::Host instance.

=cut

sub register_scan_started_event {
    $_[0]->{'SCAN_STARTED_EVENT'} = $_[1];
}

=pod

=head1 register_host_closed_event()

Use this to tell the backend processor you want
to be notified when nmap has determined that the
current host is not available (up).

Pass in a reference to a function that will
receive two arguments when called:  A reference
to the calling object and a reference to an
Nmap::Scanner::Host instance.

=cut

sub register_host_closed_event {
    $_[0]->{'SCAN_STARTED_EVENT'} = $_[1];
}

=pod

=head1 register_port_found_event()

Use this to tell the backend processor you want
to be notified when an open port has been found
on the current host being scanned.

Pass in a reference to a function that will
receive three arguments when called:  A reference
to the calling object, a reference to an
Nmap::Scanner::Host instance, and a reference to
an Nmap::Scanner::Port containing information on
the port.

=cut

sub register_port_found_event {
    $_[0]->{'PORT_FOUND_EVENT'} = $_[1];
}

=pod

=head1 register_no_ports_open_event()

Use this to tell the backend processor you want
to be notified when the scan of a HOST has
yielded NO open ports.  

Pass in a reference to a function that will
receive three arguments when called:  A reference
to the calling object, a reference to an
Nmap::Scanner::Host instance, and a reference to
an Nmap::Scanner::ExtraPorts instance with some
information on the states of the non-open ports.

=cut

sub register_no_ports_open_event {
    $_[0]->{'NO_PORTS_OPEN_EVENT'} = $_[1];
}

=pod

=head1 results()

Return the Nmap::Scanner::Results instance
created by the scan.

=cut

sub results {
    (defined $_[1]) ? ($_[0]->{RESULTS} = $_[1]) : return $_[0]->{RESULTS};
}

sub debug {
    (defined $_[1]) ? ($_[0]->{DEBUG} = $_[1]) : return $_[0]->{DEBUG};
}

=pod

=head1 process()

This method is called on the sub-classed processor to tell it to
start processing output.  It is passed the command line arguments
to be used with nmap.

=cut

sub process {

    die "Interface only; define in sub-class!\n";

}

=pod

=head1 notify_scan_started()

Notify the listener that a scan started
event has occurred.  Caller is passed a
reference to the callers self reference
(object instance) and an Nmap::Scanner::Host
instance.

=cut

sub notify_scan_started {
    &{$_[0]->{'SCAN_STARTED_EVENT'}->[1]}(
        $_[0]->{'SCAN_STARTED_EVENT'}->[0], $_[1]
    ) if (defined $_[0]->{'SCAN_STARTED_EVENT'}->[1]);
}

=pod

=head1 notify_scan_started()

Notify the listener that a scan complete
event has occurred.  Caller is passed a
reference to the callers self reference
(object instance) and an Nmap::Scanner::Host
instance.

=cut

sub notify_scan_complete {
    &{$_[0]->{'SCAN_COMPLETE_EVENT'}->[1]}(
        $_[0]->{'SCAN_COMPLETE_EVENT'}->[0], $_[1]
    ) if (defined $_[0]->{'SCAN_COMPLETE_EVENT'}->[1]);
}

=pod

=head1 notify_scan_started()

Notify the listener that a port found
event has occurred.  Caller is passed a
reference to the callers self reference
(object instance), an Nmap::Scanner::Host
instance, and an Nmap::Scanner::Port
instance.

=cut

sub notify_port_found {
    &{$_[0]->{'PORT_FOUND_EVENT'}->[1]}(
        $_[0]->{'PORT_FOUND_EVENT'}->[0], $_[1], $_[2]
    ) if (defined $_[0]->{'PORT_FOUND_EVENT'}->[1]);
}

=pod

=head1 notify_no_ports_open()

Notify the listener that a scan started
event has occurred.  Caller is passed a
reference to the callers self reference
(object instance), an Nmap::Scanner::Host
instance, and an Nmap::Scanner::ExtraPorts
instance.

=cut

sub notify_no_ports_open {
    &{$_[0]->{'NO_PORTS_OPEN_EVENT'}->[1]}(
        $_[0]->{'NO_PORTS_OPEN_EVENT'}->[0], $_[1], $_[2]
    ) if (defined $_[0]->{'NO_PORTS_OPEN_EVENT'}->[0]);
}

1;
