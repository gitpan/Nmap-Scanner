package Nmap::Scanner::Host;

=pod

=head1 DESCRIPTION

This class represents a host as repsented by the output
of an nmap scan.

=head1 PROPERTIES

=cut

use Nmap::Scanner::Port;
use Nmap::Scanner::PortList;
use Nmap::Scanner::ProtocolList;

use strict;

sub new {
    my $class = shift;
    my $me = { NAME => undef, IP => undef, PORTS => {} };
    return bless $me, $class;
}

=pod

=head2 name()

This may be the same value as ip() if the name does not
resolve using DNS or if DNS lookups have been turned off
for nmap.

=cut

sub name {
    (defined $_[1]) ? ($_[0]->{NAME} = $_[1]) : return $_[0]->{NAME};
}

=pod

=head2 status()

Whether the host is reachable or not: `up' or `down'

=cut

sub status {
    (defined $_[1]) ? ($_[0]->{STATUS} = $_[1]) : return $_[0]->{STATUS};
}

=pod

=head2 ip()

IP address of the host as determined by nmap.

=cut

sub ip {
    (defined $_[1]) ? ($_[0]->{IP} = $_[1]) : return $_[0]->{IP};
}

=pod

=head2 os_guess()

String representing the name/version of the operating system
of the host, as determined by nmap.  Only present if guess_os()
is called on the Nmap::Scanner::Scanner object AND nmap is
able to determine the OS type via TCP fingerprinting.  See the
nmap manual for more details.

=cut

sub os_guess {
    (defined $_[1]) ? ($_[0]->{OS} = $_[1]) : return $_[0]->{OS};
}


=pod

=head2 uptime_days()

Days since the last reboot for this host.  This MAY be available
if guess_os() is called on the Nmap::Scanner::Scanner reference.
Not available for all hosts.

=cut

sub uptime_days {
    (defined $_[1]) ? 
        ($_[0]->{UPTIME_DAYS} = $_[1]) : return $_[0]->{UPTIME_DAYS};
}

=pod

=head2 uptime_date()

Date of the last reboot for this host.  This MAY be available
if guess_os() is called on the Nmap::Scanner::Scanner reference.
Not available for all hosts.

=cut

sub uptime_date {
    (defined $_[1]) ? 
        ($_[0]->{UPTIME_DATE} = $_[1]) : return $_[0]->{UPTIME_DATE};
}

=pod

=head2 add_port($port_object_reference)

=cut

sub add_port {
    $_[0]->{PORTS}->{lc($_[1]->protocol())}->{$_[1]->number()} = $_[1]
        if (defined $_[1]);
}

=pod

=head2 add_protocol($protocol_object_reference)

=cut

sub add_protocol {
    (defined $_[1]) ? ($_[0]->{PROTOS} = $_[1]) : return $_[0]->{PROTOS};
}

=pod

=head2 get_port($proto, $number)

Returns reference to requested port object.

=cut

sub get_port {
    return $_[0]->{PORTS}->{lc($_[1])}->{$_[2]}
        if $_[0]->{PORTS}->{lc($_[1])}->{$_[2]};
}

=pod

=head2 get_udp_port($number)

Returns reference to requested UDP port object.

=cut

sub get_udp_port {
    return $_[0]->{PORTS}->{'udp'}->{$_[1]}
        if $_[0]->{PORTS}->{'udp'}->{$_[1]};
}

=pod

=head2 get_tcp_port($number)

Returns reference to requested TCP port object.

=cut

sub get_tcp_port {
    return $_[0]->{PORTS}->{'tcp'}->{$_[1]}
        if $_[0]->{PORTS}->{'tcp'}->{$_[1]};
}

=pod

=head2 ENUMERATION METHODS

All these methods return lists of objects that
can be enumration through using a while loop.

my $ports = $host->get_port_list();

while (my $p = $ports->get_next()) {
    #  Do something with port reference here.
}

=head2 get_port_list()

=head2 get_protocol_list()

=head2 get_tcp_port_list()

=head2 get_udp_port_list()

=cut

sub get_port_list {
    return new Nmap::Scanner::PortList(
        $_[0]->{PORTS}->{'tcp'}, $_[0]->{PORTS}->{'udp'}
    );
}

sub get_protocol_list {
    return new Nmap::Scanner::ProtocolList($_[0]->{PROTOS});
}

sub get_tcp_port_list {
    return new Nmap::Scanner::PortList($_[0]->{PORTS}->{'tcp'});
}

sub get_udp_port_list {
    return new Nmap::Scanner::PortList(undef, $_[0]->{PORTS}->{'udp'});
}

1;
