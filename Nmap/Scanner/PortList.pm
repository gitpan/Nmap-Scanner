package Nmap::Scanner::PortList;

use Nmap::Scanner::Port;
use strict;

=pod

=head2 DESCRIPTION

Holds a list of Nmap::Scanner::Port
objects.  get_next() returns a port
reference while there are ports in
the list and returns undef when
the list is exhausted.

get_next_tcp() and get_next_udp() will
return the next port of either protocol;
get_next() returns first tcp then udp.

=cut

sub new {
    my $class = shift;
    my $me = { TCP => shift, UDP => shift };

    my @tcpkeys = sort { $a <=> $b } keys %{$me->{TCP}};
    my @udpkeys = sort { $a <=> $b } keys %{$me->{UDP}};
    $me->{UDPKEYS} = \@udpkeys;
    $me->{TCPKEYS} = \@tcpkeys;

    return bless $me, $class;
}

sub get_next_tcp {
    return $_[0]->{TCP}->{shift @{$_[0]->{TCPKEYS}}}
        if @{$_[0]->{TCPKEYS}};
}

sub get_next_udp {
    return $_[0]->{UDP}->{shift @{$_[0]->{UDPKEYS}}}
        if @{$_[0]->{UDPKEYS}};
}

sub get_next {
    return $_[0]->get_next_tcp() || $_[0]->get_next_udp();
}

1;
