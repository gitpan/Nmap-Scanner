package Nmap::Scanner::ProtocolList;

use Nmap::Scanner::Protocol;
use strict;

=pod

=head2 DESCRIPTION

Holds a list of Nmap::Scanner::Protocol
objects.  get_next() returns a protocol
reference while there are ports in
the list and returns undef when
the list is exhausted.

=cut

sub new {
    my $class = shift;
    my $me = { LISTREF => shift };

    my @keys = sort keys %{$me->{LISTREF}};
    $me->{KEYS} = \@keys;

    return bless $me, $class;
}

sub get_next {
    return $_[0]->{LISTREF}->{ shift @{$_[0]->{KEYS}} }
        if @{$_[0]->{KEYS}};
}

1;
