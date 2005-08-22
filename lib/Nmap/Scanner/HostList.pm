package Nmap::Scanner::HostList;

use Nmap::Scanner::Host;
use strict;

=pod

=head2 DESCRIPTION

Holds a list of Nmap::Scanner::Host
objects.  get_next() returns a host
reference while there are hosts in
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

=pod

=head2 get_next()

=cut

sub get_next {
    return $_[0]->{LISTREF}->{ shift @{$_[0]->{KEYS}} }
        if @{$_[0]->{KEYS}};
}

sub as_xml {

    my $self = shift;

    local($_);

    my $xml;

    while ($_ = $self->get_next()) {
        last unless defined $_;
        $xml .= $_->as_xml();
    }

    return $xml;

}

1;
