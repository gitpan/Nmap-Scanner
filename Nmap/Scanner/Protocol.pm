package Nmap::Scanner::Protocol;

use strict;

=pod

=head2 DESCRIPTION

Represents a protocol as reported by the output of nmap.

=cut

sub new {
    my $class = shift;
    my $me = {
        NUMBER => undef, STATE => undef, NAME => undef
    };
    return bless $me, $class;
}

=pod

=head2 number()

=cut

sub number {
    (defined $_[1]) ? ($_[0]->{NUMBER} = $_[1]) : return $_[0]->{NUMBER};
}

=pod

=head2 state()

=cut

sub state {
    (defined $_[1]) ? ($_[0]->{STATE} = $_[1]) : return $_[0]->{STATE};
}

=pod

=head2 name()

=cut

sub name {
    (defined $_[1]) ? ($_[0]->{NAME} = $_[1]) : return $_[0]->{NAME};
}

1;
