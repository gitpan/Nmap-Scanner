package Nmap::Scanner::Port;

use strict;

=pod

=head1 DESCRIPTION

This class represents a port as represented by the scanning output from
nmap.

=cut

sub new {
    my $class = shift;
    my $me = {
        NUMBER => undef, PROTO => undef, STATE => undef, SERVICE => undef
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

=head2 owner()

If ident scan was performed and succeeded, this will contain
the username the service on the port runs as.

=cut

sub owner {
    (defined $_[1]) ? ($_[0]->{OWNER} = $_[1]) : return $_[0]->{OWNER};
}

=pod

=head2 protocol()

=cut

sub protocol {
    (defined $_[1]) ? ($_[0]->{PROTO} = $_[1]) : return $_[0]->{PROTO};
}

=pod

=head2 state()

Textual representation of the state: `open', `closed', 
`filtered', etc.

=cut

sub state {
    (defined $_[1]) ? ($_[0]->{STATE} = $_[1]) : return $_[0]->{STATE};
}

=pod

=head2 service()

Name of the service if known.

=cut

sub service {
    (defined $_[1]) ? ($_[0]->{SERVICE} = $_[1]) : return $_[0]->{SERVICE};
}

1;
