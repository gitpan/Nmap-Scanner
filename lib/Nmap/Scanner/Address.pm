package Nmap::Scanner::Address;

use strict;

=pod

=head1 DESCRIPTION

This class represents an host address as represented by the scanning output from
nmap.

=cut

sub new {
    my $class = shift;
    my $me = {ADDR => '', ADDRTYPE => ''};
    return bless $me, $class;
}

=pod

=head2 addr()

=cut

sub addr {
    (defined $_[1]) ? ($_[0]->{ADDR} = $_[1]) : return $_[0]->{ADDR};
}

=pod

=head2 addrtype()

=cut

sub addrtype {
    (defined $_[1]) ? ($_[0]->{ADDRTYPE} = $_[1]) : return $_[0]->{ADDRTYPE};
}

sub as_xml {

    my $self = shift;

    return
        '<address addr="' . $self->addr() .
        '" addrtype="' . $self->addrtype() . '" />';

}

1;
