package Nmap::Scanner::Address;

use strict;

=pod

=head1 DESCRIPTION

This class represents an host address as represented by the scanning output from
nmap.

=cut

sub new {
    my $class = shift;
    my $me = {ADDRESS => undef, TYPE => undef};
    return bless $me, $class;
}

=pod

=head2 address()

=cut

sub address {
    (defined $_[1]) ? ($_[0]->{ADDRESS} = $_[1]) : return $_[0]->{ADDRESS};
}

=pod

=head2 type()

=cut

sub type {
    (defined $_[1]) ? ($_[0]->{TYPE} = $_[1]) : return $_[0]->{TYPE};
}

sub as_xml {

    my $self = shift;

    return
        '  <address address="' . $self->address() .
        '" type="'    .  $self->type()  .'"/>';

}

1;
