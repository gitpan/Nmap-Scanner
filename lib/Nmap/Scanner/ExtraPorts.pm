package Nmap::Scanner::ExtraPorts;

use strict;

=pod

=head1 DESCRIPTION

This class holds information on ports found to be not
open on a host.

=cut

sub new {
    my $class = shift;
    my $me = {STATE => '', COUNT => ''};
    return bless $me, $class;
}

=pod

=head2 state()

State of the non-open ports: 'closed' or 'filtered.'

=cut

sub state {
    (defined $_[1]) ? ($_[0]->{STATE} = $_[1]) : return $_[0]->{STATE};
}

=pod

=head2 count()

Number of non-open ports found.

=cut

sub count {
    (defined $_[1]) ? ($_[0]->{COUNT} = $_[1]) : return $_[0]->{COUNT};
}

sub as_xml {

    my $self = shift;

    return
        '<extraports '.
        'state="' . $self->state() . '" ' .
        'count="' . $self->count() . '" />';

}

1;
