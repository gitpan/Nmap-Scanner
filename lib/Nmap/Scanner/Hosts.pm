package Nmap::Scanner::Hosts;

use strict;

=pod

=head1 DESCRIPTION

This class represents a hosts summary object as represented by the scanning output from
nmap.

=cut

sub new {
    my $class = shift;
    my $me = {UP => undef, DOWN => undef, TOTAL => undef};
    return bless $me, $class;
}

=pod

=head2 up()

number of hosts scanned that were reachable.

=cut

sub up {
    (defined $_[1]) ? ($_[0]->{UP} = $_[1]) : return $_[0]->{UP};
}

=pod

=head2 down()

number of hosts scanned that were not reachable.

=cut

sub down {
    (defined $_[1]) ? ($_[0]->{DOWN} = $_[1]) : return $_[0]->{DOWN};
}

=pod

=head2 total()

Total number of hosts scanned.

=cut

sub total {
    (defined $_[1]) ? ($_[0]->{TOTAL} = $_[1]) : return $_[0]->{TOTAL};
}

sub as_xml {

    my $self = shift;

    return
        '  <hosts '.
        'up="'   .  $self->up() .'" '.
        'down="' .  $self->down()  .'" '.
        'total="'   .  $self->total()  .'" '. '/>';

}

1;
