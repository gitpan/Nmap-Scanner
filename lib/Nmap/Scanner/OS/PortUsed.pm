package Nmap::Scanner::OS::PortUsed;

=pod

=head1 NAME

PortUsed - Port used for OS identification

=cut
use strict;

sub new {
    my $class = shift;
    my $me = { STATE => undef, PROTO => undef, PORTID => undef };
    return bless $me, $class;
}

=pod

=head2 state()

=cut

sub state {
    (defined $_[1]) ? ($_[0]->{STATE} = $_[1]) : return $_[0]->{STATE};
}

=pod

=head2 protocol()

=cut

sub protocol {
    (defined $_[1]) ? ($_[0]->{PROTO} = $_[1]) : return $_[0]->{PROTO};
}

=pod

=head2 port_id()

=cut

sub port_id {
    (defined $_[1]) ? ($_[0]->{PORTID} = $_[1]) : return $_[0]->{PORTID};
}

sub as_xml {

    my $self = shift;

    my $xml  = "  <port-used";
       $xml .= ' state="'  . $self->state()  . '" ';
       $xml .= ' protocol="' . $self->protocol() . '" ';
       $xml .= ' port-id="' . $self->port_id() . '" ';
       $xml .= "/>\n";

    return $xml;

}

1;
__END__;
