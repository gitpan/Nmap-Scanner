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

=head2 proto()

=cut

sub proto {
    (defined $_[1]) ? ($_[0]->{PROTO} = $_[1]) : return $_[0]->{PROTO};
}

=pod

=head2 portid()

=cut

sub portid {
    (defined $_[1]) ? ($_[0]->{PORTID} = $_[1]) : return $_[0]->{PORTID};
}

sub as_xml {

    my $self = shift;

    my $xml  = "<portused";
       $xml .= ' state="'  . $self->state()  . '" ';
       $xml .= ' proto="' . $self->proto() . '" ';
       $xml .= ' portid="' . $self->portid() . '" ';
       $xml .= "/>";

    return $xml;

}

1;
__END__;
