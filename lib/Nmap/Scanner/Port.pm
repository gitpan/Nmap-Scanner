package Nmap::Scanner::Port;

use strict;

=pod

=head1 Name

Port - Holds information about a remote port as detected by nmap.

=cut

sub new {
    my $class = shift;
    my $me = {
        PORTID => 0, PROTO => '', STATE => '', SERVICE => undef
    };
    return bless $me, $class;
}

=pod

=head2 portid()

Port number

=cut

sub portid {
    (defined $_[1]) ? ($_[0]->{PORTID} = $_[1]) : return $_[0]->{PORTID};
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

Protocol of the port, 'TCP' or 'UDP' for application level ports,
'BGP,' 'ICMP,' etc for protocol level ports.

=cut

sub protocol {
    (defined $_[1]) ? ($_[0]->{PROTO} = $_[1]) : return $_[0]->{PROTO};
}

=pod

=head2 state()

Textual representation of the state of the port: `open', `closed', 
`filtered', etc.

=cut

sub state {
    (defined $_[1]) ? ($_[0]->{STATE} = $_[1]) : return $_[0]->{STATE};
}

=pod

=head2 service()

Name of the service if known (Service reference)

=cut

sub service {
    (defined $_[1]) ? ($_[0]->{SERVICE} = $_[1]) : return $_[0]->{SERVICE};
}

sub as_xml {

    my $self = shift;

    my $service_xml = "";
    my $service = $self->service();

    $service_xml = $service->as_xml() if $service;

    my $xml  = '<port ';
       $xml .= 'protocol="' . $self->protocol() . '" ';
       $xml .= 'portid="' . $self->portid() . '" >';
       $xml .= 'owner="' . $self->owner()  . '" ' if $self->owner();
       $xml .= '<state state="' . $self->state() . '" />';
       $xml .= $service_xml;
       $xml .= '</port>';

    return $xml;
}

1;
