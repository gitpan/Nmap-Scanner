package Nmap::Scanner::Host;

=pod

=head1 DESCRIPTION

This class represents a host as repsented by the output
of an nmap scan.

=head1 PROPERTIES

=cut

use Nmap::Scanner::Port;
use Nmap::Scanner::PortList;

use strict;

sub new {
    my $class = shift;
    my $me = { NAME => undef, ADDRESSES => [], PORTS => {} };
    return bless $me, $class;
}

=pod

=head2 name()

=cut

sub name {
    (defined $_[1]) ? ($_[0]->{NAME} = $_[1]) : return $_[0]->{NAME};
}

=pod

=head2 status()

Whether the host is reachable or not: `up' or `down'

=cut

sub status {
    (defined $_[1]) ? ($_[0]->{STATUS} = $_[1]) : return $_[0]->{STATUS};
}

=pod

=head2 addresses()

Addresses of the host as determined by nmap (Address references).

=cut

sub addresses {
    return @{$_[0]->{ADDRESSES}};
}

sub add_address {
    push(@{$_[0]->{ADDRESSES}}, $_[1]) if $_[1];
}

=pod

=head2 extra_ports()

Nmap::Scanner::ExtraPorts instance associated with this host.

=cut

sub extra_ports {
    my $self = shift;
    @_ ? $self->{EXTRA_PORTS} = shift
       : return $self->{EXTRA_PORTS};
}

=pod

=head2 os_guess()

holds a reference to an Nmap::Scanner::OS object that
describes the operating system and TCP fingerprint for this
host, as determined by nmap.  Only present if guess_os()
is called on the Nmap::Scanner::Scanner object AND nmap is
able to determine the OS type via TCP fingerprinting.  See the
nmap manual for more details.

=cut

sub os_guess {
    (defined $_[1]) ? ($_[0]->{OS} = $_[1]) : return $_[0]->{OS};
}

=pod

=head2 add_port($port_object_reference)

=cut

sub add_port {

    my $self = shift;
    my $port = shift;

    return unless defined $port;

    Nmap::Scanner::debug("Adding port with proto: " . $port->protocol());
    $self->{PORTS}->{lc($port->protocol())}->{$port->number()} = $port;
}

=pod

=head2 get_port($proto, $number)

Returns reference to requested port object.

=cut

sub get_port {
    return $_[0]->{PORTS}->{lc($_[1])}->{$_[2]}
        if $_[0]->{PORTS}->{lc($_[1])}->{$_[2]};
}

=pod

=head2 get_udp_port($number)

Returns reference to requested UDP port object.

=cut

sub get_udp_port {
    return $_[0]->{PORTS}->{'udp'}->{$_[1]}
        if $_[0]->{PORTS}->{'udp'}->{$_[1]};
}

=pod

=head2 get_tcp_port($number)

Returns reference to requested TCP port object.

=cut

sub get_tcp_port {
    return $_[0]->{PORTS}->{'tcp'}->{$_[1]}
        if $_[0]->{PORTS}->{'tcp'}->{$_[1]};
}

=pod

=head2 ENUMERATION METHODS

All these methods return lists of objects that
can be enumration through using a while loop.

my $ports = $host->get_port_list();

while (my $p = $ports->get_next()) {
    #  Do something with port reference here.
}

=head2 get_port_list()

=head2 get_ip_port_list()

=head2 get_tcp_port_list()

=head2 get_udp_port_list()

=cut

sub get_port_list {
    return new Nmap::Scanner::PortList(
        $_[0]->{PORTS}->{'tcp'}, $_[0]->{PORTS}->{'udp'}
    );
}

sub get_ip_port_list {
    return new Nmap::Scanner::PortList(undef, $_[0]->{PORTS}->{'ip'});
}

sub get_tcp_port_list {
    return new Nmap::Scanner::PortList($_[0]->{PORTS}->{'tcp'});
}

sub get_udp_port_list {
    return new Nmap::Scanner::PortList(undef, $_[0]->{PORTS}->{'udp'});
}

sub as_xml {

    my $self = shift;

    my $xml = 
        ' <host '.
        'name="' . $self->name() . '" '.
        'status="' . $self->status() . "\">\n";

    for my $addr ($self->addresses()) {
        $xml .=  "  " .$addr->as_xml() . "\n  ";
    }

    $xml .=  "  " .$self->os_guess()->as_xml() . "\n  "
        if defined $self->os_guess();

    $xml .= "  <ports>\n";

    $xml .= "    <tcp>\n";
    my $tcp_ports =  $self->get_tcp_port_list();
    $xml .= $tcp_ports->as_xml() . "\n" if defined $tcp_ports;
    $xml .= "    </tcp>\n";

    $xml .= "    <udp>\n";
    my $udp_ports =  $self->get_udp_port_list();
    $xml .= $udp_ports->as_xml() . "\n" if defined $udp_ports;
    $xml .= "    </udp>\n";



    $xml .= "    <ip>\n";
    my $protos =  $self->get_ip_port_list();
    $xml .= $protos->as_xml() . "\n" if defined $protos;
    $xml .= "    </ip>\n";
    $xml .= "    " . $self->extra_ports()->as_xml() ."\n"
                if defined $self->extra_ports();
    $xml .= "  </ports>\n";
    $xml .= "  </host>\n";

    return $xml;

}

1;
