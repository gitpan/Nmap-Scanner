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
    my $me = { ADDRESSES => [], 
               PORTS => {}, 
               SMURF => 0,
               HOSTNAMES => []  # Nmap::Scanner::Hostname
    };
    return bless $me, $class;
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

=pod

=head2 add_hostname()

Add an address to the list of addresses for this host

=cut

sub add_address {
    push(@{$_[0]->{ADDRESSES}}, $_[1]) if $_[1];
}

=pod

=head2 hostname()

First hostname of the host as determined by nmap (single hostname string).

=cut

sub hostname {

    # this returns the first hostname
    return @{$_[0]->{HOSTNAMES}}[0]->name() if @{$_[0]->{HOSTNAMES}};

    return "";

}

=head2 hostnames()

Hostnames of the host as determined by nmap (Array of Address references).

=cut
sub hostnames {
    return @{$_[0]->{HOSTNAMES}};
}

=pod

=head2 add_hostname()

Add a hostname to the list of hostnames for this host

=cut

sub add_hostname {
    push(@{$_[0]->{HOSTNAMES}}, $_[1]) if $_[1];
}

=head2 smurf()

    True (1) if the host responded to a ping of a broadcast address and
    is therefore vulnerable to a Smurf-style attack.

=cut

sub smurf {
    (defined $_[1]) ? ($_[0]->{SMURF} = $_[1]) : return $_[0]->{SMURF};
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

=head2 os()

holds a reference to an Nmap::Scanner::OS object that
describes the operating system and TCP fingerprint for this
host, as determined by nmap.  Only present if guess_os()
is called on the Nmap::Scanner::Scanner object AND nmap is
able to determine the OS type via TCP fingerprinting.  See the
nmap manual for more details.

=cut

sub os {
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
    $self->{PORTS}->{lc($port->protocol())}->{$port->portid()} = $port;
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
 
    my $xml =  '<host>';
    $xml .= '<status state="' . $self->status() . '" />'."\n";
  
    for my $addr ($self->addresses()) {
        $xml .= $addr->as_xml() . "\n";
    }

    $xml .= '<smurf responses="' . $self->smurf().'" />'."\n" if $self->smurf() > 0;

    my $hxml = '';
    foreach ($self->hostnames()) {
        $hxml.=$_->as_xml() 
    } 
    $xml .= "<hostnames>". $hxml ."</hostnames>\n" if $hxml;
  
    $xml .= $self->os()->as_xml() . "\n"
                if $self->os();
  
                

    my $pxml .= $self->extra_ports()->as_xml() ."\n"
                if $self->extra_ports();
  
    my $tcp_ports = $self->get_tcp_port_list();
    $pxml .= $tcp_ports->as_xml();
  
    my $udp_ports = $self->get_udp_port_list();
    $pxml .= $udp_ports->as_xml();
  
    my $protos = $self->get_ip_port_list();
    $pxml .= $protos->as_xml();
    
    $xml .= "<ports>". $pxml ."</ports>\n" if $pxml;

    $xml .= "</host>\n";
  
    return $xml;
  
}

1;
