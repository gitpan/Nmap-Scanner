package Nmap::Scanner::OS;

=pod

=head1 DESCRIPTION

This class represents an nmap OS deduction as output by nmap.  It is
generally returned as part of a host object, and only so if guess_os() 
is used as an option with the Nmap::Scanner::Scanner instance.

=head1 PROPERTIES

=cut

use strict;
use Nmap::Scanner::OS::Match;
use Nmap::Scanner::OS::Class;
use Nmap::Scanner::OS::PortUsed;
use Nmap::Scanner::OS::Uptime;
use Nmap::Scanner::OS::TCPSequence;
use Nmap::Scanner::OS::TCPTSSequence;
use Nmap::Scanner::OS::IPIdSequence;

sub new {
    my $class = shift;
    my $me = { PORTSUSED    => [],  # Nmap::Scanner::OS::PortUsed array
               OSMATCHES    => [], 
               OSCLASSES    => [], 
               UPTIME       => Nmap::Scanner::OS::Uptime->new(),       
               TCPSEQUENCE  => Nmap::Scanner::OS::TCPSequence->new(),
               TCPTSEQUENCE => Nmap::Scanner::OS::TCPTSSequence->new(), 
               IPIDSEQUENCE => Nmap::Scanner::OS::IPIdSequence->new() 
              };
    return bless $me, $class;
}

=pod

=head2 ports_used()

The open ports used to try and fingerprint the remote OS.

=cut

sub ports_used {
    (defined $_[1]) ? ($_[0]->{PORTSUSED} = $_[1]) : return @{$_[0]->{PORTSUSED}};
}

=pod

=head2 add_port_used()

Add a port to the list of ports used to try and fingerprint the remote hosts' OS.

=cut

sub add_port_used {
    push(@{$_[0]->{PORTSUSED}}, $_[1]);
}

=pod

=head2 osmatches()

Object representing nmaps' best attempt to fingerprint the remote OS.

=cut

sub add_os_match {
    push(@{$_[0]->{OSMATCHES}}, $_[1]);
}

sub osmatches {
    return @{$_[0]->{OSMATCHES}};
}

sub add_os_class {
    push(@{$_[0]->{OSCLASSES}}, $_[1]);
}

sub osclasses {
    return @{$_[0]->{OSCLASSES}};
}

=pod

=head2 uptime

Object representing uptime/last reboot time for this host.  
This MAY be available if guess_os() is called on the 
Nmap::Scanner::Scanner reference.  Not available for all hosts.

=cut

sub uptime {
    (defined $_[1]) ? ($_[0]->{UPTIME} = $_[1]) : return $_[0]->{UPTIME};
}

sub tcpsequence {
    (defined $_[1]) ? ($_[0]->{TCPSEQUENCE} = $_[1]) : return $_[0]->{TCPSEQUENCE};
}

sub tcptssequence {
    (defined $_[1]) ? ($_[0]->{TCPTSSEQUENCE} = $_[1]) : return $_[0]->{TCPTSSEQUENCE};
}

sub ipidsequence {
    (defined $_[1]) ? ($_[0]->{IPIDSEQUENCE} = $_[1]) : return $_[0]->{IPIDSEQUENCE};
}

sub as_xml {

    my $self = shift;

    #  No fingerprinting happened if no ports found to fingerprint with.
    return unless scalar($self->ports_used()) > 0;

    my $xml = "<os>";

    for my $port ($self->ports_used()) {
        $xml .= $port->as_xml() . "\n";
    }

    for my $m ($self->osclasses()) {
        $xml .= $m->as_xml() . "\n";
    }

    for my $m ($self->osmatches()) {
        $xml .= $m->as_xml() . "\n";
    }

    $xml .= "</os>\n";

    $xml .= $self->uptime()->as_xml() . "\n"
        if $self->uptime()->seconds();

    $xml .= $self->tcpsequence()->as_xml() . "\n"
        if $self->tcpsequence()->class();

    $xml .= $self->tcptssequence()->as_xml() . "\n" 
        if $self->tcptssequence();

    $xml .= $self->ipidsequence()->as_xml() . "\n"
        if $self->ipidsequence()->class();

    return $xml;

}

1;
__END__;
