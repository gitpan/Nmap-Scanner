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
use Nmap::Scanner::OS::PortUsed;
use Nmap::Scanner::OS::Uptime;
use Nmap::Scanner::OS::TCPSequence;
use Nmap::Scanner::OS::TCPTSSequence;
use Nmap::Scanner::OS::IPIdSequence;

sub new {
    my $class = shift;
    my $me = { PORTUSED     => Nmap::Scanner::OS::PortUsed->new(),     
               OSMATCHES    => [], 
               UPTIME       => Nmap::Scanner::OS::Uptime->new(),       
               TCPSEQUENCE  => Nmap::Scanner::OS::TCPSequence->new(),
               TCPTSEQUENCE => Nmap::Scanner::OS::TCPTSSequence->new(), 
               IPIDSEQUENCE => Nmap::Scanner::OS::IPIdSequence->new() 
              };
    return bless $me, $class;
}

=pod

=head2 port_used()

The open port used to try and fingerprint the remote OS.

=cut

sub port_used {
    (defined $_[1]) ? ($_[0]->{PORTUSED} = $_[1]) : return $_[0]->{PORTUSED};
}

=pod

=head2 os_matches()

Object representing nmaps' best attempt to fingerprint the remote OS.

=cut

sub add_os_match {
    push(@{$_[0]->{OSMATCHES}}, $_[1]);
}

sub os_matches {
    return @{$_[0]->{OSMATCHES}};
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

sub tcp_sequence {
    (defined $_[1]) ? ($_[0]->{TCPSEQUENCE} = $_[1]) : return $_[0]->{TCPSEQUENCE};
}

sub tcp_ts_sequence {
    (defined $_[1]) ? ($_[0]->{TCPTSSEQUENCE} = $_[1]) : return $_[0]->{TCPTSSEQUENCE};
}

sub ip_id_sequence {
    (defined $_[1]) ? ($_[0]->{IPIDSEQUENCE} = $_[1]) : return $_[0]->{IPIDSEQUENCE};
}

sub as_xml {

    my $self = shift;

    my $xml = "<osguess>\n";
    $xml .= "  " . $self->port_used()->as_xml() .  "\n";

    for my $m ($self->os_matches()) {
        $xml .= "  " . $m->as_xml() .  "\n";
    }

    $xml .= "  " . $self->uptime()->as_xml() .  "\n"
        if $self->uptime();
    $xml .= "  " . $self->tcp_sequence()->as_xml() .  "\n"
        if $self->tcp_sequence();
    $xml .= "  " . $self->tcp_ts_sequence()->as_xml() .  "\n" 
        if $self->tcp_ts_sequence();
    $xml .= "  " . $self->ip_id_sequence()->as_xml() .  "\n"
        if $self->ip_id_sequence();
    $xml .= "</osguess>\n";

    return $xml;

}

1;
__END__;
