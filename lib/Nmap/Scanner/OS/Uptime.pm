package Nmap::Scanner::OS::Uptime;

=pod

=head1 NAME

Uptime - uptime for remote host (not always available)

=cut

use strict;

sub new {
    my $class = shift;
    my $me = { SECONDS => undef, LASTBOOT => undef };
    return bless $me, $class;
}

=pod

=head2 seconds()

Seconds up since last boot

=cut

sub seconds {
    (defined $_[1]) ? ($_[0]->{NAME} = $_[1]) : return $_[0]->{NAME};
}

=pod

=head2 last_boot()

Time/date of last boot

=cut

sub last_boot {
    (defined $_[1]) ? ($_[0]->{LASTBOOT} = $_[1]) : return $_[0]->{LASTBOOT};
}

sub as_xml {

    my $self = shift;

    my $xml  = "  <uptime";
       $xml .= ' seconds="'  . $self->seconds()  . '" ';
       $xml .= ' last-boot="' . $self->last_boot() . '" ';
       $xml .= "/>\n";

    return $xml;

}

1;
__END__;
