package Nmap::Scanner::RunStats;

=pod

=head1 DESCRIPTION

This class represents Nmap Summary/scan information.

=head1 PROPERTIES

=cut

use strict;

sub new {
    my $class = shift;
    my $me = { FINISHED => '', HOSTS => '' };
    return bless $me, $class;
}

=pod

=head2 finished()

=cut

sub finished {
    (defined $_[1]) ? ($_[0]->{FINISHED} = $_[1]) : return $_[0]->{FINISHED};
}

=pod

=head2 hosts()

=cut

sub hosts {
    (defined $_[1]) ? ($_[0]->{HOSTS} = $_[1]) : return $_[0]->{HOSTS};
}

sub as_xml {

    my $self = shift;

    my $xml = "<runstats>";
    $xml .= '<finished time="' . $self->finished() . "\" />\n";
    $xml .= $self->hosts()->as_xml() if $self->hosts();
    $xml .= "</runstats>\n";

    return $xml;

}

1;
__END__;