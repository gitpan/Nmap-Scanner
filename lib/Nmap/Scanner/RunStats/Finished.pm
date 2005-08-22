package Nmap::Scanner::RunStats::Finished;

=pod

=head1 DESCRIPTION

This class represents Nmap scan time finishing information

=head1 PROPERTIES

=cut

use strict;

sub new {
    my $class = shift;
    my $me = { TIME => '', TIMESTR => '' };
    return bless $me, $class;
}

=pod

=head2 time() - when scan finished, in seconds since the epoch

=cut

sub time {
    (defined $_[1]) ? ($_[0]->{TIME} = $_[1]) : return $_[0]->{TIME};
}

=pod

=head2 timestr() - ctime representation of finish time

=cut

sub timestr {
    (defined $_[1]) ? ($_[0]->{TIMESTR} = $_[1]) : return $_[0]->{TIMESTR};
}

sub as_xml {

    my $self = shift;

    my $xml = '<finished time="' . $self->time . '" timestr="' . 
                                   $self->timestr . "\" />\n";

    return $xml;

}

1;
__END__;
