package Nmap::Scanner::NmapRun;

=pod

=head1 DESCRIPTION

This class represents Nmap Summary/scan information.

=head1 PROPERTIES

=cut

use strict;
use Nmap::Scanner::ScanInfo;
use Nmap::Scanner::RunStats;

sub new {
    my $class = shift;
    my $me = { 
               SCANINFO         => Nmap::Scanner::ScanInfo->new(),
               RUNSTATS         => Nmap::Scanner::RunStats->new(),
               SCANNER          => '',
               ARGS             => '',
               START            => '',
               STARTSTR         => '',
               VERSION          => '',
               XMLOUTPUTVERSION => 0,
               VERBOSE          => 0,
               DEBUGGING        => 0
             };
    return bless $me, $class;
}

=pod

=head2 scan_info()

=cut

sub scan_info {
    (defined $_[1]) ? ($_[0]->{SCANINFO} = $_[1]) : return $_[0]->{SCANINFO};
}

=pod

=head2 run_stats()

=cut

sub run_stats {
    (defined $_[1]) ? ($_[0]->{RUNSTATS} = $_[1]) : return $_[0]->{RUNSTATS};
}

=pod

=head2 scanner()

=cut

sub scanner {
    (defined $_[1]) ? ($_[0]->{SCANNER} = $_[1]) : return $_[0]->{SCANNER};
}

=pod

=head2 args()

Command line arguments used for this scan.

=cut

sub args {
    (defined $_[1]) ? ($_[0]->{ARGS} = $_[1]) : return $_[0]->{ARGS};
}

=pod

=head2 start()

Starting time for scan.

=cut

sub start {
    (defined $_[1]) ? ($_[0]->{START} = $_[1]) : return $_[0]->{START};
}

=pod

=head2 startstr()

Starting time for scan, ctime format

=cut

sub startstr {
    (defined $_[1]) ? ($_[0]->{STARTSTR} = $_[1]) : return $_[0]->{STARTSTR};
}

=pod

=head2 version()

Version of scanner used.

=cut

sub version {
    (defined $_[1]) ? ($_[0]->{VERSION} = $_[1]) : return $_[0]->{VERSION};
}

=pod

=head2 xmloutputversion()

=cut

sub xmloutputversion {
    (defined $_[1]) ? ($_[0]->{XMLOUTPUTVERSION} = $_[1]) 
                    : return $_[0]->{XMLOUTPUTVERSION};
}

=pod

=head2 verbose()

=cut

sub verbose {
    (defined $_[1]) ? ($_[0]->{VERBOSE} = $_[1]) : return $_[0]->{VERBOSE};
}

=pod

=head2 debugging()

=cut

sub debugging {
    (defined $_[1]) ? ($_[0]->{DEBUGGING} = $_[1]) : return $_[0]->{DEBUGGING};
}

sub as_xml {

    my $self = shift;
    my $hostlist = shift;

    # missing: verbose debugging
    my $xml = "<nmaprun";

    $xml .= ' scanner="' . $self->scanner() .  '"';
    $xml .= ' args="' . $self->args() . '"';
    $xml .= ' start="' . $self->start() . '"';
    $xml .= ' startstr="' . $self->startstr() . '"';
    $xml .= ' version="' . $self->version() . '"';
    $xml .= ' xmloutputversion="' . $self->xmloutputversion() . '"';
    $xml .= ">\n";

    $xml .= $self->scan_info()->as_xml();

    $xml .= '<verbose level="' . $self->verbose() . '" />'."\n";
    $xml .= '<debugging level="' . $self->debugging() . '" />'."\n";

    $xml .= $hostlist;

    $xml .= $self->run_stats()->as_xml();

    $xml .= "</nmaprun>\n";

    return $xml;

}

1;
__END__;
