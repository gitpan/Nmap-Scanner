package Nmap::Scanner::Backend::Normal;

use vars qw(@ISA);

use Nmap::Scanner::Factory::Normal;
use Nmap::Scanner::Backend::Results;
use Nmap::Scanner::Backend::Processor;

use strict;

@ISA = qw(Nmap::Scanner::Backend::Processor);

sub new {
    my $class = shift;
    my $you = $class->SUPER::new();
    return bless $you, $class;
}

#  Process results from "-oN -"

sub process {
    
    my $this = shift;
    my $cmdline = shift;
    my $results = new Nmap::Scanner::Backend::Results();

    local($_);
    local(*NMAP);

    open(NMAP,"$cmdline |") || die "Can't run $cmdline: $!\n";

    my $hoststatus;
    my $hostname;
    my $ip;

    while (<NMAP>) {

        print "NMAP: $_" if $this->debug();

        my @hostlines;

        TOP:

        if (/Host (?:(\S+))? \(([^)]+)\) \S+ to be (\w+)/) {

            print "HOST: $_" if $this->debug();

            $hostname = $1;
            $ip       = $2;
            $hoststatus = $3;

            $hostname = $ip unless $hostname;

            $this->notify_scan_started($hostname, $ip, $hoststatus);
        }

        if (/Adding (\S+) port (\d+)\/(\S+)\s*(?:\(owner: (\w+)\))?/) {
            my $foundport = new Nmap::Scanner::Port();
            $foundport->state($1);
            $foundport->number($2);
            $foundport->protocol($3);
            $foundport->owner($4) if $4;

            $this->notify_port_found($hostname, $ip, $foundport);
        }

        if (/\S+ \d+ \S+ \S+ on (?:\S+) \([^)]+\) are: (\S+)/) {
            $this->notify_no_ports_open($hostname, $ip, $1);
        }

        next unless /Interesting/;

        push(@hostlines, $_);

        while (($_ = <NMAP>)) {
            last if /^\s*$/;
            print "PORTS: $_" if $this->debug();
            push(@hostlines, $_);
        }

        $_ = <NMAP>;

        goto TOP if /Host/;

        if (/Remote/) {

            do {
                print "DETECT: $_" if $this->{'DEBUG'};
                push(@hostlines, $_) unless /^\s*$/;
                $_ = <NMAP>;
            } while (!/^IPID/);

        }

        my $newhost = Nmap::Scanner::Factory::Normal::host(@hostlines);

        $this->notify_scan_complete($newhost);

        $newhost->status($hoststatus);
        $results->add_host($newhost);

        $hoststatus = "";
        $hostname = "";
        $ip = "";

    }

    close(NMAP);

    return $results;

}

1;
