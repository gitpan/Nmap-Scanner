#!/usr/bin/perl

use lib 'lib';

use Nmap::Scanner;

use strict;

my $scanner = new Nmap::Scanner;

$scanner->tcp_syn_scan();
#$scanner->debug(1);
$scanner->add_scan_port('22,80');
$scanner->ack_icmp_ping();
$scanner->guess_os();
$scanner->add_target($ARGV[0] || 'localhost');
$scanner->max_rtt_timeout(2000);
$scanner->register_scan_complete_event(\&scan_complete);
$scanner->register_scan_started_event(\&scan_started);
$scanner->scan();

sub scan_complete {

    my $self = shift;
    my $host = shift;

    print "Finished scanning ", $host->name(),"\n";

    for my $match ($host->os_guess()->os_matches()) {
        print "Host is of type: " . $match->name(),"\n";
        printf "Nmap is %d%% sure of this\n", $match->accuracy();
    }

    print "Host has been up since " . $host->os_guess->uptime()->last_boot()."\n"
            if defined $host->os_guess()->uptime->last_boot();

}

sub scan_started {
    my $self = shift;
    my $host = shift;

    my $hostname = $host->name();
    my $ip       = ($host->addresses)[0]->address();
    my $status   = $host->status;

    print "$hostname ($ip) is $status\n";

}
