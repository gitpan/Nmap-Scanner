#!/usr/bin/perl

use lib 'lib';

use Nmap::Scanner;

use strict;

my $scanner = new Nmap::Scanner;

$scanner->tcp_syn_scan();
$scanner->add_scan_port('22,80');
$scanner->ack_icmp_ping();
$scanner->guess_os();
$scanner->add_target($ARGV[0] || 'localhost');
$scanner->max_rtt_timeout(200);
$scanner->register_scan_complete_event(\&scan_complete);
$scanner->register_scan_started_event(\&scan_started);
$scanner->scan();

sub scan_complete {

    my $self = shift;
    my $host = shift;

    print "Finished scanning ", $host->name(),"\n";
    print "Host is of type: " . $host->os_guess(),"\n";
    print "Host has been up since " . $host->uptime_date(),"\n";

}

sub scan_started {
    my $self = shift;
    my $hostname = shift;
    my $ip       = shift;
    my $status   = shift;

    print "$hostname ($ip) is $status\n";

}
