#!/usr/bin/perl

use lib 'lib';

use Nmap::Scanner;

use strict;

my $scanner = new Nmap::Scanner;

$scanner->ping_scan();
$scanner->ack_icmp_ping();
$scanner->add_target($ARGV[0] || 'localhost');
$scanner->register_scan_started_event(\&scan_started);
$scanner->scan();

sub scan_started {
    shift;
    my $hostname = shift;
    my $ip       = shift;
    my $status   = shift;

    print "$hostname ($ip) is $status\n";

}
