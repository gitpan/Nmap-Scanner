#!/usr/bin/perl

use lib 'lib';

use Nmap::Scanner;

use strict;

my $scanner = new Nmap::Scanner;

$scanner->tcp_syn_scan();
$scanner->udp_scan();
$scanner->add_scan_port('21,25,80,443,3306,8080,22,79,13,11,7,10');
$scanner->ack_icmp_ping();
$scanner->guess_os();
$scanner->add_target($ARGV[0] || 'localhost');
$scanner->max_rtt_timeout(200);
my $results = $scanner->scan();

print $results->as_xml();
