#!/usr/bin/perl

use lib 'lib';
use Nmap::Scanner;
use strict;

my $scanner = new Nmap::Scanner;

$scanner->tcp_connect_scan();
$scanner->ident_check();
$scanner->add_scan_port(80);
$scanner->add_scan_port(25);
$scanner->add_scan_port(22);
$scanner->add_scan_port(21);
$scanner->ack_icmp_ping();
$scanner->add_target($ARGV[0] || 'localhost');
$scanner->max_rtt_timeout(200);
$scanner->register_port_found_event(\&found_port);
$scanner->scan();

sub found_port {

    shift;
    my $host = shift;
    my $port = shift;

    my $name = $host->name();
    my $ip   = join(',',map {$_->address()} $host->addresses());

    print "$name ($ip), port ",$port->number()," owned by ",
          $port->owner(),"\n";

}
