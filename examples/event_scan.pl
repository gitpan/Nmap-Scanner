#!/usr/bin/perl

use lib 'lib';

use Nmap::Scanner;

use strict;

my $scanner = new Nmap::Scanner;

$scanner->tcp_syn_scan();
$scanner->add_scan_port('21');
$scanner->ack_icmp_ping();
$scanner->guess_os();
$scanner->add_target($ARGV[0] || 'localhost');
$scanner->max_rtt_timeout(200);
$scanner->register_scan_complete_event(\&scan_complete);
$scanner->register_scan_started_event(\&scan_started);
$scanner->register_port_found_event(\&port_found);
$scanner->register_no_ports_open_event(\&no_ports);
$scanner->scan();

sub no_ports {
    my $self     = shift;
    my $hostname = shift;
    my $ip       = shift;
    my $state    = shift;

    print "All ports on $hostname ($ip) are in state $state\n";
}

sub scan_complete {

    my $self     = shift;
    my $host = shift;

    print "Finished scanning ", $host->name(),"\n";
    print "Host is of type: " . $host->os_guess(),"\n";
    print "Host has been up since " . $host->uptime_date(),"\n";

}

sub scan_started {
    my $self     = shift;
    my $hostname = shift;
    my $ip       = shift;
    my $status   = shift;

    print "$hostname ($ip) is $status\n";
}

sub port_found {
    my $self     = shift;
    my $hostname = shift;
    my $ip       = shift;
    my $port     = shift;

    print "On host $hostname ($ip), found ",
          $port->state()," port ",join('/',$port->protocol(),$port->number()),
          "\n";

}
