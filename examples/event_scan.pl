#!/usr/bin/perl

use lib 'lib';

use Nmap::Scanner;

use strict;

my $scanner = new Nmap::Scanner;

$scanner->tcp_syn_scan();
#$scanner->debug(1);
$scanner->add_scan_port($ARGV[1] || '21');
$scanner->ack_icmp_ping();
$scanner->guess_os();
$scanner->add_target($ARGV[0] || 'localhost');
$scanner->max_rtt_timeout(300);
$scanner->register_scan_complete_event(\&scan_complete);
$scanner->register_scan_started_event(\&scan_started);
$scanner->register_port_found_event(\&port_found);
$scanner->register_no_ports_open_event(\&no_ports);
$scanner->scan();

sub no_ports {
    my $self       = shift;
    my $host       = shift;
    my $extraports = shift;

    my $name = $host->name();
    my $addresses = join(',', map {$_->address()} $host->addresses());
    my $state = $extraports->state();

    print "All ports on host $name ($addresses) are in state $state\n";
}

sub scan_complete {
    my $self      = shift;
    my $host      = shift;

    print "Finished scanning ", $host->name(),"\n";
    my $guess = $host->os_guess();
    my @matches = $host->os_guess()->os_matches();

    if ($guess && @matches) {
        print "OS guesses:\n";
        for my $match (@matches) {
            print "    " . $match->name() . "/(". $match->accuracy() . "% sure)\n";
        }
        my $uptime = $guess->uptime;
        print "Host has been up since " . $uptime->last_boot(),"\n"
            if $uptime;
        my $t = $guess->tcp_sequence();
        print "TCP Sequence difficulty: " . $t->difficulty(),"\n"
            if $t;
    } else {
        print "Can't figure out what OS ",$host->name()," has.\n";
    }

}

sub scan_started {
    my $self     = shift;
    my $host     = shift;

    my $hostname = $host->name();
    my $addresses = join(',', map {$_->address()} $host->addresses());
    my $status = $host->status();

    print "$hostname ($addresses) is $status\n";
}

sub port_found {
    my $self     = shift;
    my $host     = shift;
    my $port     = shift;

    my $name = $host->name();
    my $addresses = join(',', map {$_->address()} $host->addresses());

    print "On host $name ($addresses), found ",
          $port->state()," port ",
          join('/',$port->protocol(),$port->number()),"\n";

}
