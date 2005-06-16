#!/usr/bin/perl

#
#  This program will print a textual summary showing how many hosts have what
#  type of services on them.  It can take a while to run depending on how 
#  many hosts you are scanning.
#
#  USAGE: svcscan.pl host_spec port_spec
#
#  Ex: svcscan.pl 192.168.192.1-255 1-1024
#

use strict;
use lib 'lib';
use Nmap::Scanner;

my %HOSTS;
my %PORTS;

my $scan = new Nmap::Scanner();

$scan->debug(1);
$scan->tcp_syn_scan();
$scan->version_scan();
$scan->udp_scan();
$scan->add_target($ARGV[0] || 
                      die "Missing host to scan!\n$0 host ports\n");
$scan->add_scan_port($ARGV[1] || 
                      die "Missing ports to scan!\n$0 host ports\n");

my $hosts = $scan->scan()->get_host_list();

my $MAXLEN;

while (my $host = $hosts->get_next()) {

    $MAXLEN = length($host->hostname()) 
        if length($host->hostname()) > $MAXLEN;

    my $ports = $host->get_port_list();

    while (my $port = $ports->get_next()) {
        next unless lc($port->state()) eq 'open';
        my $key = join(':',$port->service()->name(),$port->portid(),$port->protocol,
                           $port->service()->product(),
                           $port->service()->version(),
                           $port->service()->extrainfo());
        $PORTS{$key}++;
        push(@{$HOSTS{$key}},$host->hostname());
    }

}

for my $svc (sort by_port_name keys %PORTS) {
    my ($n, $p, $proto, $product, $version, $extra) = split(':', $svc);
    print "\n$n ($p/$proto -- $product: $version [$extra]):\n";

    my $i = 0;
    
    print "\n";

    for my $name (sort @{$HOSTS{$svc}}) {
        ++$i;
        printf "    %-${MAXLEN}s", $name;
        if ($i == 2) {
            print "\n";
            $i = 0;
        }
    }
    print "\n";
}

sub by_port_name {
    my $porta = (split(':',$a))[0];
    my $portb = (split(':',$b))[0];

    $porta cmp $portb;
}
