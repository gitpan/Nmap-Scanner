#!/usr/bin/perl

#
#  This program will search the local subnet (it tries to figure this out
#  on its own) for services listed in the state desired.
#
#  USAGE: whohas.pl port_spec state
#
#  Ex: whohas.pl smtp,http,https open
#

## PUT PATH TO YOUR NMAP SERVICES FILE HERE ##
my $NMAP_SERVICES='/usr/local/share/nmap/nmap-services';

use strict;
use lib 'lib';
use Nmap::Scanner;
use Socket;
use Net::DNS;
use Network::IPv4Addr qw(ipv4_network);
use File::Find;
use File::Spec;

my $USAGE = "$0 svc[,svc,svc...] open|closed|filtered";

my $SVCSPEC = $ARGV[0] || die $USAGE;
my $STATE    = $ARGV[1] || die $USAGE;

$STATE =~ m/open|closed|filtered/ || die "Invalid state $STATE\n$USAGE\n";

#  Find out our network and netmask ... what a pain this
#  was to do .. anyone know of easier ways to get this
#  in perl portably?

my $name = gethostbyaddr(inet_aton('127.0.0.1'), AF_INET);

my $res = new Net::DNS::Resolver;
my $query = $res->search("$name");
my $addr = '';

if ($name eq 'localhost') {
#  Find address for localhost on different IF
    print gethostbyname('');
}

if ($query) {
  foreach my $rr ($query->answer) {
     next unless $rr->type eq "A";
     $addr = $rr->address;
     last unless $addr eq '127.0.0.1';
  }
} else {
  print "query failed: ", $res->errorstring, "\n";
}

my ($net,$msk) = ipv4_network($addr);

my $scan = new Nmap::Scanner();

#
#  Try to turn service names into port numbers with 
#  nmap-services file.
#

$SVCSPEC = convert_to_ports($SVCSPEC);

print "Looking for hosts that have $SVCSPEC $STATE on $net/$msk\n";

$scan->tcp_syn_scan();
$scan->udp_scan();
$scan->use_interface('ppp0');
$scan->add_target("$net/$msk");
$scan->add_scan_port($SVCSPEC);


my $hosts = $scan->scan->get_host_list();

while (my $host = $hosts->get_next()) {


    my @ports;

    my $ports = $host->get_port_list();

    while (my $port = $ports->get_next()) {
        next unless lc($port->state()) eq $STATE;
        push(@ports, $port);
    }

    if (@ports) {
        print $host->hostname(),": ", 
              join(', ',sort map{join('/',
                                 $_->service()->name(),
                                 $_->protocol())} @ports),
              "\n";
    }

}

sub convert_to_ports {
    my @wants = split(',',$_[0]);

    local($_);

    return $_[0] if $_[0] =~ /^[\d,]+$/;

    my $file = $NMAP_SERVICES;

    unless (-r $file) {
        die "Can't find nmap-services file: please use NUMBERS only\n";
    }

    open(FILE,"< $file") || die "Can't read $file: $!\n";

    my @list;
    my @svcs;

    for my $svc (@wants) {
        if ($svc =~ /\d+/) {
            push(@list,$svc);
        } else {
            push(@svcs,$svc);
        }
    }

    while(<FILE>) {

        next if /^#/;

        my ($name, $portspec) = split(' ',$_);

        for my $svcname (@svcs) {
            if (uc($name) eq uc($svcname)) {
                my ($port,$proto) = split('/',$portspec);
                my $p;
                if ($proto =~ /^u/i) {
                    $p = 'U';
                } else {
                    $p = 'T';
                }
                push(@list,"$p:$port");
            } 
        }

    }

    close(FILE);

    return join(',',@list);

}
