#!/usr/bin/perl

use lib 'lib';

use Test;
use Nmap::Scanner;
use strict;

BEGIN { plan tests => 3 }

my $scan = Nmap::Scanner->new();

ok($scan);

$scan->add_target('localhost');
$scan->add_scan_port('1-1024');
$scan->tcp_syn_scan();

my $localhost = $scan->scan()->get_host_list()->get_next();
ok(sub { $localhost->name() ne '' });

my $aport = $localhost->get_port_list()->get_next();
ok($aport->number());
