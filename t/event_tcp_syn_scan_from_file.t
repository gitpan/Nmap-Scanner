#!/usr/bin/perl -w

use lib 'lib';
use Test;
use strict;
use Nmap::Scanner;
use constant FILE => 't/victor.xml';

BEGIN { plan tests => 3 }

my $scanner = Nmap::Scanner->new();
$scanner->debug(1);
my $scan = $scanner->scan_from_file(FILE);

ok($scan);

my $host = $scan->get_host_list()->get_next();
ok(sub { ($host->addresses())[0]->addr() ne "" });

my $aport = $host->get_port_list()->get_next();
ok($aport->portid());

1;
