#!/usr/bin/perl

use lib 'lib';

use Nmap::Scanner;

use strict;

my $scanner = new Nmap::Scanner;

$scanner->protocol_scan();
$scanner->debug(1);
$scanner->add_target($ARGV[0] || 
                         die "Missing host to scan!\n$0 host\n");
my $results = $scanner->scan();

print $results->as_xml();
