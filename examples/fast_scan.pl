#!/usr/bin/perl


use lib 'lib';

use Nmap::Scanner;

die "Missing nmap option string (.e.g -sS -P0 -F)"
    unless @ARGV;
print Nmap::Scanner->new()->scan(join(' ', @ARGV))->as_xml();
