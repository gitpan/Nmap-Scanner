#!/usr/bin/perl


use lib 'lib';

use Nmap::Scanner;

print Nmap::Scanner->new()->scan(join(' ',@ARGV))->as_xml();
