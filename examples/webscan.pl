#!/usr/bin/perl

use lib 'lib';
use Nmap::Scanner::Util::WebScanner;
use strict;

my $web = new Nmap::Scanner::Util::WebScanner($ARGV[0] || 'localhost');

$web->callback(sub { shift; print "$_[0] ($_[1]): $_[2]\n"; });
$web->scan();
