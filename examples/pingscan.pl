#!/usr/bin/perl

use lib 'lib';

use Nmap::Scanner;

my $p = new Nmap::Scanner::Util::PingScanner($ARGV[0] || 'localhost');
$p->callback(sub{ shift; print "$_[0] ($_[1]): $_[2]\n"; });
$p->scan();
