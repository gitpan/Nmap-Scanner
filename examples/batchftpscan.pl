#!/usr/bin/perl

use lib 'lib';

use Nmap::Scanner;

my $ftp = new Nmap::Scanner::Util::FtpScanner($ARGV[0] || 'localhost');

print $ftp->scan->get_host_list->get_next()->name(),"\n";
