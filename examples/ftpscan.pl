#!/usr/bin/perl

use lib 'lib';

use Nmap::Scanner;

my $ftp = Nmap::Scanner::Util::FtpScanner->new($ARGV[0] || 'localhost');
$ftp->callback(sub { shift; print "$_[0] ($_[1]): $_[2]\n"; });
$ftp->scan();
