#!/usr/bin/perl

use lib 'lib';

use strict;

use Nmap::Scanner;

my $os = new Nmap::Scanner::Util::OsGuesser($ARGV[0] || 'localhost');
$os->callback(\&guessed);
$os->scan();

sub guessed {
    
    my $self = shift;
    my $name = shift;
    my $ip   = shift;
    my $os   = shift;
    my $days = shift;
    my $date = shift;

    print "$name ($ip) looks like $os\n";
    print "Uptime: $days ($date)\n";

}
