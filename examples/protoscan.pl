#!/usr/bin/perl

use lib 'lib';

use Nmap::Scanner;

use strict;

my $scanner = new Nmap::Scanner;

$scanner->protocol_scan();
$scanner->add_target($ARGV[0] || 'localhost');
$scanner->register_scan_complete_event(\&scan_done);
$scanner->scan();

sub scan_done {

    shift;
    my $host = shift;

    print $host->name()," -- ";

    my $list = $host->get_protocol_list();
    while (my $p = $list->get_next()) {
        print join(':',
            $p->number(),$p->name(),$p->state()
        ) . " ";
    }
    print "\n";

}
