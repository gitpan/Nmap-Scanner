#!/usr/bin/perl

use lib 'lib';
use Nmap::Scanner;
use strict;

do_web_scan();
do_ftp_scan();

sub do_web_scan {
    my $web = new Nmap::Scanner::Util::BannerScanner();

    $web->regex('Server:\s*(.+)$');
    $web->send_on_connect("HEAD / HTTP/1.0\r\n\r\n");
    $web->add_scan_port(80);
    $web->max_rtt_timeout(200);
    $web->add_target($ARGV[0] || 'localhost');
    $web->callback(\&banner);
    $web->scan();
}

sub do_ftp_scan {

    my $bs = new Nmap::Scanner::Util::BannerScanner();

    $bs->regex('^\d+ (.*)$');
    $bs->add_scan_port(21);
    $bs->max_rtt_timeout(200);
    $bs->add_target($ARGV[0] || 'localhost');
    $bs->callback(\&banner);
    $bs->scan();

}

sub banner {
    shift;
    my $host = shift;
    my $ip   = shift;
    my $msg  = shift;

    print "$host ($ip): $msg\n"

}
