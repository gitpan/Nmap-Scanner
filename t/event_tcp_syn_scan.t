#!/usr/bin/perl

use lib 'lib';

package MyScanner;

use lib 'lib';
use Nmap::Scanner;
use strict;

use vars qw(@ISA);

@ISA = qw(Nmap::Scanner::Scanner);

sub new {
    my $class = shift;
    my $self  = $class->SUPER::new();
    $self->register_scan_started_event(\&started);
    $self->register_port_found_event(\&port);
    return bless $self, $class;
}

sub started {
    die unless scalar(@_) == 4;
}

sub port {
    die unless scalar(@_) == 4;
}

1;

use Test;
use strict;

BEGIN { plan tests => 3 }

my $scan = MyScanner->new();

ok($scan);

$scan->add_target('localhost');
$scan->add_scan_port('1-1024');
$scan->tcp_syn_scan();

my $localhost = $scan->scan()->get_host_list()->get_next();
ok(sub { $localhost->name() ne "" });

my $aport = $localhost->get_port_list()->get_next();
ok($aport->number());

1;
