#!/usr/bin/perl

package OsGuesser;

use Nmap::Scanner::Scanner;

use strict;
use vars qw(@ISA);

@ISA = qw(Nmap::Scanner::Scanner);

sub new {

    my $class = shift;
    my $self = $class->SUPER::new();

    $self->tcp_syn_scan();
    $self->add_scan_port('21,22,23,25,80');
    $self->guess_os();
    $self->add_target($_[0] || die "Need target in constructor!\n");
    $self->register_scan_complete_event(\&complete);

    return bless $self, $class;

}

sub scan {
    die "Need callback!\n" unless $_[0]->{'CALLBACK'};
    $_[0]->SUPER::scan();
}

sub callback {
    $_[0]->{'CALLBACK'} = $_[1] || return $_[0]->{'CALLBACK'};
}

sub complete {
    &{$_[0]->{'CALLBACK'}}($_[0], $_[1]);
}

1;

use lib 'lib';

use strict;

use Nmap::Scanner;

my $os = OsGuesser->new($ARGV[0] || 'localhost');
$os->callback(\&guessed);
$os->scan();

sub guessed {
    
    my $self = shift;
    my $host = shift;
    my $name = $host->name();
    my $ip   = ($host->addresses())[0]->address();
    my $os   = $host->os_guess();

    print "Used port ", $os->port_used()->port_id(), " for fingerprint\n";
    print "$name ($ip) looks like ",
        join('/',
            map { $_->name() . " (" . $_->accuracy() . "%)" } $os->os_matches()
        ),"\n";

    my $u = $os->uptime();

    if ($u->seconds() > 0) {
        print "Uptime: ", ($u->seconds()/(24*60*60)),
              " days (",$u->last_boot(),")\n";
    }

}
