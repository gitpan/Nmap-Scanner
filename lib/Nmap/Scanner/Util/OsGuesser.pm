package Nmap::Scanner::Util::OsGuesser;

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
    &{$_[0]->{'CALLBACK'}}(
        $_[0],
        $_[1]->name(),
        $_[1]->ip(),
        $_[1]->os_guess(),
        $_[1]->uptime_days(),
        $_[1]->uptime_date()
    );
}

1;
