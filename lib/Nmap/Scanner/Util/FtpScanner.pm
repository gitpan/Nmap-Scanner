package Nmap::Scanner::Util::FtpScanner;

use strict;
use Nmap::Scanner::Util::BannerScanner;
use vars qw(@ISA);

@ISA = qw(Nmap::Scanner::Util::BannerScanner);

sub new {

    my $class = shift;
    my $self  = $class->SUPER::new();

    $self->regex('^\d+ (.*)$');
    $self->add_scan_port(21);
    $self->add_target($_[0] || die "Need target in constructor!\n");

    return bless $self, $class;
}

1;
