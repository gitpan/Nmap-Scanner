package Nmap::Scanner::Util::WebScanner;

use strict;
use Nmap::Scanner::Util::BannerScanner;
use vars qw(@ISA);

@ISA = qw(Nmap::Scanner::Util::BannerScanner);

sub new {

    my $class = shift;
    my $self = $class->SUPER::new();

    $self->regex('Server:\s*(.+)$');
    $self->send_on_connect("HEAD / HTTP/1.0\r\n\r\n");
    $self->add_scan_port(80);
    $self->add_scan_port(8080);
    $self->add_target($_[0] || die "Need target in constructor!\n");

    return bless $self, $class;

}

1;
