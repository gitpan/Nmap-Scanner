package Nmap::Scanner::Util::BannerScanner;

use IO::Socket;

use Nmap::Scanner::Scanner;
use strict;
use vars qw(@ISA);

@ISA = qw(Nmap::Scanner::Scanner);

sub new {
     my $class = shift;
     my $self = $class->SUPER::new();
     return bless $self, $class;
}

sub regex {
    (defined $_[1]) ? ($_[0]->{REGEX} = $_[1]) : return $_[0]->{REGEX};
}

sub send_on_connect {
    (defined $_[1]) ? ($_[0]->{SEND} = $_[1]) : return $_[0]->{SEND};
}

sub callback {
    (defined $_[1]) ? ($_[0]->{CALLBACK} = $_[1]) : return $_[0]->{CALLBACK};
}

sub scan {

    $_[0]->tcp_syn_scan();
    $_[0]->register_scan_complete_event(\&banner);
    $_[0]->SUPER::scan();

}

sub banner {
    my $self = shift;
    my $host = shift;
    my $port = $host->get_port_list->get_next();
    my $banner = get_banner(
        $host, $port, $self->{REGEX}, $self->{SEND}
    );

    &{$self->{CALLBACK}}($self, $host->name(), $host->ip(), $banner)
        if (ref($self->{'CALLBACK'}) eq 'CODE');
}

sub get_banner {

    my $host  = shift->ip();
    my $port  = shift->number();
    my $regex = shift || '.';
    my $send  = shift;

    my $server = "";
    local($_);

    my $sock = new IO::Socket::INET(
        PeerAddr => "$host:$port",
        Timeout  => 30
    );

    if (! $sock) {
        print "$host: can't connect: $!\n";
        return "";
    }

    if ($send) {
        $sock->print($send);
    }

    while (<$sock>) {
        if (/$regex/) {
            $server = $1;
            $server =~ s/\r\n//g;
            $sock->close();
            last;
        }
    }

    $sock->close();
    undef $sock;

    return $server;

}

1;
