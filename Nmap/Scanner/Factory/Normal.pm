package Nmap::Scanner::Factory::Normal;

use strict;

use Nmap::Scanner::Host;
use Nmap::Scanner::Port;
use Nmap::Scanner::Protocol;

sub new {
    my $class = shift;
    my $me = {};
    return bless $me, $class;
}

sub host {

    my @lines = @_;

    local($_);

    my $host = new Nmap::Scanner::Host();

    for (@lines) {
        chomp();

        last if /^\s*$/;

        if (/Interesting /) {
            my ($name,$ip) = (split(' ',$_))[3,4];
            if (! $ip) {
                next unless $name;
                $ip = $name;
                $name = "";
            }
            $ip =~ s/[():]+//g;
            $name = $ip unless $name;
            $host->ip($ip);
            $host->name($name);
            next;
         }

         if (m#\d+/\S+\s+\S+\s+\S+#) {
             my $port = port($_);
             $host->add_port($port);
             next;
         }

         if (m#^\d+\s+\S+\s+\S+\s*$#) {
             my $protocol = protocol($_);
             $host->add_protocol($protocol);
             next;
         }

         if (/Remote operating system guess: (.+)$/) {
             $host->os_guess($1);
             next;
         }

         if (/Uptime (\d+\.?\d+) days \(since ([^)]+)\)/) {
             $host->uptime_days($1);
             $host->uptime_date($2);
             next;
         }

    }

    return $host;

}

sub port {
    my $line = shift;

    chomp($line);
    my ($port_proto, $state, $service, $owner) = split(' ', $line);

    my ($port, $proto) = split('/', $port_proto);

    return undef unless ($port && $proto && $state && $service);

    my $p = new Nmap::Scanner::Port();

    $p->number($port);
    $p->protocol($proto);
    $p->state($state);
    $p->service($service);
    $p->owner($owner);

    return $p;

}

sub protocol {
    my $line = shift;

    chomp($line);
    my ($number, $state, $name) = split(' ', $line);

    next unless $number =~/^\d+/;

    return undef unless ($number && $state && $name);

    my $p = new Nmap::Scanner::Protocol();

    $p->number($number);
    $p->state($state);
    $p->name($name);

    return $p;

}


1;
