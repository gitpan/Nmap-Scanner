package Nmap::Scanner::Scanner;

use File::Spec;
use Nmap::Scanner::Backend::Normal;
use strict;

=pod

=head1 DESCRIPTION

This class is the primary class of this set; it is the driver for
the Nmap::Scanner hierarchy.  To use it, create an instance of
Nmap::Scanner, possibly set the path to Nmap with nmap_location()
(the default behaviour of this class is to search for nmap in
the PATH variable.

my $nmap = new Nmap::Scanner();
$nmap->nmap_location('/usr/local/bin/nmap');

Set any options you wish to use in order to run the scan in either
batch or event mode, and then call scan() to start scanning.

my $results = $nmap->scan();

For information on the options presented below, see the man page for
nmap or go to http://www.insecure.org/nmap/.

=head2 NOTE

Some descriptions of methods here are taken directly from the nmap
man page.

=head2 EXAMPLE 

See examples/ directory in the distribution for many more)

use Nmap::Scanner;
my $scan = Nmap::Scanner->new();

$scan->add_target('localhost');
$scan->add_target('host.i.administer');
$scan->add_scan_port('1-1024');
$scan->add_scan_port('31337');
$scan->tcp_syn_scan();
$scan->noping();

my $results = $scan->scan();

my $hosts = $results->gethostlist();

while (my $host = $hosts->getnext()) {

    print "On " . $host->name() . ": \n";

    my $ports = $host->getportlist();

    while (my $port = $ports->getnext()) {
        print join(' ',
            'Port',
            $port->service() . '/' . $port->number(),
            'is in state',
            $port->state(),
            "\n"
        );
    }

}

=cut

sub new {
    my $class = shift;
    my $you = {};
    $you->{'OPTIONS'}->{'-o'} = 'N -';
    return bless $you, $class;
}

=pod

=head2 SCAN EVENTS

Register for any of the below events if you wish to use Nmap::Scanner
in event-driven mode.

=head2 register_scan_complete_event(\&host_done)

Register for this event to be notified when a scan of a 
host is complete.  Pass in a function reference that can
accept a $self object reference and a reference to an
Nmap::Scanner::Host object.

host_done($self, $host);


=cut

sub register_scan_complete_event {
    $_[0]->{'SCAN_COMPLETE_EVENT'} = [$_[0], $_[1]];
}

=pod

=head2 register_scan_started_event(\&scan_started);

Register for this event to be notified when nmap has started to
scan one of the targets specified in add_target.  Pass in a 
function reference that can accept a $self object reference,
a string variable representing the host name of the host being
scanned, a string variable representing the IP address of the
host, and a variable to hold the status of the host .. either
"up" or "down."

scan_started($self, $hostname, $ip, $status);

=cut

sub register_scan_started_event {
    $_[0]->{'SCAN_STARTED_EVENT'} = [$_[0], $_[1]];
}

=pod

=head2 register_host_closed_event(\&host_closed);

Register to be notified if a scanned host is found to
be closed (no open ports).  Pass in a function reference
that can take an $self object reference, a string containing
the host name of the host scanned and a string containing
the IP address of the host scanned.

host_closed($self, $hostname, $ip);

=cut

sub register_host_closed_event {
    $_[0]->{'SCAN_STARTED_EVENT'} = [$_[0], $_[1]];
}

=pod

=head2 register_port_found_event(\&port_found);

Register to be notified when a port is scanned on a host.  The
port may be in any state ... closed, open, filtered.  Pass a
reference to a function that takes a $self object reference,
a string containing the host name of the host scanned, a
string with the IP address of the host scanned, and a 
reference to the port object representin gthe port scanned.

port_found($self, $hostname, $ip, $port);

=cut

sub register_port_found_event {
    $_[0]->{'PORT_FOUND_EVENT'} = [$_[0], $_[1]];
}

=pod

=head2 register_no_ports_open_event(\&port_found);

Register to be notified in the event that no ports are found
to be open on a host.  Pass in a reference to a function that
takes a $self object reference, a string containing the host
name of the scanned host, a string containing the IP address
of the scanned host, and a string containing the status of
all ports on the host ... closed, filtered, etc.

port_found($self, $hostname, $ip, $status);

=cut

#  Function pointer that receives host name, IP, and status of all ports
sub register_no_ports_open_event {
    $_[0]->{'NO_PORTS_OPEN_EVENT'} = [$_[0], $_[1]];
}

=pod

=head2 debug()

Set this to a non-zero value to see debugging output.

=cut

sub debug {
    (defined $_[1]) ? ($_[0]->{DEBUG} = $_[1]) : return $_[0]->{DEBUG};
}

=pod

=head2 norun()

Set this to non-zero to have Nmap::Scanner::Scanner print the
nmap command line and exit when scan() is called.

=cut

sub norun {
    $_[0]->{'NORUN'} = $_[1];
}

=pod

=head2 SCAN TYPES

See the nmap man page for descriptions of all these.  Not all nmap
scan types are supported with this release due to time limitations.

=head2 tcp_connect_scan()

=head2 tcp_syn_scan()

=head2 fin_scan()

=head2 xmas_scan()

=head2 null_scan()

=head2 ping_scan()

=head2 udp_scan()

=head2 protocol_scan()

If this scan is used, the protocols can be retrieve from
the Nmap::Scanner::Host objects using the method
get_protocol_list() .. this will return a list of
Nmap::Scanner::Protocol object references.

=head2 idle_scan($zombie_host, $probe_port)

=head2 ack_scan()

=head2 window_scan()

=head2 rpc_scan()

XXX:  Need to implement code to support the results returned from
this.

=cut

sub tcp_connect_scan {
    $_[0]->{TYPE} = 'T';
}

sub tcp_syn_scan {
    $_[0]->{TYPE} = 'S';
}

sub fin_scan {
    $_[0]->{TYPE} = 'F';
}

sub xmas_scan {
    $_[0]->{TYPE} = 'X';
}

sub null_scan {
    $_[0]->{TYPE} = 'N';
}

sub ping_scan {
    $_[0]->{TYPE} = 'P';
}

sub udp_scan {
    $_[0]->{UDPSCAN} = 'U';
}

sub protocol_scan {
    $_[0]->{TYPE} = 'O';
}

sub idle_scan {
    $_[0]->{TYPE} = "I $_[1]";
    $_[0]->{TYPE} .= ":$_[2]" if $_[2];
}

sub ack_scan {
    $_[0]->{TYPE} = 'A';
}

sub window_scan {
    $_[0]->{TYPE} = 'W';
}

sub rpc_scan {
    $_[0]->{RPCSCAN} = 'R';
}

=pod

=head2 SPECIFYING PORTS TO SCAN

Use add_scan_port($port_spec) to add one or more ports
to scan.  $port_spec can be a single port or a range ...
$n->add_scan_port(80) or $n->add_scan_port('80-1023');

Use delete_scan_port($portspec) to delete a port or range
of ports.

Use reset_scan_ports() to cancel any adds done with add_scan_port().

Use getports to get a hash reference in which the keys are the
ports you specified with add_scan_port().

=cut

sub add_scan_port {
    $_[0]->{PORTS}->{$_[1]} = 1;
}

sub delete_scan_port {
    delete $_[0]->{'PORTS'}->{$_[1]} if 
        exists $_[0]->{'PORTS'}->{$_[1]};
}

sub reset_scan_ports {
    $_[0]->{PORTS} = undef;
}

sub getports {
    return $_[0]->{PORTS};
}

=pod

=head2 SPECIFYING TARGETS TO SCAN

See the nmap documentation for the full syntax nmap supports
for specifying hosts / subnets / networks to scan.  

Use add_target($hostspec) to add a target to scan.

Use delete_target($hostspec) to delete a target from the
list of hosts/networks to scan (must match text used in
add_target($hostspec)).

Use reset_targets() to cancel any targets you specified
with add_target().

=cut

sub add_target {
    $_[0]->{'TARGETS'}->{$_[1]} = 1;
}

sub delete_target {
    delete $_[0]->{'TARGETS'}->{$_[1]} if 
        exists $_[0]->{'TARGETS'}->{$_[1]};
}

sub reset_targets {
    $_[0]->{'TARGETS'} = undef;
}

=pod

=head2 PING OPTIONS

nmap has a very flexible mechanism for setting how a ping
is interpreted for hosts during a scan.  See the nmap
documentation for more details.

Use no_ping() to not ping hosts before scanning them.

Use ack_ping($port) to use a TCP ACK packet as a ping to
the port specified on each host to be scanned.

Use syn_ping($port) to use a TCP SYN packet as a ping
to the port specified on each host to be scanned.

Use icmp_ping() to use a true ICMP ping for each host 
to be scanned.

Use ack_icmp_ping($port) to use an ICMP ping, then a TCP ACK packet 
as a ping (if the ICMP ping fails) to the port specified on each host 
to be scanned.  This is the default behaviour if no ping options are
specified.

=cut

sub no_ping {
    $_[0]->{'OPTS'}->{'-P'} = "0";
}

sub ack_ping {
    $_[0]->{'OPTS'}->{'-P'} = "T$_[1]";
}

sub syn_ping {
    $_[0]->{'OPTS'}->{'-P'} = "S$_[1]";
}

sub icmp_ping {
    $_[0]->{'OPTS'}->{'-P'} = "I";
}

sub ack_icmp_ping {
    $_[0]->{'OPTS'}->{'-P'} = "B$_[1]";
}

=pod

=head2 TIMING OPTIONS

Use these methods to set how quickly or slowly nmap scans
a host.  For more detail on these methods, see the nmap
documentation.

From slowest to fastest:

=item * paranoid_timing()

=item * sneaky_timing()

=item * polite_timing()

=item * normal_timing()

=item * aggressive_timing()

=item * insane_timing()

=cut

sub paranoid_timing {
    $_[0]->{'OPTS'}->{'-T'} = 'Paranoid';
}

sub sneaky_timing {
    $_[0]->{'OPTS'}->{'-T'} = 'Sneaky';
}

sub polite_timing {
    $_[0]->{'OPTS'}->{'-T'} = 'Polite';
}

sub normal_timing {
    $_[0]->{'OPTS'}->{'-T'} = 'Normal';
}

sub aggressive_timing {
    $_[0]->{'OPTS'}->{'-T'} = 'Aggressive';
}

sub insane_timing {
    $_[0]->{'OPTS'}->{'-T'} = 'Insane';
}

=pod

=head2 OTHER OPTIONS

There are many other nmap options.  This version does not
attempt to represent them all.  I welcome patches from 
users :) and I will fill in missing gaps as I have time.

For details on any of these methods see the nmap 
documentation.

=cut

=pod

=head2 guess_os()

Try and guess the operating system of each target host
using TCP fingerprinting.

=cut

sub guess_os {
    $_[0]->{'OPTS'}->{'-O'} = "";
}

=pod

=head2 fast_scan()

Only scan for services listed in nmap's services file.

=cut

sub fast_scan {
    $_[0]->{'OPTS'}->{'-F'} = "";
}

=pod

=head2 ident_check()

Attempts to find the user that owns each open port by
querying the ident damon of the remote host.  See the
nmap man page for more details.

=cut

sub ident_check {
    $_[0]->{'OPTS'}->{'-I'} = "";
}

=pod

=head2 host_timeout($milliseconds)

Specifies how much time nmap spends on scanning each 
host before giving up.  Not set by default.

=cut

sub host_timeout {
    $_[0]->{'OPTS'}->{'--host-timeout'} = $_[1];
}

=pod

=head2 max_rtt_timeout($milliseconds)

Specifies the maximum time nmap should
wait for a response to a probe of a port.

=cut

sub max_rtt_timeout {
    $_[0]->{'OPTS'}->{'--max_rtt_timeout'} = $_[1];
}

=head2 max_rtt_timeout($milliseconds)

Specifies the minimum time nmap should
wait for a response to a probe of a port.  Nmap
reduces the amoutn of time per response if the
scanned machines respond quickly; it will not
go below this threshold.

=cut

sub min_rtt_timeout {
    $_[0]->{'OPTS'}->{'--min_rtt_timeout'} = $_[1];
}

=head2 initial_rtt_timeout($milliseconds)

Specifies the initial probe timeout.  See the
nmap man page for more detail.

=cut

sub initial_rtt_timeout {
    $_[0]->{'OPTS'}->{'--initial_rtt_timeout'} = $_[1];
}

=pod

=head2 max_parallelism($number)

Specifies  the  maximum  number of scans Nmap is allowed to
perform in parallel.

=cut

sub max_parallelism {
    $_[0]->{'OPTS'}->{'--max_parallelism'} = $_[1];
}

=pod

=head2 scan_delay($milliseconds)

Specifies the minimum amount of time Nmap must wait between
probes.

=cut

sub scan_delay {
    $_[0]->{'OPTS'}->{'--scan_delay'} = $_[1];
}

=pod

=head2 scan()

Perform the scan.  If the return value is captured (which might
not be necessary if doing an event-based scan), returns a
populated instance of Nmap::Scanner::Backend::Results.

=cut

sub scan {
    
    my $this = shift;

    my $nmap = $this->{'NMAP'} || _find_nmap();

    die "Can't find nmap!\n" unless $nmap;

    unless (-f $nmap && -x _) {
        die "Can't execute specified nmap: $this->{NMAP}\n";
    }

    local($_);

    my $cmd = "$nmap -v -v -v";

    $cmd .= " -s$this->{'TYPE'}" if defined $this->{'TYPE'};

    $cmd .= " -s$this->{'UDPSCAN'}" if $this->{'UDPSCAN'};

    if ($this->{PORTS}) {
        $cmd .= " -p " . join(',', keys %{$this->{PORTS}});
    }

    #  Gather other options
    if ($this->{'OPTS'}) {
        for my $opt (keys %{$this->{OPTS}}) {
            $cmd .= " " . $opt . " " . $this->{'OPTS'}->{$opt};
        }
    }

    $cmd .= " " . join(' ', keys %{$this->{'TARGETS'}});

    die "$cmd\n" if $this->{'NORUN'};

    #  Choose the right kind of backend processor based
    #  on output selection type.

    my $processor = undef;

    if ($this->{'OPTIONS'}->{'-o'} eq 'N -') {
        $processor = new Nmap::Scanner::Backend::Normal();
    }

    #  All backend processors support these.
    $processor->debug($this->{'DEBUG'});
    $processor->register_scan_complete_event($this->{'SCAN_COMPLETE_EVENT'});
    $processor->register_scan_started_event($this->{'SCAN_STARTED_EVENT'});
    $processor->register_host_closed_event($this->{'SCAN_STARTED_EVENT'});
    $processor->register_port_found_event($this->{'PORT_FOUND_EVENT'});

    #  And this.
    $this->{'RESULTS'} = $processor->process($cmd);

    return $this->{'RESULTS'};

}

sub results {
    (defined $_[1]) ? ($_[0]->{RESULTS} = $_[1]) : return $_[0]->{RESULTS};
}

=pod

=head2 nmap_location($path)

If nmap is not in your PATH, you can specify where it
is using this method.

=cut

sub nmap_location {
    (defined $_[1]) ? ($_[0]->{NMAP} = $_[1]) : return $_[0]->{NMAP};
}

sub _find_nmap {

    local($_);
    local(*DIR);

    for my $dir (split(':',$ENV{'PATH'})) {
        opendir(DIR,$dir) || next;
        my @files = (readdir(DIR));
        closedir(DIR);
        my $path;
        for my $file (@files) {
            next unless $file eq 'nmap';
            $path = File::Spec->catfile($dir,$file);
            next unless -r $path && -x _;
            return $path;
            last DIR;
        }
    }

}

1;
