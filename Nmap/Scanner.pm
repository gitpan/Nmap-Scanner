package Nmap::Scanner;

use vars qw($VERSION @ISA);

$VERSION = '0.01';

use Nmap::Scanner::Scanner;
use Nmap::Scanner::Port;
use Nmap::Scanner::Host;
use Nmap::Scanner::PortList;
use Nmap::Scanner::HostList;
use Nmap::Scanner::ProtocolList;
use Nmap::Scanner::Util;

@ISA = qw(Nmap::Scanner::Scanner);

#
#  Convenience method for getting to Nmap::Scanner::Scanner.
#

sub new {

    my $class = shift;
    my $self = $class->SUPER::new();
    return bless $self, $class;    

}

1;

__END__

# Below is the stub of documentation for your module. You better edit it!

=head1 NAME

Nmap::Scanner 

=head1 SYNOPSIS

  Perl extension for performing nmap (www.insecure.org/nmap) scans.

  use Nmap::Scanner;

  #  Batch scan method

  my $scanner = new Nmap::Scanner;
  $scanner->tcp_syn_scan();
  $scanner->add_scan_port('1-1024');
  $scanner->add_scan_port(8080);
  $scanner->guess_os();
  $scanner->max_rtt_timeout(200);
  $scanner->add_target('some.host.out.there.com.org');
  my $results = $scanner->scan();

  #  Event scan method

  my $scanner = new Nmap::Scanner;
  $scanner->tcp_syn_scan();
  $scanner->add_scan_port('1-1024');
  $scanner->add_scan_port(8080);
  $scanner->guess_os();
  $scanner->max_rtt_timeout(200);
  $scanner->add_target('some.host.out.there.com.org');
  $scanner->register_scan_started_event(\&scan_started);
  $scanner->register_port_found_event(\&port_found);
  $scanner->scan();

  sub scan_started {

    my $self     = shift;
    my $hostname = shift;
    my $ip       = shift;
    my $status   = shift;

    print "$hostname ($ip) is $status\n";

  }

  sub port_found {

    my $self     = shift;
    my $hostname = shift;
    my $ip       = shift;
    my $port     = shift;

    my $port_num = $port->number();
    my $port_svc = $port->service();
    my $port_st  = $port->state();
    my $port_pr  = $port->protocol();

    print "$hostname ($ip): $port_svc ($port_num:$port_pr) is $port_st\n";

  }


=head1 DESCRIPTION

This set of modules provides perl class wrappers for the network mapper
(nmap) scanning tool (see http://www.insecure.org/nmap/).  Using these modules,
a developer, network administrator, or other techie can create perl routines
or classes which can be used to automate and integrate nmap scans elegantly 
into new and existing perl scripts.

If you don't have nmap installed, you will need to download it BEFORE you
can use these modules.  Get it from http://www.insecure.org/nmap/.

=head1 USAGE

The module set consists of a Scanner class and many classes that support
the scanner and encapsulate the data output by nmap as it scans.  The
class that you will likely use most often is Nmap::Scanner.  This class
encapsulates the nmap scanner options and `drives' the scan process.  It
provides a convenience constructor that will instantiate an instance of
Nmap::Scanner::Scanner for you.

Scans can be done in two modes using this module set: batch mode and
event mode.  

=head2 Batch mode scanning

In batch mode the scan is set up and executed and the results are returned in 
an Nmap::Scanner::Backend::Results object.  This object contains information 
about the scan and a list of the found host objects 
(instances of Nmap::Scanner::Host).  Each host contains a list of found ports 
on that host (instances of Nmap::Scanner::Port).  No information is returned
to the user until the entire scan is complete.

=head2 Event mode scanning

In event mode the user registers interest in one or more scan events by
passing a reference to a callback function to one or more event registration 
functions.  The scanner then calls the callback function during a specifc 
phase of the scan.  It passes the function arguments describing what has 
happened and the data found.

Each function is also passed a reference to the current object
instance of Nmap::Scanner::Scanner (or a subclass of Nmap::Scanner::Scanner)
as the FIRST argument so that subclasses with instance-specific data can 
be easily created (see the Nmap::Scanner::Util package for examples).

There are four events that a user can register for: scan started event,
host closed event, no ports open event, port found event, and scan
complete event.   The scan started event occurs at the beginning of
the scan process for EACH host specified with add_target().  The
host closed event is called if a specified host is found to be unavailable
via whatever type of ping has been specified.  The no ports open event
is triggered if no ports are found to be open on a scanned host.  The
port found event is called when a port IS found to be open on a host.
The scan complete event is called as soon as the scan of a host specified as a
target with add_target() is complete.

=head1 NOTES

Nmap::Scanner parses the output from nmap; I hope someday someone creates
a dynamic shared object library out of nmap so this module can be ported
to optionally use native calls and thereby speed up performance and decrease
the likelihood of parsing issues as nmap versions change.

The current set of modules parses the output from "-oN" (`normal' output) ...
I hope to someday add in support for parsing the XML output but didn't have
time to do that initially.

=head1 THANKS

Special thanks to Fyodor (fyodor@insecure.org) for creating such a useful
tool and to all the developers and contributors who constantly work to 
improve and fine-tune nmap for grateful users like me!

=head1 BUGS

Many, I am sure!  A HUGE one is there is currently NO error handling.  That
is my top priority for the next major version of this.  The other big one is
not supporting XML output.  That too is one for the next revision.

Please keep in mind that the API for this software may CHANGE and that this
is not a complete implementation of nmap in perl!

=head1 AUTHOR

Max Schubert, max@perldork.com

=head1 LICENSE

This software is released under the same license and terms as perl itself.

=head1 SEE ALSO

http://www.insecure.org/nmap/

Nmap::Scanner::Scanner

=cut
