package Nmap::Scanner::ScanInfo;

=pod

=head1 DESCRIPTION

This class represents Nmap Summary/scan information.

=head1 PROPERTIES

=cut

use strict;

sub new {
    my $class = shift;
    my $me = { 
               TYPE        => undef,
               PROTOCOL    => undef,
               NUMSERVICES => undef,
               SERViCES    => undef
             };
    return bless $me, $class;
}

=pod

=head2 type()

=cut

sub type {
    (defined $_[1]) ? ($_[0]->{TYPE} = $_[1]) : return $_[0]->{TYPE};
}

=pod

=head2 protocol()

=cut

sub protocol {
    (defined $_[1]) ? ($_[0]->{PROTOCOL} = $_[1]) : return $_[0]->{PROTOCOL};
}

=pod

=head2 numservices()

=cut

sub numservices {
    (defined $_[1]) ? ($_[0]->{NUMSERVICES} = $_[1]) : return $_[0]->{NUMSERVICES};
}

=pod

=head2 services()

=cut

sub services {
    (defined $_[1]) ? ($_[0]->{SERVICES} = $_[1]) : return $_[0]->{SERVICES};
}

sub as_xml {

    my $self = shift;

    my $xml = "<scan-info";
    $xml .= ' type="'     . $self->type() . '"';
    $xml .= ' protocol="' . $self->protocol() . '"';
    $xml .= ' numservices="' . $self->numservices() . '"';
    $xml .= ' services="' . $self->services() . '"';
    $xml .= "/>\n";

    return $xml;

}

1;
__END__;
