package Nmap::Scanner::Hostname;

use strict;

=pod

=head1 Name

Hostname - Holds information about a remote port as detected by nmap.

=cut

sub new {
    my $class = shift;
    my $me = { NAME => '', TYPE => '' };
    return bless $me, $class;
}

=pod

=head2 name()

Name of host

=cut

sub name {
    (defined $_[1]) ? ($_[0]->{NAME} = $_[1]) : return $_[0]->{NAME};
}

=pod

=head2 type()

Type of name record (PTR, CNAME)

=cut

sub type {
    (defined $_[1]) ? ($_[0]->{TYPE} = $_[1]) : return $_[0]->{TYPE};
}

sub as_xml {

    my $self = shift;

    my $xml = '<hostname ';
    $xml .= 'name="' . $self->name() . '" ';
    $xml .= 'type="' . $self->type() . '" ';
    $xml .= '/>';


    return $xml;
}

1;
