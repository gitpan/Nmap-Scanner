package Nmap::Scanner::Service;

use strict;
use HTML::Entities;

=pod

=head1 DESCRIPTION

This class represents a service as represented by the scanning output from
nmap.

=cut

sub new {
    my $class = shift;
    my $me = {
        NAME       => '', 
        PROTO      => '', 
        RPCNUM     => '', 
        LOWVER     => '', 
        HIGHVER    => '', 
        METHOD     => '', 
        SERVICE    => '', 
        VERSION    => '', 
        EXTRAINFO  => '', 
        TUNNEL     => '', 
        CONF       => ''};
    return bless $me, $class;
}

=pod

=head2 name()

=cut

sub name {
    (defined $_[1]) ? ($_[0]->{NAME} = $_[1]) : return $_[0]->{NAME};
}

=pod

=head2 proto()

=cut

sub proto {
    (defined $_[1]) ? ($_[0]->{PROTO} = $_[1]) : return $_[0]->{PROTO};
}

=pod

=head2 rpcnum()

=cut

sub rpcnum {
    (defined $_[1]) ? ($_[0]->{RPCNUM} = $_[1]) : return $_[0]->{RPCNUM};
}

=pod

=head2 lowver()

=cut

sub lowver {
    (defined $_[1]) ? ($_[0]->{LOWVER} = $_[1]) : return $_[0]->{LOWVER};
}

=pod

=head2 highver()

=cut

sub highver {
    (defined $_[1]) ? ($_[0]->{HIGHVER} = $_[1]) : return $_[0]->{HIGHVER};
}

=pod

=head2 method()

=cut

sub method {
    (defined $_[1]) ? ($_[0]->{METHOD} = $_[1]) : return $_[0]->{METHOD};
}

=pod

=head2 conf()

=cut

sub conf {
    (defined $_[1]) ? ($_[0]->{CONF} = $_[1]) : return $_[0]->{CONF};
}

=pod

=head2 tunnel()

=cut

sub tunnel {
    (defined $_[1]) ? ($_[0]->{TUNNEL} = $_[1]) : return $_[0]->{TUNNEL};
}

=pod

=head1 VERSION SCANNING MUTATORS

Information will be present for this only if -sV is used.

=head2 product()

=cut

sub product {
    (defined $_[1]) ? ($_[0]->{PRODUCT} = $_[1]) : return $_[0]->{PRODUCT};
}

=pod

=head2 version()

=cut

sub version {
    (defined $_[1]) ? ($_[0]->{VERSION} = $_[1]) : return $_[0]->{VERSION};
}

=pod

=head2 extrainfo()

=cut

sub extrainfo {
    (defined $_[1]) ? ($_[0]->{EXTRAINFO} = $_[1]) : return $_[0]->{EXTRAINFO};
}

sub as_xml {

    my $self = shift;
        
    my $xml = '<service ';

    $xml .= 'name="' . $self->name() . '" ' if $self->name();
    $xml .= 'proto="' . $self->proto() . '" ' if $self->proto();
    $xml .= 'rpcnum="' . $self->rpcnum() . '" ' if $self->rpcnum();
    $xml .= 'lowver="' . $self->lowver() . '" ' if $self->lowver();
    $xml .= 'highver="' . $self->highver() . '" ' if $self->highver();
    $xml .= 'version="' . $self->version()  . '" ' if $self->version();

    $xml .= 'product="' . encode_entities($self->product()) . '" ' 
        if $self->product();

    $xml .= 'extrainfo="' . encode_entities($self->extrainfo()) . '" ' 
        if $self->extrainfo();

    $xml .= 'method="' . $self->method() . '" ' if $self->method();
    $xml .= 'conf="' . $self->conf() . '" />' if $self->conf();

    return $xml;

}

1;
