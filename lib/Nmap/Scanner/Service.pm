package Nmap::Scanner::Service;

use strict;

=pod

=head1 DESCRIPTION

This class represents a service as represented by the scanning output from
nmap.

=cut

sub new {
    my $class = shift;
    my $me = {
        NAME     => undef, 
        PROTO    => undef, 
        RPCNUM   => undef, 
        LOWVER   => undef, 
        HIGHVER  => undef, 
        METHOD   => undef, 
        CONF     => undef};
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

sub as_xml {

    my $self = shift;

    return
        '<service '.
        'name="'   .  $self->name() .'" '.
        'proto="'   .  $self->proto() .'" '.
        'rpcnum="'   .  $self->rpcnum() .'" '.
        'lowver="'   .  $self->lowver() .'" '.
        'highver="'   .  $self->highver() .'" '.
        'method="' .  $self->method()  .'" '.
        'conf="'   .  $self->conf()  .'" '. '/>';

}

1;
