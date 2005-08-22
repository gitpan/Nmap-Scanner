package Nmap::Scanner::OS::Class;

=pod

=head1 NAME 

OS Class - Operating system class

This object encapsulates an nmap operating system
guess.


=cut

use strict;

sub new {
    my $class = shift;
    my $me = { VENDOR => undef, 
                OSGEN => undef, 
                 TYPE => undef, 
             OSFAMILY => undef, 
             ACCURACY => undef };
    return bless $me, $class;
}


=pod

=head2 vendor()

Operating system vendor

=cut

sub vendor {
    (defined $_[1]) ? ($_[0]->{VENDOR} = $_[1]) : return $_[0]->{VENDOR};
}

=head2 osgen()

Operating system generation

=cut

sub osgen {
    (defined $_[1]) ? ($_[0]->{OSGEN} = $_[1]) : return $_[0]->{OSGEN};
}

=head2 type()

Operating system generation

=cut

sub type {
    (defined $_[1]) ? ($_[0]->{TYPE} = $_[1]) : return $_[0]->{TYPE};
}

=head2 osfamily()

Operating system family

=cut

sub osfamily {
    (defined $_[1]) ? ($_[0]->{OSFAMILY} = $_[1]) : return $_[0]->{OSFAMILY};
}

=pod

=head2 accuracy()

How accurate does nmap think this match is?

=cut

sub accuracy {
    (defined $_[1]) ? ($_[0]->{ACCURACY} = $_[1]) : return $_[0]->{ACCURACY};
}

sub as_xml {

    my $self = shift;

    my $xml  = "<osclass";
       $xml .= ' type="'  . $self->type()  . '" ';
       $xml .= ' vendor="'  . $self->vendor()  . '" ';
       $xml .= ' osfamily="'  . $self->osfamily()  . '" ';
       $xml .= ' osgen="'  . $self->osgen()  . '" ' if $self->osgen();
       $xml .= ' accuracy="' . $self->accuracy() . '" ';
       $xml .= "/>";

    return $xml;

}

1;
__END__;
