package Nmap::Scanner::OS::Match;

=pod

=head1 NAME 

OS Match - Operating system match

This object encapsulates an nmap operating system
guess.


=cut

use strict;

sub new {
    my $class = shift;
    my $me = { NAME => undef, ACCURACY => undef };
    return bless $me, $class;
}


=pod

=head2 name()

Operating system name

=cut

sub name {
    (defined $_[1]) ? ($_[0]->{NAME} = $_[1]) : return $_[0]->{NAME};
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

    my $xml  = "  <match";
       $xml .= ' name="'  . $self->name()  . '" ';
       $xml .= ' accuracy="' . $self->accuracy() . '" ';
       $xml .= "/>\n";

    return $xml;

}

1;
__END__;
