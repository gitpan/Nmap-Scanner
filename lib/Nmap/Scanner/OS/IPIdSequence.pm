package Nmap::Scanner::OS::IPIdSequence;

=pod

=head1 NAME 

IPIdSequence - IP identification sequence

=cut

use strict;

sub new {
    my $class = shift;
    my $me = { CLASS => undef, VALUES => undef };
    return bless $me, $class;
}

=pod

=head2 class()

=cut

sub class {
    (defined $_[1]) ? ($_[0]->{CLASS} = $_[1]) : return $_[0]->{CLASS};
}

=pod

=head2 values()

=cut

sub values {
    (defined $_[1]) ? ($_[0]->{VALUES} = $_[1]) : return $_[0]->{VALUES};
}

sub as_xml {

    my $self = shift;

    my $xml  = "  <ip-id-sequence";
       $xml .= ' class="'  . $self->class()  . '" ';
       $xml .= ' values="' . $self->values() . '" ';
       $xml .= "/>\n";

    return $xml;

}

1;
__END__;
