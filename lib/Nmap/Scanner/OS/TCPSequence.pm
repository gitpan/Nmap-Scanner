package Nmap::Scanner::OS::TCPSequence;

=pod

=head1 NAME

TCPSequence - Information about TCP sequence mechanism of remote host

=cut

use strict;

sub new {
    my $class = shift;
    my $me = { INDEX => undef, CLASS => undef,
               DIFFICULTY => undef, VALUES => undef };
    return bless $me, $class;
}


=pod

=head2 index()

=cut

sub index {
    (defined $_[1]) ? ($_[0]->{INDEX} = $_[1]) : return $_[0]->{INDEX};
}

=pod

=head2 class()

=cut

sub class {
    (defined $_[1]) ? ($_[0]->{CLASS} = $_[1]) : return $_[0]->{CLASS};
}

=pod

=head2 difficulty()

=cut

sub difficulty {
    (defined $_[1]) ? ($_[0]->{DIFFICULTY} = $_[1]) : return $_[0]->{DIFFICULTY};
}

=pod

=head2 values()

=cut

sub values {
    (defined $_[1]) ? ($_[0]->{VALUES} = $_[1]) : return $_[0]->{VALUES};
}

sub as_xml {

    my $self = shift;

    my $xml  = "  <tcp-sequence";
       $xml .= ' index="'  . $self->index()  . '" ';
       $xml .= ' class="'  . $self->class()  . '" ';
       $xml .= ' difficulty="'  . $self->difficulty()  . '" ';
       $xml .= ' values="' . $self->values() . '" ';
       $xml .= "/>\n";

    return $xml;

}

1;
__END__;
