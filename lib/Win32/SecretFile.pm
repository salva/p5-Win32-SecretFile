package Win32::SecretFile;

our $VERSION = '0.01';

use 5.010;
use strict;
use warnings;

require Exporter;
our @ISA = qw(Exporter);
our @EXPORT_OK = qw(create_secret_file);

require XSLoader;
XSLoader::load('Win32::SecretFile', $VERSION);

sub create_secret_file {
    my ($name, $data, %opts) = @_;
    _create_secret_file($name, $data // '', 0);
}

1;
__END__
# Below is stub documentation for your module. You'd better edit it!

=head1 NAME

Win32::SecretFile - Perl extension for blah blah blah

=head1 SYNOPSIS

  use Win32::SecretFile;
  blah blah blah

=head1 DESCRIPTION

Stub documentation for Win32::SecretFile, created by h2xs. It looks like the
author of the extension was negligent enough to leave the stub
unedited.

Blah blah blah.

=head2 EXPORT

None by default.



=head1 SEE ALSO

Mention other useful documentation such as the documentation of
related modules or operating system documentation (such as man pages
in UNIX), or any relevant external documentation such as RFCs or
standards.

If you have a mailing list set up for your module, mention it here.

If you have a web site set up for your module, mention it here.

=head1 AUTHOR

Salvador Fandiño, E<lt>salva@(none)E<gt>

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2014 by Salvador Fandiño

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself, either Perl version 5.21.7 or,
at your option, any later version of Perl 5 you may have available.


=cut
