# --
# OTOBO is a web-based ticketing system for service organisations.
# --
# Copyright (C) 2001-2020 OTRS AG, https://otrs.com/
# Copyright (C) 2019-2025 Rother OSS GmbH, https://otobo.io/
# --
# This program is free software: you can redistribute it and/or modify it under
# the terms of the GNU General Public License as published by the Free Software
# Foundation, either version 3 of the License, or (at your option) any later version.
# This program is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
# FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <https://www.gnu.org/licenses/>.
# --

package Kernel::System::OpenIDConnect::TokenStoreUpdater;
use strict;
use warnings;

use Kernel::System::VariableCheck qw(:all);

our @ObjectDependencies = (
    'Kernel::System::Main',
    'Kernel::System::DateTime',
    'Kernel::System::OpenIDConnect::TokenProvider',
);

=head1 NAME

Kernel::System::OpenIDConnect::TokenStoreUpdater - refresh OAuth Tokens via cron scheduler

=head1 DESCRIPTION

Refreshes OAuth Tokens via cron scheduler

=head1 PUBLIC INTERFACE

=head2 new()

create a TokenSToreUpdater object. Do not use it directly, instead use:

     my $TokenStoreUpdaterObject = $Kernel::OM->Get('Kernel::System::OpenIDConnect::TokenStoreUpdater');

=cut

sub new {
    my ( $Type, %Param ) = @_;

    # allocate new hash for object
    my $Self = {};
    bless( $Self, $Type );

    return $Self;
}

sub Run {

    my ( $Self, %Param ) = @_;

use Data::Dumper;
    open(my $FH,">","/opt/otobo/var/log/tokenupdater2.log");

    print $FH "############################\n";
    print $FH "TokenStorageUpdater2 has run!\n";
    print $FH Dumper(\%Param);
    print $FH "############################\n";

    my $MainObject = $Kernel::OM->Get('Kernel::System::Main');

    print $FH "1############################\n";

    my $Log = "TokenStorageUpdater has been called with:\n";

    $Log .= $MainObject->Dump( \%Param );
    print $FH "2############################\n";

    my $DateTimeObject = $Kernel::OM->Create(
        'Kernel::System::DateTime',
    );

    print $FH "3############################\n";

    my $Success = $DateTimeObject->ToTimeZone(
        TimeZone => 'UTC'
    );

    print $FH "4############################\n";

    my $Time = $DateTimeObject->Format( Format => '%Y-%m-%d %H:%M:%S' );

    print $FH "5############################\n";

    $Log .= "at $Time.\n";

    print $FH "at $Time.\n";

    my $Tokens;
    eval {
        my $TokenProvider = $Kernel::OM->Get('Kernel::System::OpenIDConnect::TokenProvider');

        $Tokens = $TokenProvider->RenewTokens(%Param);
    };
    if ($@ ) {

        print $FH Dumper($@);
    }

    print $FH "6############################\n";

    if($Tokens) {
        $Log .= $MainObject->Dump( $Tokens );
    }

    print $FH Dumper($Tokens);
    print $FH "7############################\n";
    close($FH);

    my $FileLocation = $MainObject->FileWrite(
        Directory => '/opt/otobo/var/log/',
        Filename  => 'tokenupdater.log',
        Content   => \$Log,
    );

    return 1;
}

1;
