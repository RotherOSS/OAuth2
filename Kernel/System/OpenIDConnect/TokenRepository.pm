# --
# OTOBO is a web-based ticketing system for service organisations.
# --
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

package Kernel::System::OpenIDConnect::TokenRepository;

use strict;
use warnings;

# core modules

# CPAN modules
use HTTP::Request::Common;
use LWP::UserAgent;
use LWP::Simple;
use URI::Escape qw();

# OTOBO modules
use Kernel::System::VariableCheck qw(:all);

use namespace::autoclean;

#use parent qw(Kernel::System::OpenIDConnect);

our @ObjectDependencies = (
    'Kernel::Config',
    'Kernel::System::DateTime',
    'Kernel::System::Cache',
    'Kernel::System::JSON',
    'Kernel::System::Log',
    'Kernel::System::DB',
);

=head1 NAME

Kernel::System::OpenIDConnect::TokenRepository - DB backend for TokenStorage

=head1 SYNOPSIS

Functional account functions for OpenID Connect

create an object

    use Kernel::System::ObjectManager;
    local $Kernel::OM = Kernel::System::ObjectManager->new();
    my $TokenRepositoryObject = $Kernel::OM->Get('Kernel::System::OpenIDConnect::TokenRepository');

=cut

sub new {
    my ( $Type, %Param ) = @_;

    # allocate new hash for object
    my $Self = {};

    bless( $Self, $Type );

    return $Self;
}

=head2 Save()

    my $Success = $TokenRepositoryObject->Save(
        AccountCtx => 'Provider'                 # Provider|Invoker|MailAccount|User
        AccountID  => 'FunctionalAccount1',     # FunctionalAccountName|mail_account.id|users.id
        TokenType  => 'refresh',                # access_token|id_token|refresh_token
        Token => '<Token>',                     # as received from token endpoint
        ExpiresAt => '<seconds epoch>',         # expires at UNIX epoch timestamp
    );

=cut

sub Save {
    my ( $Self, %Param ) = @_;

    my $DBObject = $Kernel::OM->Get('Kernel::System::DB');

    for my $Needed (qw/AccountCtx AccountID TokenType Token ExpiresAt/) {
        if ( !$Param{$Needed} ) {
            $Kernel::OM->Get('Kernel::System::Log')->Log(
                Priority => 'error',
                Message  => "Need $Needed!",
            );

            return;
        }
    }

    if ( !$Self->ValidateAccountCtx(%Param) ) {
        return;
    }

    if ( !$Self->ValidateTokenType(%Param) ) {
        return;
    }

    $Self->Delete(%Param);

    my $AccountCtx = $Param{AccountCtx};
    my $AccountID  = $Param{AccountID};
    my $TokenType  = $Param{TokenType};
    my $Token      = $Param{Token};
    my $ExpiresAt  = $Param{ExpiresAt};

    my $InsertSuccess = $DBObject->Do(
        SQL  => "INSERT INTO token_storage (account_ctx, account_id, token_type, token, expires_at) VALUES (?, ?, ?, ?, ?)",
        Bind => [ \$AccountCtx, \$AccountID, \$TokenType, \$Token, \$ExpiresAt ],
    );

    return $InsertSuccess;
}

=head2 Delete()

    my $Success = $TokenRepositoryObject->Delete(
        AccountCtx => 'Invoker'       # see Save method above
        AccountID   => 'FunctionalAccount1',
        TokenType   => 'refresh',              # optional
    );

    or

    my $Success = $TokenRepositoryObject->Delete(
        TokenID => <id>
    );

=cut

sub Delete {
    my ( $Self, %Param ) = @_;

    my $DBObject = $Kernel::OM->Get('Kernel::System::DB');

    if ( $Param{TokenID} ) {

        my $TokenID = $Param{TokenID};

        my $DeleteSuccess = $DBObject->Do(
            SQL  => "DELETE FROM token_store WHERE id = ?",
            Bind => [ \$TokenID ],
        );

        return $DeleteSuccess;
    }

    for my $Needed (qw/AccountCtx AccountID/) {
        if ( !$Param{$Needed} ) {
            $Kernel::OM->Get('Kernel::System::Log')->Log(
                Priority => 'error',
                Message  => "Need $Needed!",
            );

            return;
        }
    }

    if ( !$Self->ValidateAccountCtx(%Param) ) {
        return;
    }

    my $TokenType = $Param{TokenType};

    if ( $TokenType && !$Self->ValidateTokenType(%Param) ) {
        return;
    }

    my $AccountCtx = $Param{AccountCtx};
    my $AccountID  = $Param{AccountID};

    my $SQL  = "DELETE FROM token_storage WHERE account_ctx = ? AND account_id = ? ";
    my $Bind = [ \$AccountCtx, \$AccountID, ];

    if ($TokenType) {
        $SQL .= "AND token_type = ? ";
        push @$Bind, \$TokenType;
    }

    my $DeleteSuccess = $DBObject->Do(
        SQL  => $SQL,
        Bind => $Bind,
    );

    return $DeleteSuccess;
}

=head2 Cleanup()

    my $Success = $TokenRepositoryObject->Cleanup();

=cut

sub Cleanup {

    my ( $Self, %Param ) = @_;

    my $DBObject = $Kernel::OM->Get('Kernel::System::DB');

    my $DateTimeObject = $Kernel::OM->Create(
        'Kernel::System::DateTime'
    );

    $DateTimeObject->ToTimeZone(
        TimeZone => 'UTC'
    );

    my $Epoch = $DateTimeObject->ToEpoch();

    my $SQL  = "DELETE FROM token_storage WHERE expires_at < ? ";
    my $Bind = [ \$Epoch ];

    my $DeleteSuccess = $DBObject->Do(
        SQL  => $SQL,
        Bind => $Bind,
    );

    return $DeleteSuccess;
}

=head2 Get()

    my $TokenData = $TokenRepositoryObject->Get(
        AccountCtx => 'Provider',
        AccountID  => 'FunctionalAccount1',
        TokenType  => 'refresh',
    );

    or

    my $TokenData = $TokenRepositoryObject->Get(
        TokenID => <id>
    );

    where:

    $TokenData = {
        TokenID => <id>,
        AccountCtx => 'Invoker',
        AccountID => '<AccountID>',
        TokenType => 'refresh_token',
        Token => '<Token>',
        ExpiresAt => 1234, # unix epoch ts
    };

=cut

sub Get {
    my ( $Self, %Param ) = @_;

    $Self->Cleanup();

    my $DBObject = $Kernel::OM->Get('Kernel::System::DB');

    if ( $Param{TokenID} ) {

        my $TokenID = $Param{TokenID};

        $DBObject->Prepare(
            SQL => "SELECT id, account_ctx, account_id, token_type, token, expires_at
                      FROM token_storage WHERE id = ?  ",
            Bind  => [ \$TokenID ],
            Limit => 1
        );
    }
    else {

        for my $Needed (qw/AccountCtx AccountID TokenType/) {
            if ( !$Param{$Needed} ) {
                $Kernel::OM->Get('Kernel::System::Log')->Log(
                    Priority => 'error',
                    Message  => "Need $Needed!",
                );

                return;
            }
        }

        if ( !$Self->ValidateAccountCtx(%Param) ) {
            return;
        }

        if ( !$Self->ValidateTokenType(%Param) ) {
            return;
        }

        my $AccountCtx = $Param{AccountCtx};
        my $AccountID  = $Param{AccountID};
        my $TokenType  = $Param{TokenType};

        $DBObject->Prepare(
            SQL => "SELECT id, account_ctx, account_id, token_type, token, expires_at
                      FROM token_storage
                      WHERE account_ctx = ? AND account_id = ? AND token_type = ? ",
            Bind  => [ \$AccountCtx, \$AccountID, \$TokenType ],
            Limit => 1
        );
    }

    if ( my ( $TokenID, $AccountCtx, $AccountID, $TokenType, $Token, $ExpiresAt ) = $DBObject->FetchrowArray ) {

        return {
            TokenID    => $TokenID,
            AccountCtx => $AccountCtx,
            AccountID  => $AccountID,
            TokenType  => $TokenType,
            Token      => $Token,
            ExpiresAt  => $ExpiresAt,
        };
    }

    return;
}

=head2 List()

    Get a list of Tokens for Display.

    my $Tokens = $TokenRepositoryObject->List(
        AccountCTx   => 'Invoker',
        ExpiresAfter => Unix epoch timestamp, # optional
        TokenType    => 'refresh_token',      # optional, defaults to 'refresh_token'
    );

    where:

    my $Tokens = [
        {
            TokenID    => 1,
            AccountCtx => 'Invoker',
            AccountID  => 'FunctionalAccoungt1',
            TokenType  => 'refresh_token',
            Token      => <TokenData>,
            ExpiresAt  => UNIX epoch timestamp,
        },
        ...
    ];

=cut

sub List {

    my ( $Self, %Param ) = @_;

    $Self->Cleanup();

    my $DBObject = $Kernel::OM->Get('Kernel::System::DB');

    my $AccountCtx   = $Param{AccountCtx};
    my $ExpiresAfter = $Param{ExpiresAfter};
    my $TokenType    = $Param{TokenType} || 'refresh_token';

    my $SQL  = "SELECT id, account_ctx, account_id, token_type, token, expires_at FROM token_storage ";
    my $Bind = [];

    if ($AccountCtx) {

        $SQL .= "WHERE account_ctx = ? AND token_type = 'refresh_token' ";
        $Bind = [ \$AccountCtx ];
    }
    else {

        $SQL .= "WHERE token_type = 'refresh_token' ";
    }

    if ($ExpiresAfter) {

        $SQL .= "AND expires_at < ? ";
        push @$Bind, \$ExpiresAfter;
    }

    $SQL .= "ORDER BY account_ctx, account_id, expires_at ";

    $DBObject->Prepare(
        SQL  => $SQL,
        Bind => $Bind,
    );

    my @Result;
    while ( my ( $TokenID, $AccountCtx, $AccountID, $TokenType, $Token, $ExpiresAt ) = $DBObject->FetchrowArray ) {

        push @Result, {
            TokenID    => $TokenID,
            AccountCtx => $AccountCtx,
            AccountID  => $AccountID,
            TokenType  => $TokenType,
            Token      => $Token,
            ExpiresAt  => $ExpiresAt,
        };
    }

    return \@Result;
}

=head2 Lookup()

    Get a hashref of Tokens for Display.

    my $Tokens = $TokenRepositoryObject->Lookup(
        AccountCTx   => 'Invoker',
        ExpiresAfter => Unix epoch timestamp, # optional
        TokenType    => 'refresh_token',      # optional, defaults to 'refresh_token'
    );

    where:

    my $Tokens = {
        'FunctionalAccount1' = {
            TokenID    => 1,
            AccountCtx => 'Invoker',
            AccountID  => 'FunctionalAccoungt1',
            TokenType  => 'refresh_token',
            Token      => <TokenData>,
            ExpiresAt  => UNIX epoch timestamp,
        },
        ...
    ];

=cut

sub Lookup {

    my ( $Self, %Param ) = @_;

    # Get List of refreshable Tokens from DB
    my $GenericInterfaceTokens = $Self->List(%Param);

    # Build a lookup index
    my %GenericInterfaceTokenLookup = (
        Provider => {},
        Invoker  => {},
    );
    for my $GenericInterfaceToken (@$GenericInterfaceTokens) {
        $GenericInterfaceTokenLookup{ $GenericInterfaceToken->{AccountCtx} }->{ $GenericInterfaceToken->{AccountID} } = $GenericInterfaceToken;
    }

    return \%GenericInterfaceTokenLookup;
}

=head2 ValidateAccountCtx()

    Validate AccountCtx value.

    my $Boolean = $TokenRepositoryObject->ValidateAccountCtx( AccountCtx => 'GenericInterface' );

    returns true if AccountCtx is one of GenericInterface|MailAccount|User, false otherwise.

=cut

sub ValidateAccountCtx {
    my ( $Self, %Param ) = @_;

    if (
        $Param{AccountCtx} ne 'MailAccount' &&
        $Param{AccountCtx} ne 'Provider'    &&
        $Param{AccountCtx} ne 'Invoker'     &&
        $Param{AccountCtx} ne 'User'
        )
    {
        $Kernel::OM->Get('Kernel::System::Log')->Log(
            Priority => 'error',
            Message  => "AccountCtx must be one of 'MailAccount,Provider,Invoker,User', but was '$Param{AccountCtx}'.\n",
        );

        return 0;
    }

    return 1;
}

=head2 ValidateTokenType()

    Validate TokenType value.

    my $Boolean = $TokenRepositoryObject->ValidateTokenType( TokenType => 'refresh_token' );

    returns true if TokenType is one of access_token|id_token|refresh_token, false otherwise.

=cut

sub ValidateTokenType {
    my ( $Self, %Param ) = @_;

    if (
        $Param{TokenType} ne 'access_token'
        &&
        $Param{TokenType} ne 'id_token' &&
        $Param{TokenType} ne 'refresh_token'
        )
    {
        $Kernel::OM->Get('Kernel::System::Log')->Log(
            Priority => 'error',
            Message  => "TokenType must be one of 'access_token,id_token,refresh_token', but was '$Param{TokenType}'.\n",
        );

        return 0;
    }

    return 1;
}

1;
