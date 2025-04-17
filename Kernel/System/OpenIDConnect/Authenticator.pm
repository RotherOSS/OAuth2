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

package Kernel::System::OpenIDConnect::Authenticator;

use strict;
use warnings;

# core modules

# CPAN modules

# OTOBO modules
use Kernel::System::VariableCheck qw(:all);

use namespace::autoclean;

our @ObjectDependencies = (
    'Kernel::System::Log',
    'Kernel::System::User',
    'Kernel::System::OpenIDConnect::Token',
    'Kernel::System::OpenIDConnect::UserMappings',
);

=head1 NAME

Kernel::System::OpenIDConnect::Authenticator

=for stopwords OIDC

authenticate incoming OIDC OAuth2 Tokens

=head1 SYNOPSIS

authenticate incoming OIDC OAuth2 Tokens

create an object

    use Kernel::System::ObjectManager;
    local $Kernel::OM = Kernel::System::ObjectManager->new();
    my $AuthenticatorObject = $Kernel::OM->Get('Kernel::System::OpenIDConnect::Authenticator');

=cut

sub new {
    my ( $Type, %Param ) = @_;

    # allocate new hash for object
    my $Self = {};
    bless( $Self, $Type );

    return $Self;
}

=head2 Authenticate()

    Authenticates an incoming Bearer Token

    my $Result = $AuthenticatorObject->Authenticate(
        Token => $Token,
    );

    where

    my $Result = {
            Success   => 1,
            TokenData => $TokenData,
            UserData  => \%UserData,
    };

=cut

sub Authenticate {
    my ( $Self, %Param ) = @_;

    my $BearerToken = $Param{Token};

    my $Result = { Success => 0 };

    # get all configured OAuth Accounts for API access
    my $UserMappings = $Kernel::OM->Get('Kernel::System::OpenIDConnect::UserMappings');
    my $Accounts     = $UserMappings->GetUserMappings();

    if ( !IsHashRefWithData($Accounts) ) {
        return $Result;
    }

    # loop though accounts and try to authenticate
    ACCOUNTNAME:
    for my $AccountName ( keys %$Accounts ) {

        # get functional account data
        my $Account = $Accounts->{$AccountName};

        # validate the token
        my $TokenResult = $Self->_ValidateToken(
            AccountName => $AccountName,
            Account     => $Account,
            Token       => $BearerToken,
            %Param,
        );

        # if token not validated, try next token
        if ( !$TokenResult->{Success} ) {
            next ACCOUNTNAME;
        }

        # IDKey is the name of the claim we match agains the otobo user login, typically 'sub'
        my $IDKey = $Account->{UID} || 'sub';

        # lookup the UserLogin from the Token data
        my $UserLogin = $TokenResult->{TokenData}->{$IDKey};

        if ( !IsStringWithData($UserLogin) ) {
            next ACCOUNTNAME;
        }

        # see if the user login matches the expected login
        if ( $Account->{UserLogin} ) {
            if ( $Account->{UserLogin} ne $UserLogin ) {
                next ACCOUNTNAME;
            }
        }

        # resolve UserLogin from otobo user db table
        my %UserData = $Kernel::OM->Get('Kernel::System::User')->GetUserData(
            User  => $UserLogin,
            Valid => 1,
        );

        # assert the user actually exists in database
        if ( !$UserData{UserID} ) {
            next ACCOUNTNAME;
        }

        # report success!
        return {
            Success   => 1,
            TokenData => $TokenResult->{TokenData},
            UserData  => \%UserData,
        };
    }

    return $Result;
}

# validate

sub _ValidateToken {
    my ( $Self, %Param ) = @_;

    my $Return = { Success => 0 };

    for my $Needed (qw/Token Account AccountName/) {
        if ( !$Param{$Needed} ) {
            $Kernel::OM->Get('Kernel::System::Log')->Log(
                Priority => 'error',
                Message  => "Need $Needed!",
            );

            return $Return;
        }
    }

    my $Account     = $Param{Account};
    my $AccountName = $Param{AccountName};

    my $UserMappings = $Kernel::OM->Get('Kernel::System::OpenIDConnect::UserMappings');
    my $OpenIDConfig = $UserMappings->GetOpenIDConfig(
        AccountID => $AccountName,
    );

    my $ClientSettings   = $OpenIDConfig->{ClientSettings};
    my $ExpectedAudience = $Account->{Audience} || $ClientSettings->{ClientID};

    my $TokenObject = $Kernel::OM->Get('Kernel::System::OpenIDConnect::Token');

    return $TokenObject->Validate(
        Token            => $Param{Token},
        OpenIDConfig     => $OpenIDConfig,
        ExpectedAudience => $ExpectedAudience,
        AuthorizedParty  => $Account->{AuthorizedParty},
        ExpectedScopes   => $Account->{Scope},
    );
}

1;
