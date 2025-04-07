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

package Kernel::GenericInterface::Operation::Session::Common;

use strict;
use warnings;

use Kernel::System::VariableCheck qw(:all);

our $ObjectManagerDisabled = 1;

=head1 NAME

Kernel::GenericInterface::Operation::Session::Common - Base class for Session Operations

=head1 PUBLIC INTERFACE

=head2 CreateSessionID()

performs user authentication and return a new SessionID value

    my $SessionID = $CommonObject->CreateSessionID(
        Data {
            UserLogin         => 'Agent1',
            CustomerUserLogin => 'Customer1',       # optional, provide UserLogin or
                                                    #   CustomerUserLogin
            Password          => 'some password',   # plain text password
        }
    );

Returns undef on failure or

    $SessionID = 'AValidSessionIDValue';         # the new session id value

=cut

sub CreateSessionID {
    my ( $Self, %Param ) = @_;

    my $User;
    my %UserData;
    my $UserType;

# Rother OSS / OAuth2
    # special case for session creation based on OAuth Bearer token
    if ( $Param{Data}->{BearerToken} ) {
        return $Self->_CreateSessionIDFromBearerToken(%Param);
    }
# EO / OAuth2

    # get params
    my $PostPw = $Param{Data}->{Password} || '';

    if ( defined $Param{Data}->{UserLogin} && $Param{Data}->{UserLogin} ) {

        # if UserLogin
        my $PostUser = $Param{Data}->{UserLogin} || '';

        # check submitted data
        $User = $Kernel::OM->Get('Kernel::System::Auth')->Auth(
            User => $PostUser,
            Pw   => $PostPw,
        );
        %UserData = $Kernel::OM->Get('Kernel::System::User')->GetUserData(
            User  => $User,
            Valid => 1,
        );
        $UserType = 'User';
    }
    elsif ( defined $Param{Data}->{CustomerUserLogin} && $Param{Data}->{CustomerUserLogin} ) {

        # if UserCustomerLogin
        my $PostUser = $Param{Data}->{CustomerUserLogin} || '';

        # check submitted data
        $User = $Kernel::OM->Get('Kernel::System::CustomerAuth')->Auth(
            User => $PostUser,
            Pw   => $PostPw,
        );
        %UserData = $Kernel::OM->Get('Kernel::System::CustomerUser')->CustomerUserDataGet(
            User  => $PostUser,
            Valid => 1,
        );
        $UserType = 'Customer';
    }

    # login is invalid
    return if !$User;

    # create new session id
    my $NewSessionID = $Kernel::OM->Get('Kernel::System::AuthSession')->CreateSessionID(
        %UserData,
        UserLastRequest => $Kernel::OM->Create('Kernel::System::DateTime')->ToEpoch(),
        UserType        => $UserType,
        SessionSource   => 'GenericInterface',
    );

    return $NewSessionID if ($NewSessionID);

    return;
}

# Rother OSS / OAuth2

sub _CreateSessionIDFromBearerToken {
    my ( $Self, %Param ) = @_;

    my $BearerToken = $Param{Data}->{BearerToken};

    my $ConfigObject = $Kernel::OM->Get('Kernel::Config');

    # get all configured OAuth Accounts for API access
    my $Accounts = $ConfigObject->Get('OpenIDConnect::Provider::Accounts');

    if ( !IsHashRefWithData($Accounts) ) {
        return;
    }

    # loop though accounts and try to authenticate
    ACCOUNTNAME:
    for my $AccountName ( keys %$Accounts ) {

        # get functional account data
        my $Account = $Accounts->{$AccountName};

        # validate the token
        my $Return = $Self->_ValidateToken(
            AccountName => $AccountName,
            Account     => $Account,
            IDToken     => $BearerToken,
            %Param,
        );

        # if token not validated, try next token
        if ( !$Return->{Success} ) {
            next ACCOUNTNAME;
        }

        # IDKey is the name of the claim we match agains the otobo user login, typically 'sub'
        my $IDKey = $Account->{UID} || 'sub';

        # lookup the UserLogin from the Token data
        my $UserLogin = $Return->{TokenData}->{$IDKey};

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
        $Param{DebuggerObject}->Debug(
            Summary => 'Bearer Token decoded:',
            Data    => $Return->{TokenData},
        );

        # create new session id
        my $NewSessionID = $Kernel::OM->Get('Kernel::System::AuthSession')->CreateSessionID(
            %UserData,
            UserLastRequest => $Kernel::OM->Create('Kernel::System::DateTime')->ToEpoch(),
            UserType        => 'User',
            SessionSource   => 'GenericInterface',
        );

        # if we have a valis session, we are done.
        return $NewSessionID if ($NewSessionID);

        # otherwise try next account
        next ACCOUNTNAME;
    }

    return;
}

# validate 

sub _ValidateToken {
    my ( $Self, %Param ) = @_;

    my $Return = { Success => 0 };

    for my $Needed (qw/IDToken Account AccountName/) {
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

    # extract OAuth config parameetrs
    my $ConfigObject        = $Kernel::OM->Get('Kernel::Config');
    my $OpenIdConnectConfig = $ConfigObject->Get( $Account->{OpenIDConfig} || 'AuthModule::OpenIDConnect::Config' );

    if ( !IsHashRefWithData($OpenIdConnectConfig) ) {
        print STDERR "INVALID OIDC CONFIG\n";
        $Param{DebuggerObject}->Debug(
            Summary => 'OpenID Connect Config is Invalid.',
            Data    => $Account->{OpenIDConfig} || 'AuthModule::OpenIDConnect::Config',
        );

        return $Return;
    }

    for my $Needed (qw/ProviderSettings ClientSettings/) {
        if ( !IsHashRefWithData( $OpenIdConnectConfig->{$Needed} ) ) {

            $Param{DebuggerObject}->Debug(
                Summary => 'Invalid OpenID Connect Config - missing $Needed.',
                Data    => $Return->{TokenData},
            );

            return $Return;
        }
    }

    my $ProviderSettings = $OpenIdConnectConfig->{ProviderSettings};
    my $ClientSettings   = $OpenIdConnectConfig->{ClientSettings};

    my $OpenIDConnectObject = $Kernel::OM->Get('Kernel::System::OpenIDConnect');

    my $TokenData;

    # this might throw, in which case validation failed
    eval {
        $TokenData = $OpenIDConnectObject->DecodeIDToken(
            %Param,
            ProviderSettings => $ProviderSettings,
            ClientSettings   => $ClientSettings,
        );
    };
    if ($@) {

        # print STDERR $@;
        return $Return;
    }

    return $Return if !$TokenData;

    # assert the claims we expect are in the token
    for my $Needed (qw/iss sub aud exp iat/) {
        if ( !$TokenData->{$Needed} ) {
            $Kernel::OM->Get('Kernel::System::Log')->Log(
                Priority => 'error',
                Message  => "Token invalid: claim <$Needed> not included.",
            );

            return $Return;
        }
    }

    # get provider settings
    my $ProviderKey        = 'ProviderData' . ( $ProviderSettings->{Name} // '' );
    my $OpenIDProviderData = $Kernel::OM->Get('Kernel::System::Cache')->Get(
        Type => 'OpenIDConnect',
        Key  => $ProviderKey,
    );

    # if nothing is cached, get the data
    if ( !$OpenIDProviderData ) {
        $OpenIDProviderData = $OpenIDConnectObject->_ProviderDataGet(
            ProviderSettings => $Param{ProviderSettings},
        );
    }

    # get issuer
    my $Issuer = $OpenIDProviderData->{OpenIDConfiguration}{issuer};

    # do the validation
    if ( $TokenData->{iss} ne $Issuer ) {
        return $Return;
    }

    # assert the audience
    my $ExpectedAudience = $Account->{Audience} || $Param{ClientSettings}{ClientID};

    if ($ExpectedAudience) {

        my @Audience = ref $TokenData->{aud} ? @{ $TokenData->{aud} } : ( $TokenData->{aud} );

        if ( !grep { $_ eq $ExpectedAudience } @Audience ) {
            return $Return;
        }
    }

    # optionally assert the authorized party (azp)
    if ( $Account->{AuthorizedParty} ) {

        if ( ref $TokenData->{aud} && !$TokenData->{azp} ) {

            return $Return;
        }

        if ( $TokenData->{azp} ) {

            my $Found = 0;

            PARTY:
            for my $Party ( $Account->{AuthorizedParty}->@* ) {

                if ( $TokenData->{azp} eq $Party ) {
                    $Found = 1;
                    last PARTY;
                }
            }

            if ( !$Found ) {
                return $Return;
            }
        }
    }

    # ttl
    my $CurrentTime = $Kernel::OM->Create('Kernel::System::DateTime')->ToEpoch();
    my $Leeway      = int( $Param{Leeway} // 2 );

    if ( $TokenData->{iat} - $Leeway > $CurrentTime ) {
        $Kernel::OM->Get('Kernel::System::Log')->Log(
            Priority => 'error',
            Message  => "<iat> invalid. IDToken creation time is in the future. Token: $TokenData->{iat}; Current: $CurrentTime;",
        );

        return $Return;
    }

    if ( $TokenData->{exp} + $Leeway <= $CurrentTime ) {
        $Kernel::OM->Get('Kernel::System::Log')->Log(
            Priority => 'error',
            Message  => "<exp> invalid. IDToken expired. Expiration Time: $TokenData->{exp}; Current: $CurrentTime;",
        );
        $Return->{Error} = 'exp';

        return $Return;
    }

    return {
        Success   => 1,
        TokenData => $TokenData,
    };
}
# Rother OSS / OAuth2


1;
