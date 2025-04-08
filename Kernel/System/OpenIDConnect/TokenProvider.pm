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

package Kernel::System::OpenIDConnect::TokenProvider;

use strict;
use warnings;

# core modules

# CPAN modules

use LWP::Simple;
use LWP::UserAgent;
use HTTP::Request::Common;
use URI::Escape qw(uri_escape_utf8);
use Crypt::JWT  qw(decode_jwt);
use JSON;

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
    'Kernel::System::Main',
    'Kernel::System::OpenIDConnect',
    'Kernel::System::OpenIDConnect::FunctionalAccounts',
    'Kernel::System::OpenIDConnect::TokenRepository',
);

=head1 NAME

Kernel::System::OpenIDConnect::TokenProvider - methods for OpenIDConnect::TokenProvider

=head1 SYNOPSIS

Functional account functions for OpenID Connect

create an object

    use Kernel::System::ObjectManager;
    local $Kernel::OM = Kernel::System::ObjectManager->new();
    my $TokenProviderObject = $Kernel::OM->Get('Kernel::System::OpenIDConnect::TokenProvider');

=cut

sub new {
    my ( $Type, %Param ) = @_;

    # allocate new hash for object
    my $Self = {
        SSLOptionMap => {
            SSLCertificate    => 'SSL_cert_file',
            SSLKey            => 'SSL_key_file',
            SSLPassword       => 'SSL_passwd_cb',
            SSLCAFile         => 'SSL_ca_file',
            SSLCADir          => 'SSL_ca_path',
            SSLVerifyHostname => 'verify_hostname',
            SSLVerifyMode     => 'SSL_verify_mode',
        },
    };
    bless( $Self, $Type );

    return $Self;
}

=head2 Fetch()

Main interface for client code. Just use fetch to get a valid token from cache, from DB, via refresh_token,
or from scratch if credentials are known (like for password and client_credential grants).

Accounts using ahtorization_code grant might get undef and then have to initiate a browser based flow redirecting
the clients browser to the result from GetAuthURL()

FOr now only Provider and Invoker  accounts are allowed.

    my $TokenResult = $TokenProviderObject->Fetch(
        AccountCtx => 'Invoker',
        AccountID  => '<SomeAccountName>',
    );

    where TokenResult:

    my $TokenResult = {
        Success => 0|1,
        Token   => <token value on success>,
        Error   => <Error msg on error>
    };
=cut

sub Fetch {

    my ( $Self, %Param ) = @_;

    for my $Needed (qw/AccountCtx AccountID/) {
        if ( !$Param{$Needed} ) {
            $Kernel::OM->Get('Kernel::System::Log')->Log(
                Priority => 'error',
                Message  => "Need $Needed!",
            );

            return {
                Success => 0,
                Error   => "Invalid Parameters",
            };
        }
    }

    my $AccountCtx = $Param{AccountCtx};
    my $AccountID  = $Param{AccountID};

    my $FunctionalAccountsObject = $Kernel::OM->Get('Kernel::System::OpenIDConnect::FunctionalAccounts');
    my $Account                  = $FunctionalAccountsObject->GetOAuthAccount(
        AccountCtx => $AccountCtx,
        AccountID  => $AccountID,
    );

    if ( !IsHashRefWithData($Account) || $AccountCtx ne 'Invoker' ) {

        $Kernel::OM->Get('Kernel::System::Log')->Log(
            Priority => 'error',
            Message  => "Invoker AccountID $AccountID not found!",
        );

        return {
            Success => 0,
            Error   => "$AccountCtx AccountID $AccountID not found!",
        };
    }

    my $TokenType = $Param{TokenType} || $Account->{Token} || 'access_token';

    # 1) try fetch from Cache
    my $Token = $Self->_FetchTokenFromCache(
        AccountCtx => $AccountCtx,
        AccountID  => $AccountID,
        TokenType  => $TokenType,
    );

    return {
        Success => 1,
        Token   => $Token,
    } if $Token && $Self->IsTokenStillValid( Token => $Token );

    # 2) try fetch from DB
    my $TokenRepository = $Kernel::OM->Get('Kernel::System::OpenIDConnect::TokenRepository');

    my $TokenData = $TokenRepository->Get(
        AccountCtx => $AccountCtx,
        AccountID  => $AccountID,
        TokenType  => $TokenType,
    );

    $Token = $TokenData->{Token};

    return {
        Success => 1,
        Token   => $Token,
    } if $Token && $Self->IsTokenStillValid( Token => $Token );

    # 3) try refresh_token, if any

    my $RefreshToken = $TokenRepository->Get(
        AccountCtx => $AccountCtx,
        AccountID  => $AccountID,
        TokenType  => 'refresh_token',
    );

    if ($RefreshToken) {

        my $Result = $Self->FetchToken(
            AccountCtx   => $AccountCtx,
            AccountID    => $AccountID,
            TokenType    => $TokenType,
            RefreshToken => $RefreshToken->{Token},
        );

        return $Result unless $Result->{Success};

        return {
            Success => 1,
            Token   => $Result->{Token},
        } if $Result->{Token} && $Self->IsTokenStillValid( Token => $Result->{Token} );
    }

    # 4) if grant_type is not 'authorization_code' try fetch fresh token
    # using configured credentials

    if ( $Account->{GrantType} eq 'authorization_code' ) {

        $Kernel::OM->Get('Kernel::System::Log')->Log(
            Priority => 'error',
            Message  => "No valid refresh_token for Account $AccountCtx:$AccountID using grant_tpye 'authorization code' !",
        );

        return {
            Success => 0,
            Error   => "No valid refresh_token for Account $AccountCtx ($AccountID) using grant_tpye 'authorization code' !",
        };
    }

    return $Self->FetchToken(
        AccountCtx => $AccountCtx,
        AccountID  => $AccountID,
        TokenType  => $TokenType,
    );
}

=head2 sub RenewTokens()

Main interface for the refresh via refresh_tokens cron job.

    my $TokensProcessed = $TokenProviderObject->RenewTokens(
        Interval => 600 # time in mislisec between cron jobs
    );

=cut

sub RenewTokens {

    my ( $Self, %Param ) = @_;

    my $Interval = $Param{Interval};

    my $DateTimeObject = $Kernel::OM->Create(
        'Kernel::System::DateTime',
    );

    my $Success = $DateTimeObject->ToTimeZone(
        TimeZone => 'UTC'
    );

    my $Epoch = $DateTimeObject->ToEpoch() + $Interval;

    my $TokenRepository = $Kernel::OM->Get('Kernel::System::OpenIDConnect::TokenRepository');
    my $Tokens          = $TokenRepository->List(
        AccountCtx   => 'Invoker',
        ExpiresAfter => $Epoch
    );

    my $FunctionalAccountsObject = $Kernel::OM->Get('Kernel::System::OpenIDConnect::FunctionalAccounts');
    my $Accounts                 = $FunctionalAccountsObject->GetOAuthAccounts( AccountCtx => 'Invoker' );

    TOKEN:
    for my $Token (@$Tokens) {

        my $Account = $Accounts->{ $Token->{AccountID} };

        my $TokenType = $Account->{Token} || 'access_token';

        my $Result = $Self->FetchToken(

            AccountCtx   => $Token->{AccountCtx},
            AccountID    => $Token->{AccountID},
            TokenType    => $TokenType,
            RefreshToken => $Token->{Token},
        );

        $Token->{Result} = {
            Success => $Result->{Success},
            Error   => $Result->{Error},
        };
    }

    return $Tokens;
}

=head2 sub FetchToken()

    Called internally when password or client_credential grant are configured.
    Also calles when refreshing via refresh_token.

    Callled from client code when completing the authorization_code browser flow,
    passing the received Code parameter.

    my $TokenResult = $TokenProviderObject->FetchToken(
        AccountCtx => 'Invoker',
        AccountID  => '<SomeAccountName>',
    );

    or

    my $TokenResult = $TokenProviderObject->FetchToken(
        AccountCtx  => 'Invoker',
        AccountID   => '<SomeAccountName>',
        Code        => '<authorization_code "code" query parameter value>',
        RedirectURL => $RedirectURL, # redirect url used when initiating the browser flow
    );


    where TokenResult:

    my $TokenResult = {
        Success => 0|1,
        Token   => <token value on success>,
        Error   => <Error msg on error>
    };

=cut

sub FetchToken {

    my ( $Self, %Param ) = @_;

    for my $Needed (qw/AccountCtx AccountID/) {
        if ( !$Param{$Needed} ) {
            $Kernel::OM->Get('Kernel::System::Log')->Log(
                Priority => 'error',
                Message  => "Need $Needed!",
            );

            return {
                Success => 0,
                Error   => "Invalid Parameters !",
            };
        }
    }

    my $AccountID  = $Param{AccountID};
    my $AccountCtx = $Param{AccountCtx};

    if ( $AccountCtx ne 'Provider' && $AccountCtx ne 'Invoker' ) {

        $Kernel::OM->Get('Kernel::System::Log')->Log(
            Priority => 'error',
            Message  => "AccountCtx $AccountCtx not yet implemented!",
        );

        return {
            Success => 0,
            Error   => "AccountCtx $AccountCtx not yet implemented!",
        };
    }

    my $FunctionalAccountsObject = $Kernel::OM->Get('Kernel::System::OpenIDConnect::FunctionalAccounts');
    my $Account                  = $FunctionalAccountsObject->GetOAuthAccount(
        AccountCtx => $AccountCtx,
        AccountID  => $AccountID,
    );

    if ( !IsHashRefWithData($Account) ) {
        $Kernel::OM->Get('Kernel::System::Log')->Log(
            Priority => 'error',
            Message  => "Need functional account Invoker settings in SysConfig for $AccountID ($AccountCtx).",
        );

        return {
            Success => 0,
            Error   => "Need functional account Invoker settings in SysConfig for $AccountID ($AccountCtx).",
        };
    }

    # determine which token are we expected to pass to remote system
    my $TokenType         = $Account->{Token}             || 'access_token';
    my $ResourceParamName = $Account->{ResourceParamName} || 'resource';
    my $ResourceIds       = $Account->{ResourceIds};
    my $Scope             = $Account->{Scope};

    my $OpenIDConfig = $FunctionalAccountsObject->GetOpenIDConfig(
        AccountCtx => $AccountCtx,
        AccountID  => $AccountID,
    );

    my $OpenIDProviderData = $FunctionalAccountsObject->GetProviderData(
        AccountCtx => $AccountCtx,
        AccountID  => $AccountID,
    );

    # fetch openid token endpoint

    if ( !$OpenIDProviderData->{OpenIDConfiguration}{token_endpoint} ) {
        $Kernel::OM->Get('Kernel::System::Log')->Log(
            Priority => 'error',
            Message  => "Could not get the token_endpoint for $AccountCtx $AccountID.",
        );

        return {
            Success => 0,
            Error   => "Could not get the token_endpoint for $AccountCtx $AccountID.",
        };
    }

    # prepare the fetch token request
    my $UserAgent = $Self->_GetUserAgent( OpenIDConfig => $OpenIDConfig );

    # prepare post data
    my $PostData;

    if ( $Param{RefreshToken} ) {

        # refresh_token flow
        $PostData = [
            grant_type    => 'refresh_token',
            refresh_token => $Param{RefreshToken},
        ];
    }
    elsif (
        $Account->{GrantType} eq 'password'
        &&
        IsStringWithData( $Account->{Username} ) &&
        IsStringWithData( $Account->{Password} )
        )
    {

        # password flow
        $PostData = [
            grant_type => 'password',
            username   => $Account->{Username},
            password   => $Account->{Password},
        ];
    }
    elsif ( $Account->{GrantType} eq 'client_credentials' ) {

        # client_credentials flow
        $PostData = [
            grant_type => 'client_credentials',
        ];
    }
    elsif ( $Param{Code} && $Account->{GrantType} eq 'authorization_code' ) {

        # authorization code
        $PostData = [
            grant_type   => 'authorization_code',
            code         => $Param{Code},
            redirect_uri => $Param{RedirectURL},
        ];
    }

    if ( !$Param{RefreshToken} && $ResourceIds && $ResourceIds ne '' ) {

        push @$PostData, "$ResourceParamName" => $ResourceIds;
    }

    if ( !$Param{RefreshToken} && $Scope && $Scope ne '' ) {

        push @$PostData, scope => $Scope;
    }

    # actually send the request
    my $Response = $Self->_SendRequest(
        OpenIDConfig => $OpenIDConfig,
        UserAgent    => $UserAgent,
        EndPoint     => $OpenIDProviderData->{OpenIDConfiguration}{token_endpoint},
        PostData     => $PostData,
    );

    if ( !$Response->{Success} ) {

        return {
            Success => 0,
            Error   => "Error fetching Token for $AccountCtx $AccountID: " . $Response->{Error},
        };
    }

    my $DecodedContent = $Response->{Content};

    my $Token = $DecodedContent->{$TokenType};
    if ( !$Token ) {

        $Kernel::OM->Get('Kernel::System::Log')->Log(
            Priority => 'error',
            Message  => "Did not receive the desired TokenType '$TokenType' in provider response!",
        );

        return {
            Success => 0,
            Error   => "Did not receive the desired TokenType '$TokenType' in provider response for $AccountCtx $AccountID!",
        };
    }

    # check time left
    my $TimeLeft = $Self->TimeLeft(
        Token => $Token,
    );

    if ( !$TimeLeft || $TimeLeft < 1 ) {

        $Kernel::OM->Get('Kernel::System::Log')->Log(
            Priority => 'error',
            Message  => "Time left on fresh token is: $TimeLeft s!",
        );

        return {
            Success => 0,
            Error   => "Time left on fresh token is: $TimeLeft s for $AccountCtx $AccountID!",
        };
    }

    # process and persist the Tokens
    if ( $DecodedContent->{id_token} ) {

        $Self->_ProcessNewToken(
            OpenIDConfig => $OpenIDConfig,
            AccountCtx   => $AccountCtx,
            AccountID    => $AccountID,
            TokenType    => 'id_token',
            Token        => $DecodedContent->{id_token},
        );
    }

    if ( $DecodedContent->{access_token} ) {

        $Self->_ProcessNewToken(
            OpenIDConfig => $OpenIDConfig,
            AccountCtx   => $AccountCtx,
            AccountID    => $AccountID,
            TokenType    => 'access_token',
            Token        => $DecodedContent->{access_token},
        );
    }

    if ( $DecodedContent->{refresh_token} ) {

        $Self->_ProcessNewToken(
            OpenIDConfig => $OpenIDConfig,
            AccountCtx   => $AccountCtx,
            AccountID    => $AccountID,
            TokenType    => 'refresh_token',
            Token        => $DecodedContent->{refresh_token},
        );
    }

    return {
        Success => 1,
        Token   => $Token,
    };
}

=head2 GetAuthURL()

Build the URL to request an authorization code.

Example:
    my $AuthURL = $TokenProviderObject->GetAuthURL(
        AccountID   => '<FunctionalAccountName>',
        AccountCtx  => 'Provider',
        RedirectURI => 'https://your.otobo.url/otobo/index.pl?Action=AdminOAuthTokenStore&Subaction=OAuth'
    );

Returns:
    $AuthURL = https://login.microsoftonline.com/common/oauth2/v2.0/authorize?client_id=077d2059-219...

=cut

sub GetAuthURL {
    my ( $Self, %Param ) = @_;

    for my $Needed (qw/AccountCtx AccountID/) {
        if ( !$Param{$Needed} ) {
            $Kernel::OM->Get('Kernel::System::Log')->Log(
                Priority => 'error',
                Message  => "Need $Needed!",
            );

            return;
        }
    }

    my $AccountID  = $Param{AccountID};
    my $AccountCtx = $Param{AccountCtx};

    my $ConfigObject = $Kernel::OM->Get('Kernel::Config');
    my $LogObject    = $Kernel::OM->Get('Kernel::System::Log');

    my $FunctionalAccountsObject = $Kernel::OM->Get('Kernel::System::OpenIDConnect::FunctionalAccounts');
    my $Account                  = $FunctionalAccountsObject->GetOAuthAccount(
        AccountCtx => $AccountCtx,
        AccountID  => $AccountID,
    );

    if ( !IsHashRefWithData($Account) ) {
        $Kernel::OM->Get('Kernel::System::Log')->Log(
            Priority => 'error',
            Message  => 'Need functional account Invoker settings in SysConfig.',
        );

        return;
    }

    my $TokenType = $Account->{Token} || 'access_token';

    my $OpenIDConfig = $FunctionalAccountsObject->GetOpenIDConfig(
        AccountCtx => $AccountCtx,
        AccountID  => $AccountID,
    );

    #    my $OAuthConfig = $ConfigObject->Get('OAuth2::Settings');
    # TODO

    # Create a random string to prevent cross-site requests.
    my $RandomString = $Kernel::OM->Get('Kernel::System::Main')->GenerateRandomString(
        Length => 22    #$OAuthConfig->{StateNonceLength} || 22,
    );

    my $AuthRequest = {
        ResponseType => ['code'],
        State        => $RandomString,
        RedirectURI  => $Param{RedirectURI},
    };

    my $ResourceIds = $Account->{ResourceIds};
    if ( $ResourceIds && $ResourceIds ne '' ) {

        my $ResourceParamName = $Account->{ResourceParamName} || 'resource';

        my @Resources = split( / +/, $ResourceIds );
        $AuthRequest->{"$ResourceParamName"} = \@Resources;
        $AuthRequest->{ResourceParamName}    = "$ResourceParamName";
    }

    my $Scope = $Account->{Scope};
    if ( $Scope && $Scope ne '' ) {

        my @Scopes = split( / +/, $Scope );
        $AuthRequest->{Scope} = \@Scopes;
    }

    if ( $TokenType eq 'id_token' ) {

        push $AuthRequest->{ResponseType}->@*, 'id_token';
    }

    my $OpenIDConnectObject = $Kernel::OM->Get('Kernel::System::OpenIDConnect');

    my $RedirectURL = $OpenIDConnectObject->BuildRedirectURL(
        AuthRequest      => $AuthRequest,
        Login            => $Param{Login},
        Prompt           => $Param{Prompt},
        ClientSettings   => $OpenIDConfig->{ClientSettings},
        ProviderSettings => $OpenIDConfig->{ProviderSettings},
    );

    if(!$RedirectURL) {
        return;
    }

    $Param{RedirectURL} = $AuthRequest->{RedirectURI};

    # Save all parameters to use after successful authorization.
    $Kernel::OM->Get('Kernel::System::Cache')->Set(
        Type  => 'TokenProvider',
        TTL   => 60 * 15,                                       # TODO make configurable
        Key   => "TokenProvider::OAuth2State::$RandomString",
        Value => \%Param,
    );

# TODO: endsession_endpoint in provider info
# my $LogoutURL = "https://keycloak:8443/realms/master/protocol/openid-connect/logout?client_id=otobo&post_logout_redirect_uri=";
# $LogoutURL .= uri_escape_utf8($RedirectURL);
# https://auth-server/auth/realms/{realm-name}/protocol/openid-connect/logout?redirect_uri=https://auth-server/auth/realms/{realm-name}/protocol/openid-connect/auth?client_id=client_id&redirect_uri
# print STDERR "WRAPPED: $LogoutURL\n";

    return $RedirectURL;
}

=head2 sub IsTokenStillValid()

    Return true if a Token is still valid

    my $Boolean = $TokenProviderObject->IsTokenStillValid( Token => $Token );

=cut

sub IsTokenStillValid {

    my ( $Self, %Param ) = @_;

    for my $Needed (qw/Token/) {
        if ( !$Param{$Needed} ) {
            $Kernel::OM->Get('Kernel::System::Log')->Log(
                Priority => 'error',
                Message  => "Need $Needed!",
            );

            return;
        }
    }

    # TODO: make configurable
    my $MinTimeTillExpired = 30;
    my $Token              = $Param{Token};

    my $TimeLeft = $Self->TimeLeft(
        Token => $Token,
    );

    if ( $TimeLeft > $MinTimeTillExpired ) {
        return $Token if $TimeLeft > $MinTimeTillExpired;
    }

    return;
}

=head2 TimeLeft()

Returns the time in seconds a token is still valid

    my $TimeLeft = $TokenProviderObject->TimeLeft(
        Token          => $Token,
    );

=cut

sub TimeLeft {
    my ( $Self, %Param ) = @_;

    for my $Needed (qw/Token/) {
        if ( !$Param{$Needed} ) {
            $Kernel::OM->Get('Kernel::System::Log')->Log(
                Priority => 'error',
                Message  => "Need $Needed!",
            );
            return;
        }
    }

    my $TokenData;
    eval {
        $TokenData = decode_jwt(
            token            => $Param{Token},
            ignore_signature => 1
        );
    };
    if ($@) {
        return 0;
    }

    if ( !$TokenData->{exp} ) {
        $Kernel::OM->Get('Kernel::System::Log')->Log(
            Priority => 'error',
            Message  => "No expiration time found in provided token!",
        );
        return;
    }

    # time window
    my $CurrentTime = $Kernel::OM->Create('Kernel::System::DateTime')->ToEpoch();

    return $TokenData->{exp} - $CurrentTime;
}

sub EmptyCache {

    my ( $Self, %Param ) = @_;

    for my $Needed (qw/AccountID AccountCtx/) {
        if ( !$Param{$Needed} ) {
            $Kernel::OM->Get('Kernel::System::Log')->Log(
                Priority => 'error',
                Message  => "Need $Needed!",
            );

            return;
        }
    }

    my $AccountCtx = $Param{AccountCtx};
    my $AccountID  = $Param{AccountID};

    my $CacheObject = $Kernel::OM->Get('Kernel::System::Cache');

    for my $TokenType (qw/access_token id_token refresh_token/) {

        my $CacheType = "TokenProvider";
        my $CacheKey  = join( ',', $AccountCtx, $AccountID, $TokenType );

        my $Token = $CacheObject->Delete(
            Type => $CacheType,
            Key  => $CacheKey,
        );
    }

    my $FunctionalAccounts = $Kernel::OM->Get('Kernel::System::OpenIDConnect::FunctionalAccounts');
    my $OpenIDConfig = $FunctionalAccounts->GetOpenIDConfig(
        AccountCtx => $AccountCtx,
        AccountID  => $AccountID,
    );

    my $ProviderKey = 'ProviderData' . ( $OpenIDConfig->{ProviderSettings}->{Name} // '' );

    my $OpenIDProviderData = $Kernel::OM->Get('Kernel::System::Cache')->Delete(
        Type => 'OpenIDConnect',
        Key  => $ProviderKey,
    );
}

# helpers

sub _FetchTokenFromCache {
    my ( $Self, %Param ) = @_;

    for my $Needed (qw/AccountID AccountCtx TokenType/) {
        if ( !$Param{$Needed} ) {
            $Kernel::OM->Get('Kernel::System::Log')->Log(
                Priority => 'error',
                Message  => "Need $Needed!",
            );

            return;
        }
    }

    my $AccountCtx = $Param{AccountCtx};
    my $AccountID  = $Param{AccountID};
    my $TokenType  = $Param{TokenType};

    my $CacheObject = $Kernel::OM->Get('Kernel::System::Cache');

    my $CacheType = "TokenProvider";
    my $CacheKey  = join( ',', $AccountCtx, $AccountID, $TokenType );

    my $Token = $CacheObject->Get(
        Type => $CacheType,
        Key  => $CacheKey,
    );

    return $Token;
}

sub _PopulateCache {

    my ( $Self, %Param ) = @_;

    for my $Needed (qw/AccountID AccountCtx TokenType Token ExpiresAt/) {
        if ( !$Param{$Needed} ) {
            $Kernel::OM->Get('Kernel::System::Log')->Log(
                Priority => 'error',
                Message  => "Need $Needed!",
            );

            return;
        }
    }

    my $AccountCtx = $Param{AccountCtx};
    my $AccountID  = $Param{AccountID};
    my $TokenType  = $Param{TokenType};
    my $Token      = $Param{Token};
    my $ExpiresAt  = $Param{ExpiresAt};

    my $CacheObject = $Kernel::OM->Get('Kernel::System::Cache');

    my $CacheType = "TokenProvider";
    my $CacheKey  = join( ',', $AccountCtx, $AccountID, $TokenType );

    # check time left
    my $TimeLeft = $Self->TimeLeft(
        Token => $Token,
    );

    if ( !$TimeLeft || $TimeLeft < 1 ) {
        $Kernel::OM->Get('Kernel::System::Log')->Log(
            Priority => 'error',
            Message  => "Time left on fresh token is: $TimeLeft s!",
        );
        return;
    }

    $CacheObject->Set(
        Type  => $CacheType,
        Key   => $CacheKey,
        Value => $Token,
        TTL   => $TimeLeft,
    );

    return $Token;
}

sub _GetUserAgent {

    my ( $Self, %Param ) = @_;

    my $OpenIDConfig = $Param{OpenIDConfig};

    # prepare the fetch token request
    my $UserAgent = LWP::UserAgent->new();

    # SSL options
    if ( $OpenIDConfig->{ProviderSettings}{SSLOptions} ) {
        OPTION:
        for my $Key ( keys $OpenIDConfig->{ProviderSettings}{SSLOptions}->%* ) {
            next OPTION if !$Self->{SSLOptionMap}{$Key};

            if ( $Key eq 'SSLPassword' ) {
                $UserAgent->ssl_opts(
                    $Self->{SSLOptionMap}{$Key} => sub { $OpenIDConfig->{ProviderSettings}{SSLOptions}{$Key} },
                );

                next OPTION;
            }

            $UserAgent->ssl_opts(
                $Self->{SSLOptionMap}{$Key} => $OpenIDConfig->{ProviderSettings}{SSLOptions}{$Key},
            );
        }
    }

    return $UserAgent;
}

sub _SendRequest {

    my ( $Self, %Param ) = @_;

    my $OpenIDConfig = $Param{OpenIDConfig};
    my $UserAgent    = $Param{UserAgent};
    my $EndPoint     = $Param{EndPoint};
    my $PostData     = $Param{PostData};

    # send the data form-encoded
    my $Request = POST(
        $EndPoint,
        $PostData
    );

    # add client_id and client_secret to authenticate the client
    if ( !$OpenIDConfig->{ClientSettings}{ClientID} || !$OpenIDConfig->{ClientSettings}{ClientSecret} ) {
        $Kernel::OM->Get('Kernel::System::Log')->Log(
            Priority => 'error',
            Message  => 'Need ClientID and ClientSecret!',
        );

        return {
            Success => 0,
            Error   => 'Need ClientID and ClientSecret!',
        };
    }

    $Request->authorization_basic( $OpenIDConfig->{ClientSettings}{ClientID}, $OpenIDConfig->{ClientSettings}{ClientSecret} );

    # execute request
    my $Response = $UserAgent->request($Request);
    my $Content  = $Response->content();

    if ( !$Content ) {
        $Kernel::OM->Get('Kernel::System::Log')->Log(
            Priority => 'error',
            Message  => "Got no content when requesting Token. Response Code: $Response->code();",
        );

        return {
            Success => 0,
            Error   => "Got no content when requesting Token. Response Code: $Response->code();",
        };
    }

    # decode content
    my $DecodedContent = $Kernel::OM->Get('Kernel::System::JSON')->Decode(
        Data => $Content,
    );

    if ( !IsHashRefWithData($DecodedContent) ) {
        $Kernel::OM->Get('Kernel::System::Log')->Log(
            Priority => 'error',
            Message  => "Got error when requesting IDToken. Returned data (raw): '$Content'",
        );

        return {
            Success => 0,
            Error   => "Got no content when requesting Token. Response Code: $Response->code();",
        };
    }

    # fetch the desired token (access_token (default) or id_token)
    if ( $DecodedContent->{error} ) {
        $Kernel::OM->Get('Kernel::System::Log')->Log(
            Priority => 'error',
            Message  => "$DecodedContent->{error}; Description: $DecodedContent->{error_description};",
        );

        return {
            Success => 0,
            Error   => "$DecodedContent->{error}; Description: $DecodedContent->{error_description};",
        };
    }

    return {
        Success => 1,
        Content => $DecodedContent,
    };
}

sub _ProcessNewToken {

    my ( $Self, %Param ) = @_;

    my $AccountCtx   = $Param{AccountCtx};
    my $AccountID    = $Param{AccountID};
    my $OpenIDConfig = $Param{OpenIDConfig};
    my $TokenType    = $Param{TokenType};
    my $Token        = $Param{Token};

    my $TokenData;

    if ( $TokenType eq 'refresh_token' ) {

        my $Result = decode_jwt(
            token            => $Token,
            ignore_signature => 1
        );

        return unless $Result;

        $TokenData = $Result;
    }
    else {

        my $OpenIDConnectObject = $Kernel::OM->Get('Kernel::System::OpenIDConnect');

        my $Result = $OpenIDConnectObject->ValidateToken(
            Token                => $Token,
            ProviderSettings     => $OpenIDConfig->{ProviderSettings},
            ClientSettings       => $OpenIDConfig->{ClientSettings},
            SkipValidateAudience => $TokenType eq 'id_token' ? 0 : 1,
        );

        return unless $Result->{Success};

        $TokenData = $Result->{TokenData};
    }

    my $ExpiresAt = $TokenData->{exp};

    my $TokenRepository = $Kernel::OM->Get('Kernel::System::OpenIDConnect::TokenRepository');

    my $Success = $TokenRepository->Save(
        AccountCtx => $AccountCtx,
        AccountID  => $AccountID,
        TokenType  => $TokenType,
        Token      => $Token,
        ExpiresAt  => $ExpiresAt,
    );

    return unless $Success;

    $Self->_PopulateCache(
        AccountCtx => $AccountCtx,
        AccountID  => $AccountID,
        TokenType  => $TokenType,
        Token      => $Token,
        ExpiresAt  => $ExpiresAt,
    );

    return 1;
}

1;
