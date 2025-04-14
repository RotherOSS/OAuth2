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

    for my $Needed (qw/AccountID/) {
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

    my $AccountID  = $Param{AccountID};

    my $LanguageObject           = $Kernel::OM->Get('Kernel::Language');
    my $FunctionalAccountsObject = $Kernel::OM->Get('Kernel::System::OpenIDConnect::FunctionalAccounts');
	my $TokenObject              = $Kernel::OM->Get('Kernel::System::OpenIDConnect::Token');
    my $Account                  = $FunctionalAccountsObject->GetAccount( AccountID  => $AccountID );

    if ( !IsHashRefWithData($Account) ) {

        $Kernel::OM->Get('Kernel::System::Log')->Log(
            Priority => 'error',
            Message  => "Invoker AccountID $AccountID not found!",
        );

        return {
            Success => 0,
            Error   => $LanguageObject->Translate("AccountID %s not found!", $AccountID),
        };
    }

    my $TokenType = $Param{TokenType} || $Account->{Token} || 'access_token';

    # 1) try fetch from Cache
    my $Token = $Self->_FetchTokenFromCache(
        AccountID  => $AccountID,
        TokenType  => $TokenType,
    );

    if( $Token && $TokenObject->IsTokenStillValid( Token => $Token ) ) {

        return {
            Success => 1,
            Token   => $Token,
            Origin  => 'cache',
        };
    }

    # 2) try fetch from DB
    my $TokenRepository = $Kernel::OM->Get('Kernel::System::OpenIDConnect::TokenRepository');

    my $TokenData = $TokenRepository->Get(
        AccountID  => $AccountID,
        TokenType  => $TokenType,
    );

    $Token = $TokenData->{Token};

    if( $Token && $TokenObject->IsTokenStillValid( Token => $Token ) ) {

        return {
            Success => 1,
            Token   => $Token,
            Origin  => 'db',
        };
    }

    # 3) try refresh_token, if any

    my $RefreshToken = $TokenRepository->Get(
        AccountID  => $AccountID,
        TokenType  => 'refresh_token',
    );

    if ($RefreshToken) {

        my $Result = $Self->FetchToken(
            AccountID    => $AccountID,
            TokenType    => $TokenType,
            RefreshToken => $RefreshToken->{Token},
        );

        if( $Result->{Token} && $TokenObject->IsTokenStillValid( Token => $Result->{Token} ) ) {

            return {
                Success => 1,
                Token   => $Result->{Token},
                Origin  => 'refresh_token'
            };
        }
    }

    # 4) if grant_type is not 'authorization_code' try fetch fresh token
    # using configured credentials

    if ( $Account->{GrantType} eq 'authorization_code' ) {

        $Kernel::OM->Get('Kernel::System::Log')->Log(
            Priority => 'error',
            Message  => "No valid refresh_token for Account $AccountID using grant_tpye 'authorization code' !",
        );

        return {
            Success => 0,
            Error   => $LanguageObject->Translate("No valid refresh_token for Account %s using grant_tpye 'authorization code' !", $AccountID),
        };
    }

    return $Self->FetchToken(
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

    my $TokenRepository    = $Kernel::OM->Get('Kernel::System::OpenIDConnect::TokenRepository');
    my $FunctionalAccounts = $Kernel::OM->Get('Kernel::System::OpenIDConnect::FunctionalAccounts');

    my $DateTimeObject = $Kernel::OM->Create(
        'Kernel::System::DateTime',
    );

    my $Success = $DateTimeObject->ToTimeZone(
        TimeZone => 'UTC'
    );

    my $Epoch = $DateTimeObject->ToEpoch() + $Interval;

    my $Tokens = $TokenRepository->List(
        ExpiresAfter => $Epoch
    );

    my $Accounts = $FunctionalAccounts->GetAccounts();

    TOKEN:
    for my $Token (@$Tokens) {

        my $Account = $Accounts->{ $Token->{AccountID} };

        my $TokenType = $Account->{Token} || 'access_token';

        my $Result = $Self->FetchToken(

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
        AccountID  => '<SomeAccountName>',
    );

    or

    my $TokenResult = $TokenProviderObject->FetchToken(
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

    for my $Needed (qw/AccountID/) {
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

    my $LanguageObject           = $Kernel::OM->Get('Kernel::Language');
	my $TokenObject              = $Kernel::OM->Get('Kernel::System::OpenIDConnect::Token');
    my $FunctionalAccountsObject = $Kernel::OM->Get('Kernel::System::OpenIDConnect::FunctionalAccounts');

    # Fetch config data from account
    my $AccountID = $Param{AccountID};
    my $Account   = $FunctionalAccountsObject->GetAccount( AccountID  => $AccountID );
    
    if ( !IsHashRefWithData($Account) ) {
        $Kernel::OM->Get('Kernel::System::Log')->Log(
            Priority => 'error',
            Message  => "Need functional account Invoker settings in SysConfig for $AccountID.",
        );

        return {
            Success => 0,
            Error   => $LanguageObject->Translate("Need functional account Invoker settings in SysConfig for %s.", $AccountID),
        };
    }

    my $TokenType         = $Account->{Token}             || 'access_token';
    my $ResourceParamName = $Account->{ResourceParamName} || 'resource';
    my $ResourceIds       = $Account->{Resources};
    my $Scope             = $Account->{Scope};

    my $OpenIDConfig = $FunctionalAccountsObject->GetOpenIDConfig(
        AccountID  => $AccountID,
    );

    # fetch the token
    my $Result = $Self->FetchTokenFromConfig(
        TokenType         => $TokenType,
        ResourceParamName => $ResourceParamName,
        Resources         => $ResourceIds,
        Scope             => $Scope,
        OpenIDConfig      => $OpenIDConfig,
        GrantType         => $Account->{GrantType},
        Username          => $Account->{Username},
        Password          => $Account->{Password},
        RefreshToken      => $Param{RefreshToken},
        Code              => $Param{Code},
        RedirectURL       => $Param{RedirectURL},  
    );

    if(!$Result->{Success}) {
        return $Result;
    }

    my $DecodedContent = $Result->{DecodedContent};

    my $Token = $DecodedContent->{$TokenType};
    if ( !$Token ) {

        $Kernel::OM->Get('Kernel::System::Log')->Log(
            Priority => 'error',
            Message  => "Did not receive the desired TokenType '$TokenType' in provider response!",
        );

        return {
            Success => 0,
            Error   => $LanguageObject->Translate("Did not receive the desired TokenType '%s' in OIDC provider response for Invoker %s!", $TokenType, $AccountID),
        };
    }

    # check time left
    my $TimeLeft = $TokenObject->TimeLeft(
        Token => $Token,
    );

    if ( !$TimeLeft || $TimeLeft < 1 ) {

        $Kernel::OM->Get('Kernel::System::Log')->Log(
            Priority => 'error',
            Message  => "Time left on fresh token is: $TimeLeft s!",
        );

        return {
            Success => 0,
            Error   => $LanguageObject->Translate("Time left on fresh token is: %s s for Invoker %s!", $TimeLeft, $AccountID),
        };
    }

    # process and persist the Tokens
    if ( $DecodedContent->{id_token} ) {

        $Self->_ProcessNewToken(
            OpenIDConfig => $OpenIDConfig,
            AccountID    => $AccountID,
            Account      => $Account,
            TokenType    => 'id_token',
            Token        => $DecodedContent->{id_token},
        );
    }

    if ( $DecodedContent->{access_token} ) {

        $Self->_ProcessNewToken(
            OpenIDConfig => $OpenIDConfig,
            AccountID    => $AccountID,
            Account      => $Account,
            TokenType    => 'access_token',
            Token        => $DecodedContent->{access_token},
        );
    }

    if ( $DecodedContent->{refresh_token} ) {

        $Self->_ProcessNewToken(
            OpenIDConfig => $OpenIDConfig,
            AccountID    => $AccountID,
            Account      => $Account,
            TokenType    => 'refresh_token',
            Token        => $DecodedContent->{refresh_token},
        );
    }

    return {
        Success => 1,
        Token   => $Token,
        Origin  => 'fresh_token',
    };
}


sub FetchTokenFromConfig {

    my ( $Self, %Param ) = @_;

    for my $Needed (qw/OpenIDConfig GrantType/) {
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

    my $LanguageObject    = $Kernel::OM->Get('Kernel::Language');
	my $TokenObject       = $Kernel::OM->Get('Kernel::System::OpenIDConnect::Token');
    my $OIDCConfiguration = $Kernel::OM->Get('Kernel::System::OpenIDConnect::Configuration');

    # determine which token are we expected to pass to remote system
    my $TokenType         = $Param{Token}             || 'access_token';
    my $ResourceParamName = $Param{ResourceParamName} || 'resource';
    my $ResourceIds       = $Param{Resources};
    my $Scope             = $Param{Scope};
    my $OpenIDConfig      = $Param{OpenIDConfig};
    my $GrantType         = $Param{GrantType};
    my $Username          = $Param{Username};
    my $Password          = $Param{Password};

	my $TokenEndpoint = $OIDCConfiguration->GetTokenEndpoint(
        OpenIDConfig  => $OpenIDConfig,
	);
    if ( !$TokenEndpoint ) {

        return {
            Success => 0,
            Error   => $LanguageObject->Translate("Could not get the OAuth2 token_endpoint for Invoker "),
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
        $Param{GrantType} eq 'password'
        &&
        IsStringWithData( $Username ) &&
        IsStringWithData( $Password )
        )
    {

        # password flow
        $PostData = [
            grant_type => 'password',
            username   => $Username,
            password   => $Password,
        ];
    }
    elsif ( $Param{GrantType} eq 'client_credentials' ) {

        # client_credentials flow
        $PostData = [
            grant_type => 'client_credentials',
        ];
    }
    elsif ( $Param{Code} && $Param{GrantType} eq 'authorization_code' ) {

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
        EndPoint     => $TokenEndpoint,
        PostData     => $PostData,
    );

    if ( !$Response->{Success} ) {

        return {
            Success => 0,
            Error   => $LanguageObject->Translate("Error fetching Token for Invoker: %s", $Response->{Error} ),
        };
    }

    return {
        Success => 1,
        DecodedContent => $Response->{Content}
    };
}

=head2 GetAuthURL()

Build the URL to request an authorization code.

Example:
    my $AuthURL = $TokenProviderObject->GetAuthURL(
        AccountID   => '<FunctionalAccountName>',
        RedirectURI => 'https://your.otobo.url/otobo/index.pl?Action=AdminOAuthTokenStore&Subaction=OAuth'
    );

Returns:
    $AuthURL = https://login.microsoftonline.com/common/oauth2/v2.0/authorize?client_id=077d2059-219...

=cut

sub GetAuthURL {
    my ( $Self, %Param ) = @_;

    for my $Needed (qw/AccountID/) {
        if ( !$Param{$Needed} ) {
            $Kernel::OM->Get('Kernel::System::Log')->Log(
                Priority => 'error',
                Message  => "Need $Needed!",
            );

            return;
        }
    }

    my $AccountID  = $Param{AccountID};

    my $FunctionalAccountsObject = $Kernel::OM->Get('Kernel::System::OpenIDConnect::FunctionalAccounts');
    my $Account                  = $FunctionalAccountsObject->GetAccount( AccountID  => $AccountID );

    if ( !IsHashRefWithData($Account) ) {
        $Kernel::OM->Get('Kernel::System::Log')->Log(
            Priority => 'error',
            Message  => 'Need functional account Invoker settings in SysConfig.',
        );

        return;
    }

    my $TokenType = $Account->{Token} || 'access_token';

    my $OpenIDConfig = $FunctionalAccountsObject->GetOpenIDConfig(
        AccountID  => $AccountID,
    );

    # Create a random string to prevent cross-site requests.
    my $RandomString = $Kernel::OM->Get('Kernel::System::Main')->GenerateRandomString(
        Length => 22    #$OAuthConfig->{StateNonceLength} || 22,
    );

    my $AuthRequest = {
        ResponseType => ['code'],
        State        => $Param{State} || $RandomString,
        RedirectURI  => $Param{RedirectURI},
    };

    my $Resources = $Account->{Resources};
    my $ResourceParamName = $Account->{ResourceParamName} || 'resource';

    my $Scope = $Account->{Scope};

    if ( $TokenType eq 'id_token' ) {

        push $AuthRequest->{ResponseType}->@*, 'id_token';
    }

#    my $RedirectURL = $Self->_BuildRedirectURL(
 #       AuthRequest      => $AuthRequest,
  #      Login            => $Param{Login},
    #    Prompt           => $Param{Prompt},
	#	OpenIDConfig     => $OpenIDConfig,
    #);

#	my $OpenIDConfig     = $Param{OpenIDConfig};
	my $ClientSettings   = $OpenIDConfig->{ClientSettings};

#	my $OIDCConfigurationObject = $Kernel::OM->Get('Kernel::System::OpenIDConnect::Configuration');
 
	my $AuthEndpoint = $FunctionalAccountsObject->GetAuthorizationEndpoint(
		AccountID => $AccountID,
	);

    if ( !$AuthEndpoint ) {
        $Kernel::OM->Get('Kernel::System::Log')->Log(
            Priority => 'error',
            Message  => 'Could not retrieve the authorization endpoint!',
        );

        return;
    }
#
#	my $OpenIDProviderData = $FunctionalAccountsObject->GetProviderData(
#		AccountID => $AccountID,
#	);
#
    my $RedirectURL = $AuthEndpoint;
    $RedirectURL .= '?response_type=' . join( '%20', @{ $AuthRequest->{ResponseType} } );

    if ( $Param{AdditionalScope} ) {
        $RedirectURL .= '&scope=openid%20' . uri_escape_utf8($Param{AdditionalScope});
    }
    elsif ( $Scope ) {
        $RedirectURL .= '&scope='. uri_escape_utf8($Scope);
    }
    else {
        $RedirectURL .= '&scope=openid';
    }

    $RedirectURL .= '&client_id=' . $ClientSettings->{ClientID};

    if ( $Resources ) {
        $RedirectURL .= "&".$ResourceParamName."=" . uri_escape_utf8($Resources);
    }

    if ( $AuthRequest->{Nonce} ) {
        $RedirectURL .= '&nonce=' . $AuthRequest->{Nonce};
    }

    if ( grep { $_ eq 'id_token' } @{ $AuthRequest->{ResponseType} } ) {
        $RedirectURL .= '&response_mode=form_post';
    }

    if ( $Param{Login} ) {
        $RedirectURL .= '&login_hint=' . uri_escape_utf8( $Param{Login} );
    }

    if ( $Param{Prompt} ) {
        $RedirectURL .= '&prompt=login';
    }

    $RedirectURL .= '&state=' . $AuthRequest->{State};
    $RedirectURL .= '&redirect_uri=' . uri_escape_utf8( $AuthRequest->{RedirectURI} || $ClientSettings->{RedirectURI} );

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

sub EmptyCache {

    my ( $Self, %Param ) = @_;

    for my $Needed (qw/AccountID/) {
        if ( !$Param{$Needed} ) {
            $Kernel::OM->Get('Kernel::System::Log')->Log(
                Priority => 'error',
                Message  => "Need $Needed!",
            );

            return;
        }
    }

    my $AccountID  = $Param{AccountID};

    my $CacheObject = $Kernel::OM->Get('Kernel::System::Cache');

    for my $TokenType (qw/access_token id_token refresh_token/) {

        my $CacheType = "TokenProvider";
        my $CacheKey  = join( ',', 'Invoker', $AccountID, $TokenType );

        my $Token = $CacheObject->Delete(
            Type => $CacheType,
            Key  => $CacheKey,
        );
    }

    my $FunctionalAccounts = $Kernel::OM->Get('Kernel::System::OpenIDConnect::FunctionalAccounts');
	$FunctionalAccounts->ClearCache(
        AccountID  => $AccountID,
    );
}

# helpers

sub _FetchTokenFromCache {
    my ( $Self, %Param ) = @_;

    for my $Needed (qw/AccountID TokenType/) {
        if ( !$Param{$Needed} ) {
            $Kernel::OM->Get('Kernel::System::Log')->Log(
                Priority => 'error',
                Message  => "Need $Needed!",
            );

            return;
        }
    }

    my $AccountID  = $Param{AccountID};
    my $TokenType  = $Param{TokenType};

    my $CacheObject = $Kernel::OM->Get('Kernel::System::Cache');

    my $CacheType = "TokenProvider";
    my $CacheKey  = join( ',', 'Invoker', $AccountID, $TokenType );

    my $Token = $CacheObject->Get(
        Type => $CacheType,
        Key  => $CacheKey,
    );

    return $Token;
}

sub _PopulateCache {

    my ( $Self, %Param ) = @_;

    for my $Needed (qw/AccountID TokenType Token ExpiresAt/) {
        if ( !$Param{$Needed} ) {
            $Kernel::OM->Get('Kernel::System::Log')->Log(
                Priority => 'error',
                Message  => "Need $Needed!",
            );

            return;
        }
    }

    my $AccountID  = $Param{AccountID};
    my $TokenType  = $Param{TokenType};
    my $Token      = $Param{Token};
    my $ExpiresAt  = $Param{ExpiresAt};

    my $CacheObject = $Kernel::OM->Get('Kernel::System::Cache');
	my $TokenObject = $Kernel::OM->Get('Kernel::System::OpenIDConnect::Token');

    my $CacheType = "TokenProvider";
    my $CacheKey  = join( ',', 'Invoker', $AccountID, $TokenType );

    # check time left
    my $TimeLeft = $TokenObject->TimeLeft(
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

    my $LanguageObject = $Kernel::OM->Get('Kernel::Language');

    # add client_id and client_secret to authenticate the client
    if ( !$OpenIDConfig->{ClientSettings}{ClientID} || !$OpenIDConfig->{ClientSettings}{ClientSecret} ) {

        return {
            Success => 0,
            Error   => $LanguageObject->Translate('Need ClientID and ClientSecret!'),
        };
    }

    $Request->authorization_basic( $OpenIDConfig->{ClientSettings}{ClientID}, $OpenIDConfig->{ClientSettings}{ClientSecret} );

    # execute request
    my $Response = $UserAgent->request($Request);
    my $Content  = $Response->content();

    if ( !$Content ) {

        return {
            Success => 0,
            Error   => $LanguageObject->Translate("Got no content when requesting Token. Response Code: %s", $Response->code()),
        };
    }

    # decode content
    my $DecodedContent = $Kernel::OM->Get('Kernel::System::JSON')->Decode(
        Data => $Content,
    );

    if ( !IsHashRefWithData($DecodedContent) ) {

        return {
            Success => 0,
            Error   => $LanguageObject->Translate("Got no JSON object when requesting Token. Response: %s", $Content),
        };
    }

    # fetch the desired token (access_token (default) or id_token)
    if ( $DecodedContent->{error} ) {
        return {
            Success => 0,
            Error   => "Error: ". $DecodedContent->{erro}. ". Description: ".$DecodedContent->{error_description},
        };
    }

    return {
        Success => 1,
        Content => $DecodedContent,
    };
}

sub _ProcessNewToken {

    my ( $Self, %Param ) = @_;

    my $Account      = $Param{Account};
    my $AccountID    = $Param{AccountID};
    my $OpenIDConfig = $Param{OpenIDConfig};
    my $TokenType    = $Param{TokenType};
    my $Token        = $Param{Token};

    my $TokenObject = $Kernel::OM->Get('Kernel::System::OpenIDConnect::Token');

    my $TokenData;

    if ( $TokenType eq 'refresh_token' ) {

        my $Result = $TokenObject->Inspect(
			Token  => $Token,
        );

        return unless $Result;

        $TokenData = $Result;
    }
    else {

        my $Result = $TokenObject->Validate(
            Token                => $Token,
			OpenIDConfig         => $OpenIDConfig,
            ExpectedAudience     => $TokenType eq 'id_token' ? $OpenIDConfig->{ClientSettings}->{ClientID} : undef,
            AuthorizedParty      => $OpenIDConfig->{ClientSettings}->{ClientID},
            ExpectedScopes       => $Account->{Scope},
        );

        return unless $Result->{Success};

        $TokenData = $Result->{TokenData};
    }

    my $ExpiresAt = $TokenData->{exp};

    my $TokenRepository = $Kernel::OM->Get('Kernel::System::OpenIDConnect::TokenRepository');

    my $Success = $TokenRepository->Save(
        AccountID  => $AccountID,
        TokenType  => $TokenType,
        Token      => $Token,
        ExpiresAt  => $ExpiresAt,
    );

    return unless $Success;

    $Self->_PopulateCache(
        AccountID  => $AccountID,
        TokenType  => $TokenType,
        Token      => $Token,
        ExpiresAt  => $ExpiresAt,
    );

    return 1;
}

sub _BuildRedirectURL {
    my ( $Self, %Param ) = @_;

    for my $Needed (qw/AuthRequest OpenIDConfig/) {
        if ( !$Param{$Needed} ) {
            $Kernel::OM->Get('Kernel::System::Log')->Log(
                Priority => 'error',
                Message  => "Need $Needed!",
            );

            return;
        }
    }

    if ( !IsArrayRefWithData( $Param{AuthRequest}{ResponseType} ) ) {
        $Kernel::OM->Get('Kernel::System::Log')->Log(
            Priority => 'error',
            Message  => "ResponseType must be an array ref with data!",
        );

        return;
    }

	my $OpenIDConfig     = $Param{OpenIDConfig};
	my $ClientSettings   = $OpenIDConfig->{ClientSettings};

	my $OIDCConfigurationObject = $Kernel::OM->Get('Kernel::System::OpenIDConnect::Configuration');

	my $RedirectURL = $OIDCConfigurationObject->GetAuthorizationEndpoint();

    if ( !$RedirectURL ) {
        $Kernel::OM->Get('Kernel::System::Log')->Log(
            Priority => 'error',
            Message  => 'Could not retrieve the authorization endpoint!',
        );

        return;
    }

    $RedirectURL .= '?response_type=' . join( '%20', @{ $Param{AuthRequest}{ResponseType} } );

    if ( $Param{AdditionalScope} ) {
        $RedirectURL .= '&scope=' . join( '%20', ( 'openid', @{ $Param{AuthRequest}{AdditionalScope} // [] } ) );
    }
    elsif ( $Param{Scope} ) {
        $RedirectURL .= '&scope=' . join( '%20', ( @{ $Param{AuthRequest}{Scope} // [] } ) );
    }
    else {
        $RedirectURL .= '&scope=openid';
    }

    $RedirectURL .= '&client_id=' . $Param{ClientSettings}{ClientID};
    $RedirectURL .= '&state=' . $Param{AuthRequest}{State};
    $RedirectURL .= '&redirect_uri=' . uri_escape_utf8( $Param{AuthRequest}{RedirectURI} || $Param{ClientSettings}{RedirectURI} );

    if ( exists $Param{AuthRequest}->{ResourceParamName} ) {
        my $Resources = $Param{AuthRequest}->{ $Param{AuthRequest}->{ResourceParamName} };
        $RedirectURL .= "&$Param{AuthRequest}->{ResourceParamName}=" .
            join( '%20', ( @{ $Resources // [] } ) );
    }

    if ( $Param{AuthRequest}{Nonce} ) {
        $RedirectURL .= '&nonce=' . $Param{AuthRequest}{Nonce};
    }

    if ( grep { $_ eq 'id_token' } @{ $Param{AuthRequest}{ResponseType} } ) {
        $RedirectURL .= '&response_mode=form_post';
    }

    if ( $Param{Login} ) {
        $RedirectURL .= '&login_hint=' . uri_escape_utf8( $Param{Login} );
    }

    if ( $Param{Prompt} ) {
        $RedirectURL .= '&prompt=login';
    }

    return $RedirectURL;
}

1;
