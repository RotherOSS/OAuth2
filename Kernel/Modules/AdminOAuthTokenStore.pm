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

package Kernel::Modules::AdminOAuthTokenStore;

use strict;
use warnings;

use Kernel::Language              qw(Translatable);
use Kernel::System::VariableCheck qw(:all);

our $ObjectManagerDisabled = 1;

sub new {
    my ( $Type, %Param ) = @_;

    # allocate new hash for object
    my $Self = {%Param};
    bless( $Self, $Type );

    return $Self;
}

sub Run {
    my ( $Self, %Param ) = @_;

    my $ConfigObject       = $Kernel::OM->Get('Kernel::Config');
    my $CacheObject        = $Kernel::OM->Get('Kernel::System::Cache');
    my $LayoutObject       = $Kernel::OM->Get('Kernel::Output::HTML::Layout');
    my $ParamObject        = $Kernel::OM->Get('Kernel::System::Web::Request');
    my $LogObject          = $Kernel::OM->Get('Kernel::System::Log');
    my $TokenRepository    = $Kernel::OM->Get('Kernel::System::OpenIDConnect::TokenRepository');
    my $TokenProvider      = $Kernel::OM->Get('Kernel::System::OpenIDConnect::TokenProvider');
    my $FunctionalAccounts = $Kernel::OM->Get('Kernel::System::OpenIDConnect::FunctionalAccounts');

    my %Errors = ();

    my $Output = $LayoutObject->Header();
    $Output .= $LayoutObject->NavigationBar();

    # ------------------------------------------------------------ #
    # AddInvoker
    # ------------------------------------------------------------ #
    if ( $Self->{Subaction} eq 'AddInvoker' ) {

        my %GetParam = ();

        $GetParam{AccountName}   = $ParamObject->GetParam( Param => 'AccountName' );
        $GetParam{AccountCtx}    = 'Invoker';
        $GetParam{GrantType}     = 'client_credentials';
        $GetParam{InvokerScopes} = 'openid';
        $GetParam{TokenType}     = 'access_token';

        my $Output = $LayoutObject->Header();
        $Output .= $LayoutObject->NavigationBar();
        $Self->_EditInvoker(
            Action => 'AddInvoker',
            %GetParam,
        );
        $Output .= $LayoutObject->Output(
            TemplateFile => 'AdminOAuthTokenStore',
            Data         => \%Param,
        );
        $Output .= $LayoutObject->Footer();
        return $Output;
    }

    # ------------------------------------------------------------ #
    # AddProvider
    # ------------------------------------------------------------ #
    elsif ( $Self->{Subaction} eq 'AddProvider' ) {

        my %GetParam = ();

        $GetParam{AccountName} = $ParamObject->GetParam( Param => 'AccountName' );
        $GetParam{AccountCtx}  = 'Provider';
        $GetParam{UID}         = 'sub';

        my $Output = $LayoutObject->Header();
        $Output .= $LayoutObject->NavigationBar();
        $Self->_EditProvider(
            Action => 'AddProvider',
            %GetParam,
        );
        $Output .= $LayoutObject->Output(
            TemplateFile => 'AdminOAuthTokenStore',
            Data         => \%Param,
        );
        $Output .= $LayoutObject->Footer();
        return $Output;
    }

    # ------------------------------------------------------------ #
    # AddInvokerAction and EditInvokerAction
    # ------------------------------------------------------------ #
    if ( $Self->{Subaction} eq 'AddInvokerAction' || $Self->{Subaction} eq 'EditInvokerAction' ) {

        # challenge token check for write action
        $LayoutObject->ChallengeTokenCheck();

        my %GetParam = ();

        $GetParam{AccountName} = $ParamObject->GetParam( Param => 'AccountName' );

        if ( !$GetParam{AccountName} ) {
            $Errors{AccountNameServerError} = Translatable('Account Name is missing!');
        }

        $GetParam{AccountCtx}    = 'Invoker';
        $GetParam{ProviderName}  = $ParamObject->GetParam( Param => 'ProviderName' );
        $GetParam{GrantType}     = $ParamObject->GetParam( Param => 'GrantType' );
        $GetParam{Username}      = $ParamObject->GetParam( Param => 'Username' );
        $GetParam{Password}      = $ParamObject->GetParam( Param => 'Password' );
        $GetParam{TokenType}     = $ParamObject->GetParam( Param => 'TokenType' );
        $GetParam{InvokerScopes} = $ParamObject->GetParam( Param => 'InvokerScopes' );
        $GetParam{Resources}     = $ParamObject->GetParam( Param => 'Resources' );
        $GetParam{ResourceParam} = $ParamObject->GetParam( Param => 'ResourceParam' );

        if ( $GetParam{GrantType} eq 'password' ) {
            if ( !$GetParam{Username} && $GetParam{EnableInvoker} ) {
                $Errors{UsernameServerError} = Translatable('Username is required!');
            }
            if ( !$GetParam{Password} && $GetParam{EnableInvoker} ) {
                $Errors{PasswordServerError} = Translatable('Password is required!');
            }
        }

        my $OIDCAccounts = $FunctionalAccounts->GetOAuthAccounts( AccountCtx => 'Invoker' );
        if ( $Self->{Subaction} eq 'AddInvokerAction' && exists $OIDCAccounts->{ $GetParam{AccountName} } ) {
            $Errors{AccountNameServerError} = Translatable('Account Name is taken!');
        }

        if ( scalar keys %Errors ) {

            my $Output = $LayoutObject->Header();
            $Output .= $LayoutObject->NavigationBar();

            if ( $Errors{TokenError} ) {
                $Output .= $LayoutObject->Notify(
                    Error    => $Errors{TokenError},
                    Priority => 'Error'
                );
            }

            $Self->_EditInvoker(
                Action => $Self->{Subaction} eq 'AddInvokerAction' ? 'AddInvoker' : 'EditInvoker',
                %GetParam,
                %Errors,
            );

            $Output .= $LayoutObject->Output(
                TemplateFile => 'AdminOAuthTokenStore',
                Data         => \%Param,
            );
            $Output .= $LayoutObject->Footer();

            return $Output;
        }

        # save config

        $OIDCAccounts->{ $GetParam{AccountName} } = {
            OpenIDConfig      => $GetParam{ProviderName},
            GrantType         => $GetParam{GrantType},
            Scope             => $GetParam{InvokerScopes},
            Resources         => $GetParam{Resources},
            ResourceParamName => $GetParam{ResourceParam},
            Token             => $GetParam{TokenType},
            Username          => $GetParam{Username},
            Password          => $GetParam{Password},
        };

        my $SysConfigObject = $Kernel::OM->Get('Kernel::System::SysConfig');

        my $Success = $SysConfigObject->SettingsSet(
            UserID   => $Self->{UserID},
            Comments => "Functional Account " . $GetParam{AccountName} . " created",
            Settings => [
                {
                    Name           => 'OpenIDConnect::Invoker::Accounts',
                    EffectiveValue => $OIDCAccounts,
                    IsValid        => 1,
                    NoValidation   => 1,
                },
            ],
        );

        if ( !$Success ) {
            $Output .= $LayoutObject->Notify(
                Info     => "Error creating/updating $GetParam{AccountName} ($GetParam{AccountCtx})!",
                Priority => 'Error'
            );
        }

        if ( $GetParam{GrantType} eq 'authorization_code' ) {

            my $AuthURL = $TokenProvider->GetAuthURL(
                %GetParam,
                AccountID   => $GetParam{AccountName},
                Prompt      => 1,
                Subaction   => $Self->{Subaction},
                RedirectURI => $ConfigObject->Get('HttpType')
                    . '://'
                    . $ConfigObject->Get('FQDN')
                    . '/'
                    . $ConfigObject->Get('ScriptAlias')
                    . 'index.pl?Action=AdminOAuthTokenStore&Subaction=OAuth'
            );

            return $LayoutObject->Redirect(
                ExtURL => $AuthURL
            );
        }
        else {

            my $TokenResult = $TokenProvider->Fetch(
                AccountID  => $GetParam{AccountName},
                AccountCtx => $GetParam{AccountCtx},
            );

            if ( !$TokenResult->{Success} ) {
                $Errors{TokenError} = $TokenResult->{Error};
            }
        }
    }

    # ------------------------------------------------------------ #
    # AddProviderAction and EditProviderAction
    # ------------------------------------------------------------ #
    if ( $Self->{Subaction} eq 'AddProviderAction' || $Self->{Subaction} eq 'EditProviderAction' ) {

        # challenge token check for write action
        $LayoutObject->ChallengeTokenCheck();

        my %GetParam = ();

        $GetParam{AccountName} = $ParamObject->GetParam( Param => 'AccountName' );

        if ( !$GetParam{AccountName} ) {
            $Errors{AccountNameServerError} = Translatable('Account Name is missing!');
        }

        $GetParam{AccountCtx}   = 'Provider';
        $GetParam{ProviderName} = $ParamObject->GetParam( Param => 'ProviderName' );

        $GetParam{UID}             = $ParamObject->GetParam( Param => 'UID' );
        $GetParam{UserLogin}       = $ParamObject->GetParam( Param => 'UserLogin' );
        $GetParam{ProviderScopes}  = $ParamObject->GetParam( Param => 'ProviderScopes' );
        $GetParam{Audience}        = $ParamObject->GetParam( Param => 'Audience' );
        $GetParam{AuthorizedParty} = $ParamObject->GetParam( Param => 'AuthorizedParty' );

        if ( !$GetParam{UID} ) {
            $Errors{UIDServerError} = Translatable('UID parameter is missing!');
        }

        my $OIDCAccounts = $FunctionalAccounts->GetOAuthAccounts( AccountCtx => 'Provider' );
        if ( $Self->{Subaction} eq 'AddProviderAction' && exists $OIDCAccounts->{ $GetParam{AccountName} } ) {
            $Errors{AccountNameServerError} = Translatable('Account Name is taken!');
        }

        if ( scalar keys %Errors ) {

            my $Output = $LayoutObject->Header();
            $Output .= $LayoutObject->NavigationBar();

            $Self->_EditProvider(
                Action => $Self->{Subaction} eq 'AddProviderAction' ? 'AddProvider' : 'EditProvider',
                %GetParam,
                %Errors,
            );

            $Output .= $LayoutObject->Output(
                TemplateFile => 'AdminOAuthTokenStore',
                Data         => \%Param,
            );
            $Output .= $LayoutObject->Footer();

            return $Output;
        }

        # save config

        $OIDCAccounts->{ $GetParam{AccountName} } = {
            OpenIDConfig    => $GetParam{ProviderName},
            UID             => $GetParam{UID},
            Scope           => $GetParam{ProviderScopes},
            Audience        => $GetParam{Audience},
            AuthorizedParty => $GetParam{AuthorizedParty},
            UserLogin       => $GetParam{UserLogin},
        };

        my $SysConfigObject = $Kernel::OM->Get('Kernel::System::SysConfig');

        my $Success = $SysConfigObject->SettingsSet(
            UserID   => $Self->{UserID},
            Comments => "Functional Account " . $GetParam{AccountName} . " created",
            Settings => [
                {
                    Name           => 'OpenIDConnect::Provider::Accounts',
                    EffectiveValue => $OIDCAccounts,
                    IsValid        => 1,
                    NoValidation   => 1,
                },
            ],
        );

        if ( !$Success ) {
            $Output .= $LayoutObject->Notify(
                Info     => "Error creating/updating $GetParam{AccountName} ($GetParam{AccountCtx})!",
                Priority => 'Error'
            );
        }
    }

    # ------------------------------------------------------------ #
    # Edit
    # ------------------------------------------------------------ #
    if ( $Self->{Subaction} eq 'Edit' ) {

        my %GetParam = ();
        $GetParam{AccountName} = $ParamObject->GetParam( Param => 'AccountName' );
        $GetParam{AccountCtx}  = $ParamObject->GetParam( Param => 'AccountCtx' );

        my $Account = $FunctionalAccounts->GetOAuthAccount(
            AccountID  => $GetParam{AccountName},
            AccountCtx => $GetParam{AccountCtx},
        );

        $GetParam{ProviderName} = $Account->{OpenIDConfig};

        my $Output = $LayoutObject->Header();
        $Output .= $LayoutObject->NavigationBar();

        if ( $GetParam{AccountCtx} eq 'Invoker' ) {

            $GetParam{GrantType} = $Account->{GrantType};

            if ( $GetParam{GrantType} eq 'password' ) {

                $GetParam{Username} = $Account->{Username};
                $GetParam{Password} = $Account->{Password};
            }

            $GetParam{InvokerScopes} = $Account->{Scope};
            $GetParam{Resources}     = $Account->{Resources};
            $GetParam{ResourceParam} = $Account->{ResourceParamName};

            $Self->_EditInvoker(
                Action => 'EditInvoker',
                %GetParam,
            );
        }
        elsif ( $GetParam{AccountCtx} eq 'Provider' ) {

            $GetParam{UID}             = $Account->{UID};
            $GetParam{UserLogin}       = $Account->{UserLogin};
            $GetParam{ProviderScopes}  = $Account->{Scope};
            $GetParam{Audience}        = $Account->{Audience};
            $GetParam{AuthorizedParty} = $Account->{AuthorizedParty};

            $Self->_EditProvider(
                Action => 'EditProvider',
                %GetParam,
            );
        }

        $LayoutObject->Block(
            Name => 'ActionDelete',
            Data => \%GetParam
        );

        $Output .= $LayoutObject->Output(
            TemplateFile => 'AdminOAuthTokenStore',
            Data         => \%Param,
        );
        $Output .= $LayoutObject->Footer();
        return $Output;
    }

    # ------------------------------------------------------------ #
    # Delete
    # ------------------------------------------------------------ #
    elsif ( $Self->{Subaction} eq 'Delete' ) {

        # challenge token check for write action
        $LayoutObject->ChallengeTokenCheck();

        my $AccountCtx  = $ParamObject->GetParam( Param => 'AccountCtx' )  || '';
        my $AccountName = $ParamObject->GetParam( Param => 'AccountName' ) || '';

        my $OIDCAccounts = $FunctionalAccounts->GetOAuthAccounts( AccountCtx => $AccountCtx );
        if ( exists $OIDCAccounts->{$AccountName} ) {

            delete $OIDCAccounts->{$AccountName};

            my $SysConfigObject = $Kernel::OM->Get('Kernel::System::SysConfig');

            my $Success = $SysConfigObject->SettingsSet(
                UserID   => $Self->{UserID},
                Comments => "Functional Account " . $AccountName . " deleted.",
                Settings => [
                    {
                        Name           => "OpenIDConnect::" . $AccountCtx . "::Accounts",
                        EffectiveValue => $OIDCAccounts,
                        IsValid        => 1,
                        NoValidation   => 1,
                    },
                ],
            );

            if ($Success) {
                $Output .= $LayoutObject->Notify(
                    Info     => "$AccountName ($AccountCtx) deleted!",
                    Priority => 'Success'
                );
            }
        }
    }

    # ------------------------------------------------------------ #
    # Refresh
    # ------------------------------------------------------------ #
    elsif ( $Self->{Subaction} eq 'Refresh' ) {

        # challenge token check for write action
        $LayoutObject->ChallengeTokenCheck();

        my $AccountCtx = $ParamObject->GetParam( Param => 'AccountCtx' ) || '';
        my $AccountID  = $ParamObject->GetParam( Param => 'AccountID' )  || '';

        my $Account = $FunctionalAccounts->GetOAuthAccount(
            AccountCtx => $AccountCtx,
            AccountID  => $AccountID,
        );

        if ( IsHashRefWithData($Account) && $AccountCtx eq 'Invoker' )
        {
            my $GrantType = $Account->{GrantType};

            # authorization_code uses browser based flow
            # redirect the browser to the identity provider
            # login page
            if ( $GrantType eq 'authorization_code' ) {

                my $AuthURL = $TokenProvider->GetAuthURL(
                    AccountID   => $AccountID,
                    AccountCtx  => $AccountCtx,
                    Prompt      => 1,
                    Subaction   => 'Refresh',
                    RedirectURI => $ConfigObject->Get('HttpType')
                        . '://'
                        . $ConfigObject->Get('FQDN')
                        . '/'
                        . $ConfigObject->Get('ScriptAlias')
                        . 'index.pl?Action=AdminOAuthTokenStore&Subaction=OAuth'

                );

                return $LayoutObject->Redirect(
                    ExtURL => $AuthURL
                );
            }

            # for client_credentials and password flows,
            # we can just fetch an new token right now
            else {

                my $TokenResult = $TokenProvider->Fetch(
                    AccountID  => $AccountID,
                    AccountCtx => $AccountCtx,
                );

                if ( $TokenResult->{Success} ) {

                    $Output .= $LayoutObject->Notify(
                        Info     => "Token $AccountID ($AccountCtx) updated!",
                        Priority => 'Success'
                    );
                }
                else {

                    $TokenRepository->Delete(
                        AccountID  => $AccountID,
                        AccountCtx => $AccountCtx,
                    );

                    $Output .= $LayoutObject->Notify(
                        Error    => $TokenResult->{Error},
                        Priority => 'Error'
                    );
                }
            }
        }
    }

    # ------------------------------------------------------------ #
    # oauth action - callback when using authorization_code
    # ------------------------------------------------------------ #
    elsif ( $Self->{Subaction} eq 'OAuth' ) {

        my $State  = $ParamObject->GetParam( Param => 'state' );
        my $Code   = $ParamObject->GetParam( Param => 'code' );
        my $Issuer = $ParamObject->GetParam( Param => 'iss' );

        my $CachedState = $CacheObject->Get(
            Type => 'TokenProvider',
            Key  => "TokenProvider::OAuth2State::$State",
        );

        if ( !$CachedState ) {

            return join '',
                $LayoutObject->Header( Title => 'Error' ),
                $LayoutObject->Warning(
                    Message => 'Invalid OAuth State!'
                ),
                $LayoutObject->Footer();
        }

        my $AccountID   = $CachedState->{AccountID};
        my $AccountCtx  = $CachedState->{AccountCtx};
        my $RedirectURL = $CachedState->{RedirectURL};
        my $Subaction   = $CachedState->{Subaction};

        my $Account = $FunctionalAccounts->GetOAuthAccount(
            AccountCtx => $AccountCtx,
            AccountID  => $AccountID,
        );

        if ( !IsHashRefWithData($Account) || $AccountCtx ne 'Invoker' )
        {
            return join '',
                $LayoutObject->Header( Title => 'Error' ),
                $LayoutObject->Warning(
                    Message => "Invalid Account $AccountID ($AccountCtx) for Token!"
                ),
                $LayoutObject->Footer();
        }

        # validate the issuer
        my $ProviderIssuer = $FunctionalAccounts->GetIssuer(
            AccountCtx => $AccountCtx,
            AccountID  => $AccountID,
        );

        if ( $Issuer ne $ProviderIssuer ) {
            return join '',
                $LayoutObject->Header( Title => 'Error' ),
                $LayoutObject->Warning(
                    Message => "Invalid Issuer $Issuer for Token $AccountID ($AccountCtx) !"
                ),
                $LayoutObject->Footer();
        }

        my $TokenResult = $TokenProvider->FetchToken(
            AccountID   => $AccountID,
            AccountCtx  => $AccountCtx,
            Code        => $Code,
            RedirectURL => $RedirectURL,
        );

        if ( $TokenResult->{Success} ) {

            $Output .= $LayoutObject->Notify(
                Info     => "Token $AccountID ($AccountCtx) updated!",
                Priority => 'Success'
            );

        }
        else {

            if ( $Subaction eq 'Refresh' ) {
                $Output .= $LayoutObject->Notify(
                    Error    => $TokenResult->{Error},
                    Priority => 'Error'
                );
            }
            else {

                $Self->_EditInvoker(
                    %$CachedState,
                    TokenError => '',              #$TokenResult->{Error}    ,
                    Action     => 'EditInvoker',
                );

                $Output .= $LayoutObject->Notify(
                    Info     => "Error cfetching initial Token for $AccountID ($AccountCtx)!",
                    Priority => 'Error'
                );
            }
        }
    }

    # ------------------------------------------------------------ #
    # show overview actions - assemble Account Overview data
    # ------------------------------------------------------------ #

    $LayoutObject->Block(
        Name => 'Overview',
        Data => \%Param,
    );

    $LayoutObject->Block( Name => 'ActionAddInvoker' );
    $LayoutObject->Block( Name => 'ActionAddProvider' );

    # Get List of refreshable Tokens from DB
    my $GenericInterfaceTokens = $TokenRepository->List();

    # Build a lookup index
    my %GenericInterfaceTokenLookup = (
        Invoker  => {},
        Provider => {},
    );
    for my $GenericInterfaceToken (@$GenericInterfaceTokens) {

        if (
            $GenericInterfaceToken->{AccountCtx} eq 'Invoker'
            ||
            $GenericInterfaceToken->{AccountCtx} eq 'Provider'
            )
        {

            $GenericInterfaceTokenLookup{ $GenericInterfaceToken->{AccountCtx} }->{ $GenericInterfaceToken->{AccountID} } = $GenericInterfaceToken;
        }
    }

    # Prepare view data
    my @AccountsForDisplay;

    # Get OAuth Invoker accounts from Config
    my $InvokerAccounts = $FunctionalAccounts->GetOAuthAccounts( AccountCtx => 'Invoker' );

    # Sort keys for display
    my @OInvokerAccountKeys = keys %$InvokerAccounts;
    @OInvokerAccountKeys = sort @OInvokerAccountKeys;

    OAUTHACCOUNT:
    for my $AccountName (@OInvokerAccountKeys) {

        my $Account = $InvokerAccounts->{$AccountName};

        my $GrantType = $InvokerAccounts->{$AccountName}->{GrantType};
        my $HasToken  = exists $GenericInterfaceTokenLookup{Invoker}->{$AccountName};
        if ( !$HasToken ) {

            # client_credentials flow usually does not have refresh_tokens,
            # but we always can generate a new one
            if ( $GrantType eq 'client_credentials' ) {
                $HasToken = 1;
            }
        }

        my $Token = $GenericInterfaceTokenLookup{Invoker}{$AccountName};
        my $Time  = "";

        if ( $Token->{ExpiresAt} ) {

            my $DateTimeObject = $Kernel::OM->Create(
                'Kernel::System::DateTime',
                ObjectParams => {
                    Epoch => $Token->{ExpiresAt},
                }
            );

            my $Success = $DateTimeObject->ToTimeZone(
                TimeZone => $Self->{UserTimeZone}
            );

            $Time = $DateTimeObject->Format( Format => '%Y-%m-%d %H:%M:%S' );
        }

        $HasToken = $HasToken ? 'Yes' : 'No';

        my $AccountData = {
            AccountID  => $AccountName,
            AccountCtx => 'Invoker',
            Flow       => $GrantType,
            TokenID    => $Token->{TokenID},
            Token      => $Token->{Token},
            HasToken   => $HasToken,
            NeedToken  => $GrantType eq 'authorization_code' && !$HasToken ? 'Error' : '',
            ExpiresAt  => $Time,
            IsInvoker  => 1,
        };

        push @AccountsForDisplay, $AccountData;
    }

    # Get OAuth Invoker accounts from Config
    my $ProviderAccounts = $FunctionalAccounts->GetOAuthAccounts( AccountCtx => 'Provider' );

    # Sort keys for display
    my @ProviderAccountKeys = keys %$ProviderAccounts;
    @ProviderAccountKeys = sort @ProviderAccountKeys;

    PROVIDERACCOUNT:
    for my $AccountName (@ProviderAccountKeys) {

        my $Account = $ProviderAccounts->{$AccountName};

        my $AccountData = {
            AccountID  => $AccountName,
            AccountCtx => 'Provider',
            Flow       => 'Provider',
            HasToken   => '-',
            NeedToken  => '',
            ExpiresAt  => '-',
            IsInvoker  => 0,
        };

        push @AccountsForDisplay, $AccountData;

    }

    my $ListSize = keys @AccountsForDisplay;

    $LayoutObject->Block(
        Name => 'OverviewHeader',
        Data => {
            AllItemsCount => $ListSize,
            %Errors,
        },
    );

    # if there is data available, it is shown
    if ($ListSize) {

        $LayoutObject->Block(
            Name => 'OverviewResult',
            Data => \%Param,
        );

        for my $Account (@AccountsForDisplay) {

            $LayoutObject->Block(
                Name => 'OverviewResultRow',
                Data => $Account,
            );
        }
    }

    # otherwise, a message is displayed
    else {
        $LayoutObject->Block(
            Name => 'NoAccountsDefined',
            Data => {},
        );
    }

    $Output .= $LayoutObject->Output(
        TemplateFile => 'AdminOAuthTokenStore',
        Data         => \%Param,
    );
    $Output .= $LayoutObject->Footer();

    return $Output;
}

sub _EditInvoker {
    my ( $Self, %Param ) = @_;

    my $LayoutObject       = $Kernel::OM->Get('Kernel::Output::HTML::Layout');
    my $FunctionalAccounts = $Kernel::OM->Get('Kernel::System::OpenIDConnect::FunctionalAccounts');

    my $OIDCProfiles = $FunctionalAccounts->GetOAuthProfiles();

    $LayoutObject->Block(
        Name => 'Overview',
        Data => \%Param,
    );

    $Param{ProviderNames} = $LayoutObject->BuildSelection(
        Data          => $OIDCProfiles,
        Name          => 'ProviderName',
        Class         => 'Modernize',
        SelectedValue => $Param{ProviderName},
    );

    $Param{GrantTypes} = $LayoutObject->BuildSelection(
        Data       => [ 'client_credentials', 'password', 'authorization_code' ],
        Name       => 'GrantType',
        Class      => 'Modernize',
        SelectedID => $Param{GrantType} || 'client_credentials',
    );

    $Param{TokenType}     = $Param{TokenType}     || 'access_token';
    $Param{ResourceParam} = $Param{ResourceParam} || 'resource';

    $LayoutObject->Block(
        Name => 'OverviewUpdateInvoker',
        Data => \%Param,
    );

    return 1;
}

sub _EditProvider {
    my ( $Self, %Param ) = @_;

    my $LayoutObject       = $Kernel::OM->Get('Kernel::Output::HTML::Layout');
    my $FunctionalAccounts = $Kernel::OM->Get('Kernel::System::OpenIDConnect::FunctionalAccounts');

    my $OIDCProfiles = $FunctionalAccounts->GetOAuthProfiles();

    $LayoutObject->Block(
        Name => 'Overview',
        Data => \%Param,
    );

    $Param{ProviderNames} = $LayoutObject->BuildSelection(
        Data          => $OIDCProfiles,
        Name          => 'ProviderName',
        Class         => 'Modernize',
        SelectedValue => $Param{ProviderName},
    );

    $LayoutObject->Block(
        Name => 'OverviewUpdateProvider',
        Data => \%Param,
    );

    return 1;
}

1;
