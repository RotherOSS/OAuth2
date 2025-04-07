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

package Kernel::System::OpenIDConnect::FunctionalAccounts;

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
    'Kernel::System::OpenIDConnect::TokenRepository',
);

=head1 NAME

Kernel::System::OpenIDConnect::FunctionalAccounts

manage OAuth2/OIDC backed Functional Accounts.
Currently implemented are accounts for
Invokers and Providers. MailAccounts next.

=head1 SYNOPSIS

Functional account functions for OpenID Connect

create an object

    use Kernel::System::ObjectManager;
    local $Kernel::OM = Kernel::System::ObjectManager->new();
    my $FunctionalAccountsObject = $Kernel::OM->Get('Kernel::System::OpenIDConnect::FunctionalAccounts');

=cut

sub new {
    my ( $Type, %Param ) = @_;

    # allocate new hash for object
    my $Self = {};
    bless( $Self, $Type );

    return $Self;
}

=head2 GetOAuthProfiles()

Returns a list of the Name of the OpenID Connect Profiles
with the OAuth2 Provider and Client Settings.

    my $Profiles = $FunctionalAccountsObject->GetOAuthProfiles();

=cut

sub GetOAuthProfiles {

    my ( $Self, %Param ) = @_;

    my $ConfigObject  = $Kernel::OM->Get('Kernel::Config');
    my $OAuthProfiles = $ConfigObject->Get('OpenIDConnect::ClientProfiles');

    return $OAuthProfiles;
}

=head2 GetOAuthAccounts()

Returns the OAuth Functional accounts configured in SysConfig.

    my $Accounts = $FunctionalAccountsObject->GetOAuthAccounts(
        AccountCtx => 'Invoker',  # or 'Provider'
    );

=cut

sub GetOAuthAccounts {

    my ( $Self, %Param ) = @_;

    my $ConfigObject = $Kernel::OM->Get('Kernel::Config');

    my $AccountCtx = $Param{AccountCtx};

    if ( $AccountCtx && ( $AccountCtx eq 'Provider' || $AccountCtx eq 'Invoker' ) ) {

        my $OAuthAccounts = $ConfigObject->Get( 'OpenIDConnect::' . $Param{AccountCtx} . '::Accounts' );
        if ( !IsHashRefWithData($OAuthAccounts) ) {
            return {};
        }
        return $OAuthAccounts;
    }

    return {};
}

=head2 GetOAuthAccount()

Returns a named OAuth Functional accounts configured in SysConfig.

    my $Account = $FunctionalAccountsObject->GetOAuthAccount(
        AccountCtx => 'Invoker',           # or 'Provider'
        AccountID  => '<SomeAccountName>',
    );

=cut

sub GetOAuthAccount {

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

    my $OAuthAccounts = $Self->GetOAuthAccounts( AccountCtx => $Param{AccountCtx} );

    return unless IsHashRefWithData($OAuthAccounts);

    return $OAuthAccounts->{ $Param{AccountID} };
}

=head2 GetOpenIDConfig()

Returns the OpenIdCOnfig for a named OAuth Functional accounts configured in SysConfig.

    my $OpenIDConfig = $FunctionalAccountsObject->GetOpenIDConfig(
        AccountCtx => 'Invoker',             # or Provider
        AccountID  => '<SomeAccountName>',
    );

=cut

sub GetOpenIDConfig {

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

    my $Account = $Self->GetOAuthAccount(%Param);
    return unless IsHashRefWithData($Account);

    my $ConfigObject = $Kernel::OM->Get('Kernel::Config');
    return $ConfigObject->Get( $Account->{OpenIDConfig} || 'AuthModule::OpenIDConnect::Config' );
}

=head2 GetProviderData()

Returns the OpenId dynamic Provider Data for a named OAuth Functional accounts configured in SysConfig.

    my $OpenIDProviderData = $FunctionalAccountsObject->GetProviderData(
        AccountCtx => 'Provider',                # or Invoker
        AccountID  => '<SomeAccountName>',
    );

=cut

sub GetProviderData {

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

    my $OpenIDConfig = $Self->GetOpenIDConfig(%Param);
    return unless IsHashRefWithData($OpenIDConfig);

    my $ProviderKey = 'ProviderData' . ( $OpenIDConfig->{ProviderSettings}{Name} // '' );

    my $OpenIDProviderData = $Kernel::OM->Get('Kernel::System::Cache')->Get(
        Type => 'OpenIDConnect',
        Key  => $ProviderKey,
    );

    # if nothing is cached, get the data
    if ( !$OpenIDProviderData ) {

        my $OpenIDConnectObject = $Kernel::OM->Get('Kernel::System::OpenIDConnect');

        $OpenIDProviderData = $OpenIDConnectObject->_ProviderDataGet(
            ProviderSettings => $OpenIDConfig->{ProviderSettings},
        );
    }

    return $OpenIDProviderData;
}

=head2 GetIssuer()

=for stopwords iss

Returns the OpenId dynamic Provider Issuer value for a named OAuth Functional accounts configured in SysConfig.
This can be used to validate an 'iss' request parameter for incoming OAuth authorization_code callbacks.

    my $Issuer = $FunctionalAccountsObject->GetIssuer(
        AccountCtx => 'Provider',                # or Invoker
        AccountID  => '<SomeAccountName>',
    );

    this method returns a simple string.

=cut

sub GetIssuer {

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

    my $OpenIDProviderData = $Self->GetProviderData(%Param);
    return unless IsHashRefWithData($OpenIDProviderData);

    return $OpenIDProviderData->{OpenIDConfiguration}->{issuer};
}

1;
