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

# OTOBO modules
use Kernel::System::VariableCheck qw(:all);

use namespace::autoclean;

#use parent qw(Kernel::System::OpenIDConnect);

our @ObjectDependencies = (
    'Kernel::Config',
    'Kernel::System::DateTime',
    'Kernel::System::Cache',
    'Kernel::System::Log',
    'Kernel::System::Main',
	'Kernel::System::SysConfig',
    'Kernel::System::OpenIDConnect',
#    'Kernel::System::OpenIDConnect::TokenRepository',
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


=head2 GetAccounts()

Returns the OAuth Functional accounts configured in SysConfig.

    my $Accounts = $FunctionalAccountsObject->GetAccounts();

=cut

sub GetAccounts {

    my ( $Self, %Param ) = @_;

    my $ConfigObject = $Kernel::OM->Get('Kernel::Config');

    my $OAuthAccounts = $ConfigObject->Get( 'OpenIDConnect::FunctionalAccounts' );
    if ( !IsHashRefWithData($OAuthAccounts) ) {
        return {};
    }
    return $OAuthAccounts;
}


=head2 GetAccount()

Returns a named OAuth Functional accounts configured in SysConfig.

    my $Account = $FunctionalAccountsObject->GetOAuthAccount(
        AccountID  => '<SomeAccountName>',
    );

=cut

sub GetAccount {

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

    my $OAuthAccounts = $Self->GetAccounts();

    return unless IsHashRefWithData($OAuthAccounts);

    return $OAuthAccounts->{ $Param{AccountID} };
}

=head2 SaveAccount()

Persists Account in SysConfig.

    my $Success = $FunctionalAccountsObject->SaveAccount(
        AccountID  		  => '<SomeAccountName>',
		OpenIDConfig      => $Param{ProviderName},
		GrantType         => $Param{GrantType},
		Scope             => $Param{InvokerScopes},
		Resources         => $Param{Resources},
		ResourceParamName => $Param{ResourceParam},
		Token             => $Param{TokenType},
		Username          => $Param{Username},
		Password          => $Param{Password},		
    );

=cut


sub SaveAccount {

    my ( $Self, %Param ) = @_;

    for my $Needed (qw/AccountID UserID/) {
        if ( !$Param{$Needed} ) {
            $Kernel::OM->Get('Kernel::System::Log')->Log(
                Priority => 'error',
                Message  => "Need $Needed!",
            );

            return;
        }
    }

	my $AccountID    = $Param{AccountID};
	my $OIDCAccounts = $Self->GetAccounts();

    $OIDCAccounts->{ $AccountID } = {
		OpenIDConfig      => $Param{ProviderName},
		GrantType         => $Param{GrantType},
		Scope             => $Param{InvokerScopes},
		Resources         => $Param{Resources},
		ResourceParamName => $Param{ResourceParam},
		Token             => $Param{TokenType},
		Username          => $Param{Username},
		Password          => $Param{Password},
	};

	my $SysConfigObject = $Kernel::OM->Get('Kernel::System::SysConfig');

	my $Success = $SysConfigObject->SettingsSet(
		UserID   => $Param{UserID},
		Comments => "Functional Account " . $AccountID . " created",
		Settings => [
			{
				Name           => 'OpenIDConnect::FunctionalAccounts',
				EffectiveValue => $OIDCAccounts,
				IsValid        => 1,
				NoValidation   => 1,
			},
		],
	);

    sleep(1);
	return $Success;
}

sub DeleteAccount {

    my ( $Self, %Param ) = @_;

    for my $Needed (qw/AccountID UserID/) {
        if ( !$Param{$Needed} ) {
            $Kernel::OM->Get('Kernel::System::Log')->Log(
                Priority => 'error',
                Message  => "Need $Needed!",
            );

            return;
        }
    }

	my $AccountID = $Param{AccountID};

	my $OIDCAccounts = $Self->GetAccounts();
	if ( exists $OIDCAccounts->{$AccountID} ) {

		delete $OIDCAccounts->{$AccountID};

		my $SysConfigObject = $Kernel::OM->Get('Kernel::System::SysConfig');

		my $Success = $SysConfigObject->SettingsSet(
			UserID   => $Param{UserID},
			Comments => "Functional Account " . $AccountID . " deleted.",
			Settings => [
				{
					Name           => "OpenIDConnect::FunctionalAccounts",
					EffectiveValue => $OIDCAccounts,
					IsValid        => 1,
					NoValidation   => 1,
				},
			],
		);
        sleep(1);
		return $Success;
	}

	return;
}

=head2 GetOpenIDConfig()

Returns the OpenIdCOnfig for a named OAuth Functional accounts configured in SysConfig.

    my $OpenIDConfig = $FunctionalAccountsObject->GetOpenIDConfig(
        AccountID  => '<SomeAccountName>',
    );

=cut

sub GetOpenIDConfig {

    my ( $Self, %Param ) = @_;

	my $Account = $Self->GetAccount(%Param);
	return unless IsHashRefWithData($Account);

	my $ConfigObject = $Kernel::OM->Get('Kernel::Config');
	my $Result = $ConfigObject->Get( $Account->{OpenIDConfig} );
    return $Result;
}

=head2 GetProviderData()

Returns the OpenId dynamic Provider Data for a named OAuth Functional accounts configured in SysConfig.

    my $OpenIDProviderData = $FunctionalAccountsObject->GetProviderData(
        AccountID  => '<SomeAccountName>',
    );

=cut

sub GetProviderData {

    my ( $Self, %Param ) = @_;

    my $OpenIDConfig = $Self->GetOpenIDConfig(%Param);
    return unless IsHashRefWithData($OpenIDConfig);

	my $OIDCConfiguration = $Kernel::OM->Get('Kernel::System::OpenIDConnect::Configuration');
	my $OpenIDProviderData = $OIDCConfiguration->GetProviderData(
		OpenIDConfig => $OpenIDConfig
	);

    return $OpenIDProviderData;
}

=head2 GetIssuer()

=for stopwords iss

Returns the OpenId dynamic Provider Issuer value for a named OAuth Functional accounts configured in SysConfig.
This can be used to validate an 'iss' request parameter for incoming OAuth authorization_code callbacks.

    my $Issuer = $FunctionalAccountsObject->GetIssuer(
        AccountID  => '<SomeAccountName>',
    );

    this method returns a simple string.

=cut

sub GetIssuer {

    my ( $Self, %Param ) = @_;

    my $OpenIDProviderData = $Self->GetProviderData(%Param);
    return unless IsHashRefWithData($OpenIDProviderData);

    return $OpenIDProviderData->{OpenIDConfiguration}->{issuer};
}


sub GetTokenEndpoint {

    my ( $Self, %Param ) = @_;

    my $OpenIDProviderData = $Self->GetProviderData( %Param );

    return $OpenIDProviderData->{OpenIDConfiguration}->{token_endpoint};
}


sub GetAuthorizationEndpoint {

    my ( $Self, %Param ) = @_;

    my $OpenIDProviderData = $Self->GetProviderData( %Param );

    return $OpenIDProviderData->{OpenIDConfiguration}->{authorization_endpoint};
}


sub ClearCache {

    my ( $Self, %Param ) = @_;

    my $OpenIDConfig = $Self->GetOpenIDConfig( %Param );

    my $ProviderKey = 'ProviderData' . ( $OpenIDConfig->{ProviderSettings}->{Name} // '' );

    $Kernel::OM->Get('Kernel::System::Cache')->Delete(
        Type => 'OpenIDConnect',
        Key  => $ProviderKey,
    );
}

1;
