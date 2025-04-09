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

package Kernel::System::OpenIDConnect::UserMappings;

use strict;
use warnings;

# core modules

# CPAN modules

# OTOBO modules
use Kernel::System::VariableCheck qw(:all);

use namespace::autoclean;

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

Kernel::System::OpenIDConnect::UserMappings

manage mappings for incoming webservice calls 
authorized with an OIDC OAuth2 bearer token.

=head1 SYNOPSIS

User Mappings for OpenID Connect

create an object

    use Kernel::System::ObjectManager;
    local $Kernel::OM = Kernel::System::ObjectManager->new();
    my $UserMappingsObject = $Kernel::OM->Get('Kernel::System::OpenIDConnect::UserMappings');

=cut

sub new {
    my ( $Type, %Param ) = @_;

    # allocate new hash for object
    my $Self = {};
    bless( $Self, $Type );

    return $Self;
}

=head2 GetUserMappings()

Returns the OAuth Functional accounts configured in SysConfig.

    my $Accounts = $UserMappingsObject->GetUserMappings();

=cut

sub GetUserMappings {

    my ( $Self, %Param ) = @_;

    my $ConfigObject = $Kernel::OM->Get('Kernel::Config');

    my $SysConfigObject = $Kernel::OM->Get('Kernel::System::SysConfig');
    my @SearchResult = $SysConfigObject->ConfigurationSearch(Category => 'All', Search => 'OpenIDConnect::UserMapping' );
    
    my %ValidProviderMappings;
    foreach my $SettingName( @SearchResult) {
        my %Setting = $SysConfigObject->SettingGet(Name => $SettingName);
        if( $Setting{IsValid}) {
            $ValidProviderMappings{$SettingName} = $Setting{EffectiveValue};
        }
    }

    return \%ValidProviderMappings;

    return {};
}

=head2 GetUserMapping()

Returns a named OAuth Functional accounts configured in SysConfig.

    my $Account = $UserMappingsObject->GetUserMapping(
        AccountID  => '<SomeAccountName>',
    );

=cut

sub GetUserMapping {

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

    my $Mappings = $Self->GetUserMappings();

    return unless IsHashRefWithData($Mappings);

    return $Mappings->{ $Param{AccountID} };
}

=head2 GetOpenIDConfig()

Returns the OpenIdCOnfig for a User Mapping.

    my $OpenIDConfig = $UserMappingsObject->GetOpenIDConfig(
        AccountID  => '<SomeAccountName>',
    );

=cut

sub GetOpenIDConfig {

    my ( $Self, %Param ) = @_;

	my $Mapping = $Self->GetUserMapping(%Param);
	return unless IsHashRefWithData($Mapping);

	my $ConfigObject = $Kernel::OM->Get('Kernel::Config');
	return $ConfigObject->Get( $Mapping->{OpenIDConfig} );
}

=head2 GetProviderData()

Returns the OpenId dynamic Provider Data for a named OAuth Functional accounts configured in SysConfig.

    my $OpenIDProviderData = $UserMappingsObject->GetProviderData(
        AccountId => 'AccountName',                
    );

=cut

sub GetProviderData {

    my ( $Self, %Param ) = @_;

    my $OpenIDConfig = $Self->GetOpenIDConfig(%Param);
    return unless IsHashRefWithData($OpenIDConfig);

	my $OIDCConfiguration = $Kernel::OM->Get('Kernel::System::OpenIDConnect::Configuration');
	my $OpenIDProviderData = $OIDCConfiguration->GetProviderData(
		OpenIDCOnfig => $OpenIDConfig
	);

    return $OpenIDProviderData;
}

=head2 GetIssuer()

=for stopwords iss

Returns the OpenId dynamic Provider Issuer value for a named OAuth Functional accounts configured in SysConfig.
This can be used to validate an 'iss' request parameter for incoming OAuth authorization_code callbacks.

    my $Issuer = $UserMappingsObject->GetIssuer(
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

1;
