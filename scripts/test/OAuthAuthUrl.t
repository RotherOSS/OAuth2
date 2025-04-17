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

use v5.24;
use strict;
use warnings;
use utf8;

# core modules
use FindBin qw($Bin);

# CPAN modules
use Test2::V0;
use Crypt::JWT qw(encode_jwt decode_jwt);
use Crypt::PK::RSA;
use Plack::Runner;
use Plack::Request;
use Try::Tiny qw(try catch);
use JSON;
use URI::Escape qw(uri_escape_utf8);

# OTOBO modules
use Kernel::System::UnitTest::RegisterOM;    # set up $Kernel::OM

my $MainObject = $Kernel::OM->Get('Kernel::System::Main');
$MainObject->Require("$Bin/OAuthProviderMock");

my $ConfigObject      = $Kernel::OM->Get('Kernel::Config');
my $TokenProvider     = $Kernel::OM->Get('Kernel::System::OpenIDConnect::TokenProvider');
my $TokenRepository   = $Kernel::OM->Get('Kernel::System::OpenIDConnect::TokenRepository');
my $OIDCConfiguration = $Kernel::OM->Get('Kernel::System::OpenIDConnect::Configuration');

my $BaseURL     = 'http://localhost:2007/realms/master/protocol/openid-connect/auth';
my $RedirectURI = 'https://your.otobo.url/otobo/index.pl?Action=AdminOAuthTokenStore&Subaction=OAuth';

my $TestCases = [
    {
        Config => {
        },
        Expectation => '?response_type=code&scope=openid&client_id=otobo&state=',
    },
    {
        Config => {
            Scope => 'openid email profile http://weirdscope.com',
        },
        Expectation => '?response_type=code&scope=openid%20email%20profile%20http%3A%2F%2Fweirdscope.com&client_id=otobo&state=',
    },
    {
        Config => {
            Resources => 'someapi http://weirdresource.com',
        },
        Expectation => '?response_type=code&scope=openid&client_id=otobo&resource=someapi%20http%3A%2F%2Fweirdresource.com&state=',
    },
    {
        Config => {
            Token => 'id_token',
        },
        Expectation => '?response_type=code%20id_token&scope=openid&client_id=otobo&response_mode=form_post&state=',
    },
    {
        Config => {
            Login => 'someone@somedomain.com',
        },
        Expectation => '?response_type=code&scope=openid&client_id=otobo&login_hint=someone%40somedomain.com&state=',
    },
    {
        Config => {
            Prompt => 1,
        },
        Expectation => '?response_type=code&scope=openid&client_id=otobo&prompt=login&state=',
    },
];

my $OpenIDConfig = OAuthProviderMock::GetTestOpenIDConfig();

for my $TestCase (@$TestCases) {

    PrepareTestSysConfig( $TestCase->{Config}->%* );

    my $RandomString = $Kernel::OM->Get('Kernel::System::Main')->GenerateRandomString(
        Length => 22
    );

    my $Expected = $BaseURL . $TestCase->{Expectation};
    $Expected .= $RandomString;
    $Expected .= '&redirect_uri=';
    $Expected .= uri_escape_utf8($RedirectURI);

    my $AuthURL = $TokenProvider->GetAuthURL(
        AccountID   => '_UnitTest1',
        RedirectURI => $RedirectURI,
        State       => $RandomString,
        Login       => $TestCase->{Config}->{Login},
        Prompt      => $TestCase->{Config}->{Prompt},
    );

    ok( $AuthURL eq $Expected, "$AuthURL eq $Expected" );

}

done_testing;

# tear down fake server
kill( 'TERM', $OAuthProviderMock::ChildPID );
waitpid( $OAuthProviderMock::ChildPID, 0 );

# patch sysconfig just for this process / request

sub PrepareTestSysConfig {

    my %Param = @_;

    # configure an OIDC Profile for the unit test
    $ConfigObject->Set(
        Key   => 'OpenIDConnect::OICDProvider::_UnitTest1',
        Value => $OpenIDConfig,
    );

    # configure a functional account that uses above config
    $ConfigObject->Set(
        Key   => 'OpenIDConnect::FunctionalAccounts',
        Value => {
            '_UnitTest1' => {

                OpenIDConfig      => 'OpenIDConnect::OICDProvider::_UnitTest1',
                GrantType         => $Param{GrantType}         || 'authorization_code',
                Scope             => $Param{Scope}             || 'openid',
                Resources         => $Param{Resources}         || '',
                ResourceParamName => $Param{ResourceParamName} || 'resource',
                Token             => $Param{Token}             || 'access_token',
                Username          => $Param{Username},
                Password          => $Param{Password},
            }
        },
    );

    return;
}
