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

# OTOBO modules
use Kernel::System::UnitTest::RegisterOM;    # set up $Kernel::OM

my $CurrentTime = $Kernel::OM->Create('Kernel::System::DateTime')->ToEpoch();
my $MainObject  = $Kernel::OM->Get('Kernel::System::Main');
$MainObject->Require("$Bin/OAuthProviderMock");

#$OAuthProviderMock::KidID || $OAuthProviderMock::PrivateKey || 0;      # prevent warnings

#################################################################
# main test
#################################################################

# wait for the fake authorization server to come up
sleep 1;

my $ConfigObject      = $Kernel::OM->Get('Kernel::Config');
my $OIDCConfiguration = $Kernel::OM->Get('Kernel::System::OpenIDConnect::Configuration');
my $Authenticator     = $Kernel::OM->Get('Kernel::System::OpenIDConnect::Authenticator');

# the OpenIDConfig we will use. This would normally come from SysConfig
my $OpenIDConfig = OAuthProviderMock::GetTestOpenIDConfig();

eval {

    # make sure cache is clean for testing
    $OIDCConfiguration->GetProviderData(
        OpenIDConfig => $OpenIDConfig,
        NoCache      => 1,
    );

    PrepareTestSysConfig();

    #################################################################
    # 1) Simple JWT
    #################################################################

    my $Token = encode_jwt(
        payload       => OAuthProviderMock::Payload(),
        alg           => 'RS256',
        key           => $OAuthProviderMock::PrivateKey,
        extra_headers => { kid => $OAuthProviderMock::KidID },
    );

    # now validate this token, which will talk to our fake authorization server
    # and fetch the public key to validate the signature

    my $Result = $Authenticator->Authenticate(
        Token => $Token,
    );

    ok( $Result->{Success}, 'Authenticated' );

    #################################################################
    # 2) Simple JWT with dedicated scopes
    #################################################################

    PrepareTestSysConfig(
        Scope => 'openid superduper',
    );

    $Token = encode_jwt(
        payload       => OAuthProviderMock::Payload( Scope => 'openid superduper' ),
        alg           => 'RS256',
        key           => $OAuthProviderMock::PrivateKey,
        extra_headers => { kid => $OAuthProviderMock::KidID },
    );

    # now validate this token, which will talk to our fake authorization server
    # and fetch the public key to validate the signature

    $Result = $Authenticator->Authenticate(
        Token => $Token,
    );

    ok( $Result->{Success}, 'Authenticated' );

    #################################################################
    # 3) Simple JWT with dedicated audience check
    #################################################################

    PrepareTestSysConfig(
        Audience => 'otobo',
    );

    $Token = encode_jwt(
        payload       => OAuthProviderMock::Payload( Audience => [ 'otobo', 'mammamia' ] ),
        alg           => 'RS256',
        key           => $OAuthProviderMock::PrivateKey,
        extra_headers => { kid => $OAuthProviderMock::KidID },
    );

    # now validate this token, which will talk to our fake authorization server
    # and fetch the public key to validate the signature

    $Result = $Authenticator->Authenticate(
        Token => $Token,
    );

    ok( $Result->{Success}, 'Authenticated' );

    #################################################################
    # 4) Simple JWT with Authorized Party check
    #################################################################

    PrepareTestSysConfig(
        AuthorizedParty => 'otobo',
    );

    $Token = encode_jwt(
        payload       => OAuthProviderMock::Payload(),
        alg           => 'RS256',
        key           => $OAuthProviderMock::PrivateKey,
        extra_headers => { kid => $OAuthProviderMock::KidID },
    );

    # now validate this token, which will talk to our fake authorization server
    # and fetch the public key to validate the signature

    $Result = $Authenticator->Authenticate(
        Token => $Token,
    );

    ok( $Result->{Success}, 'Authenticated' );

    #################################################################
    # assert on the spy log
    #################################################################

    OAuthProviderMock::AssertHttpCallLog(
        Expected => [
            {
                "endpoint" => "openid",
                "content"  => ""
            },
            {
                "endpoint" => "jwks",
                "content"  => ""
            },
        ]
    );
};
if ($@) {
    print STDERR "$@\n";
    ok( 0, "should not throw." );
}

# over and out
done_testing;

# tear down fake server
kill( 'TERM', $OAuthProviderMock::ChildPID );
waitpid( $OAuthProviderMock::ChildPID, 0 );

# patch sysconfig just for this process / request

sub PrepareTestSysConfig {

    my %Param = @_;

    #     # create profile

    #     my $YAMLObject = $Kernel::OM->Get('Kernel::System::YAML');

    #     my $Valid = 1;

    #     $DBObject->Do( SQL => "DELETE FROM oidc_functional_accounts WHERE name = '_UnitTest1' ");
    #     $DBObject->Do( SQL => "DELETE FROM oidc_profiles WHERE name = '" .$OpenIDConfig->{ProviderSettings}->{Name}. "'");

    #     $DBObject->Do(
    #         SQL => "INSERT INTO oidc_profiles
    #                 ( name,client_id,client_Secret,redirect_uri,openid_config,
    #                 ssl_options,misc,ttl,valid_id,
    #                 create_time,create_by,change_time,change_by )
    #                 VALUES (?, ?, ?, ?,?, ?, ?, ?, ?, current_timestamp, 1, current_timestamp, 1)",
    #         Bind => [
    #             \$OpenIDConfig->{ProviderSettings}->{Name},
    #             \$OpenIDConfig->{ClientSettings}->{ClientID},
    #             \$OpenIDConfig->{ClientSettings}->{ClientSecret},
    #             \$OpenIDConfig->{ClientSettings}->{RedirectURI} // '',
    #             \$OpenIDConfig->{ProviderSettings}->{OpenIDConfiguration},
    #             \$YAMLObject->Dump(Data => $OpenIDConfig->{ProviderSettings}->{SSLOptions} ),
    #             \$YAMLObject->Dump(Data => $OpenIDConfig->{Misc} // {} ),
    #             \$OpenIDConfig->{ProviderSettings}->{TTL},
    #             \$Valid,
    #         ],
    #     );

    #     $DBObject->Prepare(
    #             SQL => "SELECT id FROM oidc_profiles WHERE name = ? ",
    #             Bind  => [ \$OpenIDConfig->{ProviderSettings}->{Name} ],
    # #            Limit => 1
    #     );

    #     my ($ID) = $DBObject->FetchrowArray();

    #     # create functional account

    #     my $GrantType         = $Param{GrantType} || 'authorization_code';
    #     my $Scope             = $Param{Scope} || 'openid';
    #     my $Resources         = $Param{Resources} || '';
    #     my $ResourceParamName = $Param{ResourceParamName} || 'resource';
    #     my $TokenType         = $Param{Token} || 'access_token';

    # print STDERR "TOKENTYPE: $TokenType\n";

    #     $DBObject->Do(
    #         SQL => "INSERT INTO oidc_functional_accounts
    #                 (name, oidc_profile_id,grant_type,scopes,resources,
    #                 resource_param_name,username,passwd, token_type, valid_id,
    #                 create_time,create_by,change_time,change_by )
    #                 VALUES ( '_UnitTest1', ?, ?, ?, ?, ?, ?, ?, ?, ?, current_timestamp, 1, current_timestamp, 1)",
    #         Bind => [
    #             \$ID,
    #             \$GrantType,
    #             \$Scope,
    #             \$Resources,
    #             \$ResourceParamName,
    #             \$Param{Username},
    #             \$Param{Password},
    #             \$TokenType,
    #             \$Valid,
    #         ],
    #     );

    # configure an OIDC Profile for the unit test
    $ConfigObject->Set(
        Key   => 'AuthModule::_UnitTest1::Config',
        Value => $OpenIDConfig,
    );

    $ConfigObject->Set(
        Key   => 'AuthModule2',
        Value => 'Kernel::System::Auth::_UnitTest1',
    );

    # # configure a functional account that uses above config
    # $ConfigObject->Set(
    #     Key   => 'OpenIDConnect::UserMapping',
    #     Value => {

    #         'UnitTest1' => {

    #             OpenIDConfig    => 'OpenIDConnect::OICDProvider::_UnitTest1',
    #             Audience        => $Param{Audience}        || '',
    #             Scope           => $Param{Scope}           || '',
    #             UID             => $Param{UID}             || 'sub',
    #             UserLogin       => $Param{UserLogin}       || '',
    #             AuthorizedParty => $Param{AuthorizedParty} || '',

    #         }
    #     },
    # );

    return;
}
