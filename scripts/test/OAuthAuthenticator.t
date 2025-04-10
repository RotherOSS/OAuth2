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
use Data::Dumper;

# OTOBO modules
use Kernel::System::UnitTest::RegisterOM;    # set up $Kernel::OM

my $CurrentTime = $Kernel::OM->Create('Kernel::System::DateTime')->ToEpoch();

require( "$Bin/OAuthProviderMock.pm" );
$main::KidID || $main::PrivateKey || 0; # prevent warnings

#################################################################
# main test
#################################################################

# wait for the fake authorization server to come up
sleep 1;

my $ConfigObject      = $Kernel::OM->Get('Kernel::Config');
my $OIDCConfiguration = $Kernel::OM->Get('Kernel::System::OpenIDConnect::Configuration');
my $Authenticator     = $Kernel::OM->Get('Kernel::System::OpenIDConnect::Authenticator');


# the OpenIDConfig we will use. This would normally come from SysConfig
my $OpenIDConfig = GetTestOpenIDConfig();

# make sure cache is clean for testing
$OIDCConfiguration->GetProviderData(
    OpenIDConfig => $OpenIDConfig,
    NoCache => 1,
);

PrepareTestSysConfig();


#################################################################
# 1) Simple JWT
#################################################################

my $Token = encode_jwt(
    payload       => Payload(), 
    alg           =>'RS256', 
    key           => $main::PrivateKey,
    extra_headers => { kid => $main::KidID },    
);


# now validate this token, which will talk to our fake authorization server
# and fetch the public key to validate the signature

my $Result = $Authenticator->Authenticate(
    Token => $Token,
);

ok( $Result->{Success}, 'Authenticated');


#################################################################
# 2) Simple JWT with dedicated scopes
#################################################################

PrepareTestSysConfig(
    Scope => 'openid superduper',
);

$Token = encode_jwt(
    payload       => Payload( Scope => 'openid superduper' ), 
    alg           =>'RS256', 
    key           => $main::PrivateKey,
    extra_headers => { kid => $main::KidID },    
);


# now validate this token, which will talk to our fake authorization server
# and fetch the public key to validate the signature

$Result = $Authenticator->Authenticate(
    Token => $Token,
);

ok( $Result->{Success}, 'Authenticated');


#################################################################
# 3) Simple JWT with dedicated audience check
#################################################################

PrepareTestSysConfig(
    Audience => 'otobo',
);

$Token = encode_jwt(
    payload       => Payload( Audience => [ 'otobo', 'mammamia'] ), 
    alg           =>'RS256', 
    key           => $main::PrivateKey,
    extra_headers => { kid => $main::KidID },    
);


# now validate this token, which will talk to our fake authorization server
# and fetch the public key to validate the signature

$Result = $Authenticator->Authenticate(
    Token => $Token,
);

ok( $Result->{Success}, 'Authenticated');

#################################################################
# 4) Simple JWT with Authorized Party check
#################################################################

PrepareTestSysConfig(
    AuthorizedParty => 'otobo',
);

$Token = encode_jwt(
    payload       => Payload( ), 
    alg           =>'RS256', 
    key           => $main::PrivateKey,
    extra_headers => { kid => $main::KidID },    
);


# now validate this token, which will talk to our fake authorization server
# and fetch the public key to validate the signature

$Result = $Authenticator->Authenticate(
    Token => $Token,
);

ok( $Result->{Success}, 'Authenticated');

#################################################################
# assert on the spy log
#################################################################

AssertHttpCallLog(
    Expected => [
        { "endpoint" => "openid","content" => ""},
        { "endpoint" => "jwks","content" => ""},
    ]
);

# over and out
done_testing;

# tear down fake server
kill( 'TERM', $main::ChildPID );
waitpid( $main::ChildPID, 0 );


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
        Key => 'OpenIDConnect::UserMapping',
        Value => {

            'UnitTest1' => {

                OpenIDConfig      =>'OpenIDConnect::OICDProvider::_UnitTest1',
                Audience          => $Param{Audience} || '',
                Scope             => $Param{Scope} || '',
                UID               => $Param{UID} || 'sub',
                UserLogin         => $Param{UserLogin} || '',
                AuthorizedParty   => $Param{AuthorizedParty} || '',

            }
        },
    );
}
