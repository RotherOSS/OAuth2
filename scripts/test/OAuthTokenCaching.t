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


#################################################################
# main test
#################################################################

# wait for the fake authorization server to come up
sleep 1;

my $ConfigObject      = $Kernel::OM->Get('Kernel::Config');
my $TokenProvider     = $Kernel::OM->Get('Kernel::System::OpenIDConnect::TokenProvider');
my $TokenRepository   = $Kernel::OM->Get('Kernel::System::OpenIDConnect::TokenRepository');
my $OIDCConfiguration = $Kernel::OM->Get('Kernel::System::OpenIDConnect::Configuration');
my $TokenObject       = $Kernel::OM->Get('Kernel::System::OpenIDConnect::Token');

# the OpenIDConfig we will use. This would normally come from SysConfig
my $OpenIDConfig = GetTestOpenIDConfig();

# make sure cache is clean for testing
$OIDCConfiguration->GetProviderData(
    OpenIDConfig => $OpenIDConfig,
    NoCache => 1,
);
Cleanup();


#################################################################
# Fetch a Token from token_endpoint and validate it
#################################################################

# patch sysconfig just for this process / request
PrepareTestSysConfig();

# use TokenProvider to fetch a Token for the configured unit test account

# 1) fetch a fresh token
my $Result = $TokenProvider->Fetch(
    AccountID => '_UnitTest1',
 );

ok($Result->{Success}, "Result is Success");
ok($Result->{Origin} eq 'fresh_token', 'Origin is fresh_token.');

my $Token = $Result->{Token};

# validate it, one last time
$Result = $TokenObject->Validate(
     Token        => $Token,
     OpenIDConfig => $OpenIDConfig,
);
ok($Result->{Success}, "Result is Success");

# 2) fetch again, now comes from cache
$Result = $TokenProvider->Fetch(
    AccountID => '_UnitTest1',
 );

ok($Result->{Success}, "Result is Success");
ok($Result->{Origin} eq 'cache', 'Origin is cache');

# 3) clean cache, now comes from DB
CleanupCache();

$Result = $TokenProvider->Fetch(
    AccountID => '_UnitTest1',
 );

ok($Result->{Success}, "Result is Success");
ok($Result->{Origin} eq 'db', 'Origin is db.');

# 3) clean cache and DB, now using refresh_token
CleanupCache();
$TokenRepository->Delete(
    AccountID   => '_UnitTest1',
    TokenType   => 'access_token',
);

$Result = $TokenProvider->Fetch(
    AccountID => '_UnitTest1',
 );

ok($Result->{Success}, "Result is Success");
ok($Result->{Origin} eq 'refresh_token', 'Origin is refresh_token');

# 4) clean cache,DB and refresh_token - 

Cleanup();
$Result = $TokenProvider->Fetch(
    AccountID => '_UnitTest1',
 );

ok($Result->{Success}, "Result is Success");
ok($Result->{Origin} eq 'fresh_token', 'Origin is fresh_token');

#################################################################
# invalid credentials
#################################################################

Cleanup();
$OpenIDConfig->{ClientSettings}->{ClientSecret} = 'murks';
PrepareTestSysConfig();

$Result = $TokenProvider->Fetch(
    AccountID => '_UnitTest1',
 );

ok(!$Result->{Success});

#################################################################
# Test 4) - Assert on the spied Log of our fake server
# here we can assert that parameters have been passed as
# expected to the token_endpoint
#################################################################

AssertHttpCallLog( 
    Expected => [
        { "endpoint" => "openid","content" => ""},
        { "endpoint" => "jwks","content" => ""},
        { "endpoint" => "token", "content" => "grant_type=client_credentials&resource=some_api&scope=openid"},
        { "endpoint" => "openid","content" => ""},
        { "endpoint" => "jwks","content" => ""},
        { "content"  => "grant_type=refresh_token&refresh_token=","endpoint" => "token", operator => 'match' },
        { "endpoint" => "openid","content" => ""},
        { "endpoint" => "jwks","content" => ""},
        { "endpoint" => "token", "content" => "grant_type=client_credentials&resource=some_api&scope=openid"},
        { "endpoint" => "openid","content" => ""},
        { "endpoint" => "jwks","content" => ""},
        { "content"  => "grant_type=client_credentials&resource=some_api&scope=openid","endpoint" => "token"},
    ]
);

# over and out
done_testing;

Cleanup();

# tear down fake server
kill( 'TERM', $main::ChildPID );
waitpid( $main::ChildPID, 0 );


# patch sysconfig just for this process / request

sub PrepareTestSysConfig {

    # configure an OIDC Profile for the unit test
    $ConfigObject->Set(
        Key   => 'OpenIDConnect::OICDProvider::_UnitTest1',
        Value => $OpenIDConfig,
    );

    # configure a functional account that uses above config
    $ConfigObject->Set(
        Key => 'OpenIDConnect::FunctionalAccounts',
        Value => {
            '_UnitTest1' => {

                OpenIDConfig      =>'OpenIDConnect::OICDProvider::_UnitTest1',
                GrantType         => 'client_credentials',
                Scope             => 'openid',
                Resources         => 'some_api',
                ResourceParamName => 'resource',
                Token             => 'access_token',
                # Username        => $Param{Username},
                # Password        => $Param{Password},
            }
        },
    );
}

sub Cleanup {

    # cleanup cache and db
    $TokenRepository->Delete(
        AccountID => '_UnitTest1',
    );

    CleanupCache();
}

sub CleanupCache {

    $TokenProvider->EmptyCache(
        AccountID => '_UnitTest1',
    );
}