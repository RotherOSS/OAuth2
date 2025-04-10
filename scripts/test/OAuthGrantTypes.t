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
use URI::Escape qw(uri_escape_utf8);

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

# the OpenIDConfig we will use. This would normally come from SysConfig
my $OpenIDConfig = GetTestOpenIDConfig();

# make sure cache is clean for testing
$OIDCConfiguration->GetProviderData(
    OpenIDConfig => $OpenIDConfig,
    NoCache => 1,
);

# Test Permutations
my @TestScopes = (
    '',
    'openid',
    'openid email profiles',
    'openid http://wild.scope.org',
);

my @TestResources = (
    '',
    'someapi',
    'someapi otherapi',
    'someapi http://wild.resource.org/',
);

my @TestResourceParamNames = (
    '',
    'resource',
    'resources',
    'resourceIds',
);

my @TokenType = (
    'access_token',
    'id_token',
);

# Main Test Cases
my $TestCases = [
    {
        GrantType        => 'client_credentials',
        Expected => [
            { "endpoint" => "openid","content" => ""},
            { "endpoint" => "jwks","content" => ""},
            { "endpoint" => "token","content" => "grant_type=client_credentials"},
        ]        
    },
    {
        GrantType        => 'password',
        Username         => 'test1@example.com',
        Password         => 'test',
        Expected => [
            { "endpoint" => "openid","content" => ""},
            { "endpoint" => "jwks","content" => ""},
            { "endpoint" => "token","content" => "grant_type=password&username=test1%40example.com&password=test"},
        ]
    },
    {
        GrantType        => 'authorization_code',
        Expected => [
            { "endpoint" => "openid","content" => ""},
            { "endpoint" => "jwks","content" => ""},
            { "endpoint" => "token","content" => "grant_type=authorization_code&code=COFFFEEBABECOFFEE&redirect_uri=http%3A%2F%2Fsomewhere.com%2F"},
        ]
    },
];


# iterate!
foreach my $TestCase( @$TestCases ) {
    foreach my $Resources ( @TestResources ) {
        foreach my $ResourceParamName ( @TestResourceParamNames ) {
            foreach my $Scope ( @TestScopes ) {
                foreach my $TokenType ( @TokenType ) {

                    Cleanup();

                    # patch sysconfig just for this process / request
                    PrepareTestSysConfig( 
                        %$TestCase, 
                        Scope             => $Scope, 
                        Resources         => $Resources, 
                        ResourceParamName => $ResourceParamName,
                        Token             => $TokenType,
                    );

                    # use TokenProvider to fetch a Token for the configured unit test account

                    if($TestCase->{GrantType} ne 'authorization_code') {
                        my $Result = $TokenProvider->Fetch(
                            AccountID => '_UnitTest1',  
                        );
                        ok($Result->{Success});
                        ok($Result->{Origin} eq 'fresh_token');
                    }
                    else {

                        # this is authorization_flow, initial token can only be fetched
                        # with the 'code' received through the brwoser flow
                        my $Result = $TokenProvider->FetchToken(
                            AccountID   => '_UnitTest1',  
                            Code        => 'COFFFEEBABECOFFEE',
                            RedirectURL => 'http://somewhere.com/'
                        );

                        ok($Result->{Success});
                        ok($Result->{Origin} eq 'fresh_token');

                        # once we have it, it can be retreived from cache as usual
                        $Result = $TokenProvider->Fetch(
                            AccountID => '_UnitTest1',  
                        );
                        ok($Result->{Success});
                        ok($Result->{Origin} eq 'cache');
                    }

                    # patch up Expected Content dynamically with
                    # scope, resource parameters, for various
                    # 'resource parameter names'
                    my $ExpectedContent = '';

                    if($Resources) {
                        my $ResourceParam = $ResourceParamName || 'resource';
                        $ExpectedContent.= "&$ResourceParam=".uri_escape_utf8($Resources);
                    }
                    if($Scope) {
                        $ExpectedContent.= "&scope=".uri_escape_utf8($Scope);
                    } else {
                        $ExpectedContent.= "&scope=openid";
                    }

                    # impl actually produces '+* instead of '%20', fix that
                    $ExpectedContent =~ s/%20/+/g;

                    # build an Expectation array from the TestCase template
                    # for this permutation
                    my @Expected;
                    foreach my $Expectation ( $TestCase->{Expected}->@* ) {
                        push @Expected, {
                            'content'  => $Expectation->{endpoint} eq 'token' ? 
                                $Expectation->{content} . $ExpectedContent :
                                $Expectation->{content},
                            'endpoint' => $Expectation->{endpoint},
                            'operator' => $Expectation->{operator},
                        };
                    }

                    AssertHttpCallLog( Expected => \@Expected );                
                }
            }            
        }
    }
}

# over and out
done_testing;

Cleanup();

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
        Key => 'OpenIDConnect::FunctionalAccounts',
        Value => {
            '_UnitTest1' => {

                OpenIDConfig      =>'OpenIDConnect::OICDProvider::_UnitTest1',
                GrantType         => $Param{GrantType} || 'client_credentials',
                Scope             => $Param{Scope} || 'openid',
                Resources         => $Param{Resources},
                ResourceParamName => $Param{ResourceParamName} || 'resource',
                Token             => $Param{Token} || 'access_token',
                Username          => $Param{Username},
                Password          => $Param{Password},
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