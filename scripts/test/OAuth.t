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


#################################################################
# prepare shared RSA key
#################################################################

my $PrivateKey = Crypt::PK::RSA->new();
$PrivateKey->generate_key(256, 65537);

# prepare kid data to be served from fake authorization server
my $KidData       = decode_json($PrivateKey->export_key_jwk('public'));
my $KidThumbprint = $PrivateKey->export_key_jwk_thumbprint();
my $KidID         = '2QqRmKFkfpBHoO4cj-yVfrHJykIBLOMbbe7qBvU5Unk';


#################################################################
# start test server
#################################################################

my $ChildPID = fork();

if ( !$ChildPID ) {

    # i am the forked child
    # run the test server

    try {

         my $App = sub {

            my $env = shift; # PSGI env
            my $req = Plack::Request->new($env);

            if($req->path() eq '/realms/master/.well-known/openid-configuration') {

                # test fixture from hell
                my $Data = {
                    "issuer" => "http://localhost:2007/realms/master",
                    "authorization_endpoint" => "http://localhost:2007/realms/master/protocol/openid-connect/auth",
                    "token_endpoint" => "http://localhost:2007/realms/master/protocol/openid-connect/token",
                    "introspection_endpoint" => "http://localhost:2007/realms/master/protocol/openid-connect/token/introspect",
                    "userinfo_endpoint" => "http://localhost:2007/realms/master/protocol/openid-connect/userinfo",
                    "end_session_endpoint" => "http://localhost:2007/realms/master/protocol/openid-connect/logout",
                    "frontchannel_logout_session_supported" => 1,
                    "frontchannel_logout_supported" => 1,
                    "jwks_uri" => "http://localhost:2007/realms/master/protocol/openid-connect/certs",
                    "check_session_iframe" => "http://localhost:2007/realms/master/protocol/openid-connect/login-status-iframe.html",
                    "grant_types_supported" => ["authorization_code","implicit","refresh_token","password","client_credentials","urn:openid:params:grant-type:ciba","urn:ietf:params:oauth:grant-type:device_code"],
                    "acr_values_supported" => ["0","1"],
                    "response_types_supported" => ["code","none","id_token","token","id_token token","code id_token","code token","code id_token token"],
                    "subject_types_supported" => ["public","pairwise"],
                    "prompt_values_supported" => ["none","login","consent"],
                    "id_token_signing_alg_values_supported" => ["PS384","RS384","EdDSA","ES384","HS256","HS512","ES256","RS256","HS384","ES512","PS256","PS512","RS512"],
                    "id_token_encryption_alg_values_supported" => ["ECDH-ES+A256KW","ECDH-ES+A192KW","ECDH-ES+A128KW","RSA-OAEP","RSA-OAEP-256","RSA1_5","ECDH-ES"],
                    "id_token_encryption_enc_values_supported" => ["A256GCM","A192GCM","A128GCM","A128CBC-HS256","A192CBC-HS384","A256CBC-HS512"],
                    "userinfo_signing_alg_values_supported" => ["PS384","RS384","EdDSA","ES384","HS256","HS512","ES256","RS256","HS384","ES512","PS256","PS512","RS512","none"],
                    "userinfo_encryption_alg_values_supported" => ["ECDH-ES+A256KW","ECDH-ES+A192KW","ECDH-ES+A128KW","RSA-OAEP","RSA-OAEP-256","RSA1_5","ECDH-ES"],
                    "userinfo_encryption_enc_values_supported" => ["A256GCM","A192GCM","A128GCM","A128CBC-HS256","A192CBC-HS384","A256CBC-HS512"],
                    "request_object_signing_alg_values_supported" => ["PS384","RS384","EdDSA","ES384","HS256","HS512","ES256","RS256","HS384","ES512","PS256","PS512","RS512","none"],
                    "request_object_encryption_alg_values_supported" => ["ECDH-ES+A256KW","ECDH-ES+A192KW","ECDH-ES+A128KW","RSA-OAEP","RSA-OAEP-256","RSA1_5","ECDH-ES"],
                    "request_object_encryption_enc_values_supported" => ["A256GCM","A192GCM","A128GCM","A128CBC-HS256","A192CBC-HS384","A256CBC-HS512"],
                    "response_modes_supported" => ["query","fragment","form_post","query.jwt","fragment.jwt","form_post.jwt","jwt"],
                    "registration_endpoint" => "http://localhost:2007/realms/master/clients-registrations/openid-connect",
                    "token_endpoint_auth_methods_supported" => ["private_key_jwt","client_secret_basic","client_secret_post","tls_client_auth","client_secret_jwt"],
                    "token_endpoint_auth_signing_alg_values_supported" => ["PS384","RS384","EdDSA","ES384","HS256","HS512","ES256","RS256","HS384","ES512","PS256","PS512","RS512"],
                    "introspection_endpoint_auth_methods_supported" => ["private_key_jwt","client_secret_basic","client_secret_post","tls_client_auth","client_secret_jwt"],
                    "introspection_endpoint_auth_signing_alg_values_supported" => ["PS384","RS384","EdDSA","ES384","HS256","HS512","ES256","RS256","HS384","ES512","PS256","PS512","RS512"],
                    "authorization_signing_alg_values_supported" => ["PS384","RS384","EdDSA","ES384","HS256","HS512","ES256","RS256","HS384","ES512","PS256","PS512","RS512"],
                    "authorization_encryption_alg_values_supported" => ["ECDH-ES+A256KW","ECDH-ES+A192KW","ECDH-ES+A128KW","RSA-OAEP","RSA-OAEP-256","RSA1_5","ECDH-ES"],
                    "authorization_encryption_enc_values_supported" => ["A256GCM","A192GCM","A128GCM","A128CBC-HS256","A192CBC-HS384","A256CBC-HS512"],
                    "claims_supported" => ["aud","sub","iss","auth_time","name","given_name","family_name","preferred_username","email","acr"],
                    "claim_types_supported" => ["normal"],
                    "claims_parameter_supported" => 1,
                    "scopes_supported" => ["openid","organization","phone","offline_access","profile","web-origins","service_account","basic","email","acr","address","microprofile-jwt","imap","roles"],
                    "request_parameter_supported" => 1,
                    "request_uri_parameter_supported" => 1,
                    "require_request_uri_registration" => 1,
                    "code_challenge_methods_supported" => ["plain","S256"],
                    "tls_client_certificate_bound_access_tokens" => 1,
                    "revocation_endpoint" => "http://localhost:2007/realms/master/protocol/openid-connect/revoke",
                    "revocation_endpoint_auth_methods_supported" => ["private_key_jwt","client_secret_basic","client_secret_post","tls_client_auth","client_secret_jwt"],
                    "revocation_endpoint_auth_signing_alg_values_supported" => ["PS384","RS384","EdDSA","ES384","HS256","HS512","ES256","RS256","HS384","ES512","PS256","PS512","RS512"],
                    "backchannel_logout_supported" => 1,
                    "backchannel_logout_session_supported" => 1,
                    "device_authorization_endpoint" => "http://localhost:2007/realms/master/protocol/openid-connect/auth/device",
                    "backchannel_token_delivery_modes_supported" => ["poll","ping"],
                    "backchannel_authentication_endpoint" => "http://localhost:2007/realms/master/protocol/openid-connect/ext/ciba/auth",
                    "backchannel_authentication_request_signing_alg_values_supported" => ["PS384","RS384","EdDSA","ES384","ES256","RS256","ES512","PS256","PS512","RS512"],
                    "require_pushed_authorization_requests" => 0,
                    "pushed_authorization_request_endpoint" => "http://localhost:2007/realms/master/protocol/openid-connect/ext/par/request",
                    "mtls_endpoint_aliases" => {
                        "token_endpoint" => "http://localhost:2007/realms/master/protocol/openid-connect/token",
                        "revocation_endpoint" => "http://localhost:2007/realms/master/protocol/openid-connect/revoke",
                        "introspection_endpoint" => "http://localhost:2007/realms/master/protocol/openid-connect/token/introspect",
                        "device_authorization_endpoint" => "http://localhost:2007/realms/master/protocol/openid-connect/auth/device",
                        "registration_endpoint" => "http://localhost:2007/realms/master/clients-registrations/openid-connect",
                        "userinfo_endpoint" => "http://localhost:2007/realms/master/protocol/openid-connect/userinfo",
                        "pushed_authorization_request_endpoint" => "http://localhost:2007/realms/master/protocol/openid-connect/ext/par/request",
                        "backchannel_authentication_endpoint" => "http://localhost:2007/realms/master/protocol/openid-connect/ext/ciba/auth"
                    },
                    "authorization_response_iss_parameter_supported" => 1
                };

                return [ 
                    200, 
                    ["Content-Type" => 'application/json'], 
                    [ encode_json($Data) ] 
                ];
            }
            elsif( $req->path() eq '/realms/master/protocol/openid-connect/certs') {

                # this is the jwks url endpoint, here we return the magic key data
                my $Data = {

                    "keys" => [
                        {
                            "kid" => $KidID,
                            "kty" => $KidData->{kty},
                            "alg" => "RS256",
                            "use" => "sig",
                            "n"   => $KidData->{n},
                            "e"   => $KidData->{e},
                        }
                    ]
                };

                return [ 
                    200, 
                    ["Content-Type" => 'application/json'], 
                    [ encode_json($Data) ] 
                ];
            }

            return [ 
                404, 
                [], 
                [ "Not Found!" ] 
            ];

        };

        my $Runner = Plack::Runner->new;
        $Runner->parse_options(qw'--no-default-middleware --host 127.0.0.1 --port 2007 -L Shotgun');
        $Runner->run($App);
    }
    catch {
        print STDERR $_. "\n";
        exit 1;
    };
    exit 0;
}

#################################################################
# main test
#################################################################

# wait for the fake authorization server to come up
sleep 1;

# the OpenIDConfig we will use. This would normally come from SysConfig

my $OpenIDConfig = {
    'ClientSettings' => {
        'ClientSecret' => '12345678987654321',
        'ClientID' => 'otobo',
        'RedirectURI' => 'http://localhost/otobo/index.pl?Action=Login',
    },
    'ProviderSettings' => {
        'TTL' => 1800,
        'OpenIDConfiguration' => 'http://localhost:2007/realms/master/.well-known/openid-configuration',
        'Name' => 'UnitTest',
        'SSLOptions' => {
            'SSLVerifyMode' => 0,
            'SSLVerifyHostname' => 0,
        },
    },
};

# make sure cache is clean for testing

my $OIDCConfigurationObject = $Kernel::OM->Get('Kernel::System::OpenIDConnect::Configuration');
$OIDCConfigurationObject->GetProviderData(
    OpenIDConfig => $OpenIDConfig,
    NoCache => 1,
);

# create a JWT to test, sign using our private RSA key from above

my $CurrentTime = $Kernel::OM->Create('Kernel::System::DateTime')->ToEpoch();

my $Payload = {
  "exp"                => $CurrentTime+600,
  "iat"                => $CurrentTime,
  "jti"                => "29a2f4ba-6bfa-457b-afa1-469e6f4dc2c0",
  "iss"                => "http://localhost:2007/realms/master",
  "aud"                => [
    "otobo",
    "account"
  ],
  "sub"                => "9c3e1839-b468-4cda-a39a-d969ead45a40",
  "typ"                => "Bearer",
  "azp"                => "otobo",
  "sid"                => "bac62d82-40f7-455c-9f3f-8e0316e61f5b",
  "acr"                => "1",
  "scope"              => "openid email profile roles",
  "email_verified"     => 1,
  "name"               => "testy 1 tester 1",
  "preferred_username" => 'test1@example.com',
  "given_name"         => "testy 1",
  "family_name"        => "tester 1",
  "email"              => 'test1@example.com'
};

my $Token = encode_jwt(
    payload       => $Payload, 
    alg           =>'RS256', 
    key           => $PrivateKey,
    extra_headers => { kid => $KidID },    
);


# now validate this token, which will talk to our fake authorization server
# and fetch the public key to validate the signature

my $TokenObject = $Kernel::OM->Get('Kernel::System::OpenIDConnect::Token');

my $Result = $TokenObject->Validate(
    Token        => $Token,
    OpenIDConfig => $OpenIDConfig,
);

# that was a lot of work for a single assertion :)
ok($Result->{Success});
done_testing;

# tear down fake server
kill( 'TERM', $ChildPID );
waitpid( $ChildPID, 0 );
