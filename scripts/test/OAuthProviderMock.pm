#################################################################
# OAuth Provider Mock Server
#################################################################

my $CurrentTime = $Kernel::OM->Create('Kernel::System::DateTime')->ToEpoch();

#################################################################
# prepare shared RSA key
#################################################################

$main::PrivateKey = Crypt::PK::RSA->new();
$main::PrivateKey->generate_key(256, 65537);

# prepare kid data to be served from fake authorization server
my $KidData       = decode_json($main::PrivateKey->export_key_jwk('public'));
my $KidThumbprint = $main::PrivateKey->export_key_jwk_thumbprint();
$main::KidID      = '2QqRmKFkfpBHoO4cj-yVfrHJykIBLOMbbe7qBvU5Unk';

# helper to get an OpenIDConfig
sub GetTestOpenIDConfig {

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
    return $OpenIDConfig;    
}

# helper for creating test JWT payloads
sub Payload {

    my %Param = @_;

    my $Scope = $Param{Scope} || "openid email profile roles";
    my $Audience = $Param{Audience} || [
            "otobo",
            "account"
    ];

    return {
        "exp"                => $CurrentTime+600,
        "iat"                => $CurrentTime,
        #  "jti"                => "29a2f4ba-6bfa-457b-afa1-469e6f4dc2c0",
        "iss"                => "http://localhost:2007/realms/master",
        "aud"                => $Audience,
        "sub"                => "9c3e1839-b468-4cda-a39a-d969ead45a40",
        "typ"                => "Bearer",
        "azp"                => "otobo",
        #  "sid"                => "bac62d82-40f7-455c-9f3f-8e0316e61f5b",
        "acr"                => "1",
        "scope"              => $Scope,
        "email_verified"     => 1,
        "name"               => "testy 1 tester 1",
        "preferred_username" => 'test1@example.com',
        "given_name"         => "testy 1",
        "family_name"        => "tester 1",
        "email"              => 'test1@example.com'
    };
}



sub AssertHttpCallLog {

    my %Param = @_;

    my $Expected = $Param{Expected};

    my $ua = LWP::UserAgent->new(timeout => 10);
    my $response = $ua->get('http://localhost:2007/realms/master/protocol/openid-connect/log');
    if ($response->is_success) {

        my $Log = decode_json($response->decoded_content);

        ok(scalar @$Log == scalar @$Expected, "number of logged calls matches expected (".(scalar @$Log). " == ".(scalar @$Expected).").");

        my $Index = 0;
        foreach my $Expectation ( @$Expected ) {

            my $Actual = $Log->[$Index];
            my $ExpectedContent = $Expectation->{content};
            my $Op = $Expectation->{operator} || 'equal';

            ok( $Actual->{endpoint} eq $Expectation->{endpoint},  $Actual->{endpoint} ." equals ". $Expectation->{endpoint});
            if($Op eq 'match') {
                my $Regex  = qr/$ExpectedContent/;
                ok( $Actual->{content} =~ $Regex, $Actual->{content}.' matches '.$ExpectedContent);
            }
            else {
                ok( $Actual->{content} eq $ExpectedContent, $Actual->{content}.' equals '.$ExpectedContent);
            }
            $Index++;
        }
    }
}

#################################################################
# start test authorization server
#################################################################

$main::ChildPID = fork();

if ( !$main::ChildPID ) {

    # i am the forked child
    # run the test server

    try {

        my @Log;
        my $App = sub {

            my $env = shift; # PSGI env
            my $req = Plack::Request->new($env);

            # print STDERR "\n-------------------------------------------->\n";
            # print STDERR $req->path()."\n";
            # print STDERR $req->content()."\n";
            # print STDERR Dumper($req->headers())."\n";

            if($req->path() eq '/realms/master/.well-known/openid-configuration') {

                push @Log, {
                    'endpoint' => 'openid',
                    'content'  => '',
                };

                # the test fixture from hell
                # recorded from conversations with keycloak
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

                push @Log, {
                    'endpoint' => 'jwks',
                    'content'  => '',
                };

                # this is the jwks url endpoint, here we return the magic key data
                my $Data = {

                    "keys" => [
                        {
                            "kid" => $main::KidID,
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
            elsif( $req->path() eq '/realms/master/protocol/openid-connect/token') {
 
                # this is the token endpoint, generate a fresh JWT token and return it
                my $Params = $req->parameters();
                my $Scope = $Params->{scope}; # always return JWT with scopes as requested

                push @Log, {
                    'endpoint' => 'token',
                    'content'  => $req->content(),
                };

                # validate credentials - this expects client_credentials flow so basic auth
                # has client_id and client_secret from GetTestOpenIDConfig() in the Base64
                if($req->headers()->{authorization} ne 'Basic b3RvYm86MTIzNDU2Nzg5ODc2NTQzMjE=') {

                    return [ 
                        401, 
                        [], 
                        [] 
                    ];
                }

                my $AccessTokenPayload = Payload();
                $AccessTokenPayload->{scope} = $Scope;

                my $AccessToken = encode_jwt(
                    payload       => $AccessTokenPayload, 
                    alg           =>'RS256', 
                    key           => $main::PrivateKey,
                    extra_headers => { kid => $main::KidID },    
                );

                my $IDTokenPayload = Payload();
                $IDTokenPayload->{typ} = 'ID';
                $IDTokenPayload->{scope} = $Scope;

                my $IDToken = encode_jwt(
                    payload       => $IDTokenPayload, 
                    alg           =>'RS256', 
                    key           => $main::PrivateKey,
                    extra_headers => { kid => $main::KidID },    
                );

                my $Data = {
                    access_token  => $AccessToken,
                    id_token      => $IDToken,
                    refresh_token => $AccessToken,
                };

                return [ 
                    200, 
                    ["Content-Type" => 'application/json'], 
                    [ encode_json($Data) ] 
                ];
            }
            elsif( $req->path() eq '/realms/master/protocol/openid-connect/log') {

                my $Json = encode_json(\@Log);
                @Log = (); # reset log

                return [ 
                    200, 
                    ["Content-Type" => 'application/json'], 
                    [ $Json ] 
                ];
            }

            return [ 
                404, 
                [], 
                [ "Not Found!" ] 
            ];
        };

        my $Runner = Plack::Runner->new;
        $Runner->parse_options(qw'--no-default-middleware --host 127.0.0.1 --port 2007');
        $Runner->run($App);
    }
    catch {
        print STDERR $_. "\n";
        exit 1;
    };
    exit 0;
}

1;
