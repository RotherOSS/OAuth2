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

package Kernel::System::OpenIDConnect::Token;

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

Kernel::System::OpenIDConnect::Token

Inspect and Validate OAuth2 Tokens

=head1 SYNOPSIS

OAuth2 Tokens for OpenID Connect

create an object

    use Kernel::System::ObjectManager;
    local $Kernel::OM = Kernel::System::ObjectManager->new();
    my $TokenObject = $Kernel::OM->Get('Kernel::System::OpenIDConnect::Token');

=cut

sub new {
    my ( $Type, %Param ) = @_;

    # allocate new hash for object
    my $Self = {};
    bless( $Self, $Type );

    return $Self;
}

=head2 Inspect()

	Inspect Token payload without validating the signature.

    my $TokenData = $TokenObject->Inspect( Token => $Token );

=cut

sub Inspect {
    my ( $Self, %Param ) = @_;

    for my $Needed (qw/Token/) {
        if ( !$Param{$Needed} ) {
            $Kernel::OM->Get('Kernel::System::Log')->Log(
                Priority => 'error',
                Message  => "Need $Needed!",
            );

            return;
        }
    }

    my $TokenData;
    eval {
        $TokenData = decode_jwt(
            token            => $Param{Token},
            ignore_signature => 1
        );
    };
    if ($@) {
        return;
    }

    return $TokenData;
}


=head2 sub IsTokenStillValid()

    Return true if a Token is still valid

    my $Boolean = $TokenObject->IsTokenStillValid( Token => $Token );

=cut

sub IsTokenStillValid {
    my ( $Self, %Param ) = @_;

    for my $Needed (qw/Token/) {
        if ( !$Param{$Needed} ) {
            $Kernel::OM->Get('Kernel::System::Log')->Log(
                Priority => 'error',
                Message  => "Need $Needed!",
            );

            return;
        }
    }

    my $MinTimeTillExpired = $Param{MinTimeTillExpired} || 30;
    my $Token              = $Param{Token};

    my $TimeLeft = $Self->TimeLeft(
        Token => $Token,
    );

    if ( $TimeLeft > $MinTimeTillExpired ) {
        return $Token if $TimeLeft > $MinTimeTillExpired;
    }

    return;
}

=head2 TimeLeft()

Returns the time in seconds a token is still valid

    my $TimeLeft = $TokenProviderObject->TimeLeft(
        Token          => $Token,
    );

=cut

sub TimeLeft {
    my ( $Self, %Param ) = @_;

    for my $Needed (qw/Token/) {
        if ( !$Param{$Needed} ) {
            $Kernel::OM->Get('Kernel::System::Log')->Log(
                Priority => 'error',
                Message  => "Need $Needed!",
            );
            return;
        }
    }

    my $TokenData = $Self->Inspect( %Param );
    if (!$TokenData) {
        return 0;
    }

    if ( !$TokenData->{exp} ) {
        $Kernel::OM->Get('Kernel::System::Log')->Log(
            Priority => 'error',
            Message  => "No expiration time found in provided token!",
        );
        return;
    }

    # time window
    my $CurrentTime = $Kernel::OM->Create('Kernel::System::DateTime')->ToEpoch();

    return $TokenData->{exp} - $CurrentTime;
}

=head2 Validate()

	Validates a Token

    my $Result = $TokenObject->Validate(
        Token          => $Token,
		OpenIDConfig   => $OpenIDConfig,
    );

	returns

	{ Success => 0 }

	or

	{ Success => 1, TokenData => {...} }

=cut

sub Validate {
    my ( $Self, %Param ) = @_;

    my $Return    = { Success => 0 };
    for my $Needed (qw/Token OpenIDConfig/) {
        if ( !$Param{$Needed} ) {
            $Kernel::OM->Get('Kernel::System::Log')->Log(
                Priority => 'error',
                Message  => "Need $Needed!",
            );

            return $Return;
        }
    }


	my $OpenIDConfig         = $Param{OpenIDConfig};
	my $ClientSettings       = $OpenIDConfig->{ClientSettings};
	my $ExpectedAudience     = $Param{ExpectedAudience};
	my $AuthorizedParty      = $Param{AuthorizedParty};    

    my $TokenData = $Self->DecodeToken(%Param);

    return $Return if !$TokenData;

    for my $Needed (qw/iss sub aud exp iat/) {
        if ( !$TokenData->{$Needed} ) {
            $Kernel::OM->Get('Kernel::System::Log')->Log(
                Priority => 'error',
                Message  => "Token invalid: <$Needed> not included.",
            );

            return $Return;
        }
    }

	my $OIDCConfigurationObject = $Kernel::OM->Get('Kernel::System::OpenIDConnect::Configuration');
	my $OpenIDProviderData = $OIDCConfigurationObject->GetProviderData(
		OpenIDConfig => $OpenIDConfig,
	);

    my $Issuer = $OpenIDProviderData->{OpenIDConfiguration}{issuer};

    # do the validation
    if ( $TokenData->{iss} ne $Issuer ) {
        $Kernel::OM->Get('Kernel::System::Log')->Log(
            Priority => 'error',
            Message  => "<iss> wrong. IDToken is issued by '$TokenData->{iss}', but '$Issuer' is required.",
        );

        return $Return;
    }

    my @Audience = ref $TokenData->{aud} ? @{ $TokenData->{aud} } : ( $TokenData->{aud} );

    if ( $ExpectedAudience ) {

        if ( !grep { $_ eq $ExpectedAudience } @Audience ) {
            $Kernel::OM->Get('Kernel::System::Log')->Log(
                Priority => 'error',
                Message  => "<aud> wrong. IDToken is addressed to '@Audience' which does not contain '$ClientSettings->{ClientID}'.",
            );

            return $Return;
        }
    }

    if ( ref $TokenData->{aud} && !$TokenData->{azp} ) {
        $Kernel::OM->Get('Kernel::System::Log')->Log(
            Priority => 'error',
            Message  => "<aud> is an array but <azp> not present.",
        );

        return $Return;
    }

    if ( $AuthorizedParty && $TokenData->{azp} && $AuthorizedParty !~ $TokenData->{azp} ) {
        $Kernel::OM->Get('Kernel::System::Log')->Log(
            Priority => 'error',
            Message  => "<azp> present and wrong. Authorized party is specified as '$TokenData->{azp}', we are '$ClientSettings->{ClientID}'.",
        );

        return $Return;
    }

    my $CurrentTime = $Kernel::OM->Create('Kernel::System::DateTime')->ToEpoch();
    my $Leeway      = int( $Param{Leeway} // 2 );

    if ( $TokenData->{iat} - $Leeway > $CurrentTime ) {
        $Kernel::OM->Get('Kernel::System::Log')->Log(
            Priority => 'error',
            Message  => "<iat> invalid. IDToken creation time is in the future. Token: $TokenData->{iat}; Current: $CurrentTime;",
        );

        return $Return;
    }

    if ( $TokenData->{exp} + $Leeway <= $CurrentTime ) {
        $Kernel::OM->Get('Kernel::System::Log')->Log(
            Priority => 'error',
            Message  => "<exp> invalid. IDToken expired. Expiration Time: $TokenData->{exp}; Current: $CurrentTime;",
        );
        $Return->{Error} = 'exp';

        return $Return;
    }

    if ( $Param{UseNonce} ) {
        if ( !$TokenData->{nonce} ) {
            $Kernel::OM->Get('Kernel::System::Log')->Log(
                Priority => 'error',
                Message  => "No nonce in Token.",
            );

            return $Return;
        }

        my $CacheObject = $Kernel::OM->Get('Kernel::System::Cache');
        my %Nonce       = (
            Type => 'OpenIDConnect_Nonce',
            Key  => $TokenData->{nonce},
        );

        if ( $CacheObject->Get(%Nonce) ) {
            $CacheObject->Delete(%Nonce);
        }
        else {
            $Kernel::OM->Get('Kernel::System::Log')->Log(
                Priority => 'notice',
                Message  => "<nonce> invalid.",
            );
            $Return->{Error} = 'nonce';

            return $Return;
        }
    }

    return {
        Success   => 1,
        TokenData => $TokenData,
    };
}

=head2 DecodeToken()

Returns the decoded token

    my $TokenData = $TokenObject->DecodeToken(
        Token          => $Token,
		OpenIDConfig   => $OpenIDConfig,
    );

=cut

sub DecodeToken {
    my ( $Self, %Param ) = @_;

    for my $Needed (qw/Token OpenIDConfig/) {
        if ( !$Param{$Needed} ) {
            $Kernel::OM->Get('Kernel::System::Log')->Log(
                Priority => 'error',
                Message  => "Need $Needed!",
            );
            return;
        }
    }

	my $OIDCConfigurationObject = $Kernel::OM->Get('Kernel::System::OpenIDConnect::Configuration');
	my $OpenIDProviderData = $OIDCConfigurationObject->GetProviderData(
		OpenIDConfig => $Param{OpenIDConfig},
	);

    # get the OpenIDConfiguration and Keys
    my $Try                = 0;

    # decode the token; retry once if it doesn't work for cached config
    my $TokenData;
    while ( $Try++ < 2 ) {

        # decode id_token, check key
        $TokenData = decode_jwt(
            token    => $Param{Token},
            kid_keys => $OpenIDProviderData->{KeyData},
        ) // {};

        # check whether the issuer is correct - if not the cached data might just be outdated
        if ( $TokenData->{iss} && $TokenData->{iss} eq $OpenIDProviderData->{OpenIDConfiguration}{issuer} ) {
            $Try = 100;
        }
        elsif ( $Try < 2 ) {
            $Kernel::OM->Get('Kernel::System::Log')->Log(
                Priority => 'notice',
                Message  => "Cached IDToken wrong; retrying once.",
            );

			$OpenIDProviderData = $OIDCConfigurationObject->GetProviderData(
				OpenIDConfig => $Param{OpenIDConfig},
				NoCache => 1,
			);
        }
    }

    return $TokenData if $TokenData;

    $Kernel::OM->Get('Kernel::System::Log')->Log(
        Priority => 'error',
        Message  => 'Failed to decode id_token!',
    );

    return;
}

1;
