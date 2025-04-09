# --
# OTOBO is a web-based ticketing system for service organisations.
# --
# Copyright (C) 2019–2021 Efflux GmbH, https://efflux.de/
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

package Kernel::Language::en_OAuth2;

use strict;
use warnings;
use utf8;

sub Data {
    my $Self = shift;

    # AdminOAuthTokenSTore.pm
    $Self->{Translation}->{'Account Name is missing!'} = 'Account Name is missing!';
    $Self->{Translation}->{'Username is required!'} = 'Username is required!';
    $Self->{Translation}->{'Password is required!'} = 'Password is required!';
    $Self->{Translation}->{'Account Name is taken!'} = 'Account Name is taken!';
    $Self->{Translation}->{'Error creating/updating %s!'} = 'Error creating/updating %s!';
    $Self->{Translation}->{'Unable to generate OIDC Provider Authentication URL for Login. Invalid OICD Configuration!'} = 'Unable to generate OIDC Provider Authentication URL for Login. Invalid OICD Configuration!';
    $Self->{Translation}->{'Account %s deleted!'} = 'Account %s deleted!';
    $Self->{Translation}->{'Token %s updated!'} = 'Token %s updated!';
    $Self->{Translation}->{'Invalid OAuth State!'} = 'Invalid OAuth State!';
    $Self->{Translation}->{'Invalid Account %s for Token!"'} = 'Invalid Account %s for Token!"';
    $Self->{Translation}->{'Invalid Issuer %s for Token %s!'} = 'Invalid Issuer %s for Token %s!';
    $Self->{Translation}->{'Error fetching initial Token for %s!'} = 'Error fetching initial Token for %s!';

    # TokenProvider.pm
    $Self->{Translation}->{'AccountID %s not found!'} = 'AccountID %s not found!';
    $Self->{Translation}->{'No valid refresh_token for Account %s using grant_tpye \'authorization code\' !'} = 'No valid refresh_token for Account %s using grant_tpye \'authorization code\' !';
    $Self->{Translation}->{'Need functional account Invoker settings in SysConfig for %s.'} = 'Need functional account Invoker settings in SysConfig for %s.';
    $Self->{Translation}->{'Could not get the OAuth2 token_endpoint for Invoker %s.'} = 'Could not get the OAuth2 token_endpoint for Invoker %s.';
    $Self->{Translation}->{'Error fetching Token for Invoker %s: %s'} = 'Error fetching Token for Invoker %s: %s';
    $Self->{Translation}->{'Did not receive the desired TokenType \'%s\' in OIDC provider response for Invoker %s!'} = 'Did not receive the desired TokenType \'%s\' in OIDC provider response for Invoker %s!';
    $Self->{Translation}->{'Time left on fresh token is: %s s for Invoker %s!'} = 'Time left on fresh token is: %s s for Invoker %s!';
    $Self->{Translation}->{'Need ClientID and ClientSecret!'} = 'Need ClientID and ClientSecret!';
    $Self->{Translation}->{'Got no content when requesting Token. Response Code: %s'} = 'Got no content when requesting Token. Response Code: %s';
    $Self->{Translation}->{'Got no JSON object when requesting Token. Response: %s'} = 'Got no JSON object when requesting Token. Response: %s';
    $Self->{Translation}->{'Error: %s. Description: %s'} = 'Error: %s. Description: %s';
    $Self->{Translation}->{'Profiles'} = 'Profile';

    # K/GI/O/S/Common.pm
    $Self->{Translation}->{'OpenID Connect Config is Invalid.'} = 'OpenID Connect Config is Invalid.';
    $Self->{Translation}->{'Invalid OpenID Connect Config - missing $Needed.'} = 'Invalid OpenID Connect Config - missing %s.';
    $Self->{Translation}->{'Token invalid: claim %s not included.'} = 'Token invalid: claim %s not included.';
    $Self->{Translation}->{'<iat> claim invalid. Token creation time is in the future. Token: %s; Current: $%s;'} = '<iat> claim invalid. Token creation time is in the future. Token: %s; Current: $%s;';
    $Self->{Translation}->{'<exp> invalid. Token expired. Expiration Time: %s; Current: %s;'} = '<exp> invalid. Token expired. Expiration Time: %s; Current: %s;';

    # K/GI/T/H/REST.pm

    $Self->{Translation}->{'Error fetching the OAuth2 Token'} = 'Error fetching the OAuth2 Token';
    $Self->{Translation}->{'Attached OAuth2 Bearer Token'} = 'Attached OAuth2 Bearer Token';

    # AdminOAuthTokenStore.tt

    $Self->{Translation}->{'OAuth2 Token Management (OIDC)'} = 'OAuth2 Token Management (OIDC)';
    $Self->{Translation}->{'OpenID Connect Functional OAuht2 Account Management'} = 'OpenID Connect Functional OAuh2 Account Management';
    $Self->{Translation}->{'Add Account'} = 'Add Account';
    $Self->{Translation}->{'Edit Account '} = 'Edit Account ';
    $Self->{Translation}->{'About OIDC Functional Accounts'} = 'About OIDC Functional Accounts';
    $Self->{Translation}->{'This page displays an overview of configured functional OAuth Accounts and their corresponding Token Status.'} = 'This page displays an overview of configured functional OAuth Accounts and their corresponding Token Status.';
    $Self->{Translation}->{'You can test your Configuration with a click on the \'Refresh\' Button, which will try to fetch or refresh a new Token.'} = 'You can test your Configuration with a click on the \'Refresh\' Button, which will try to fetch or refresh a new Token.';
#    $Self->{Translation}->{'Add'} = 'Add';
    $Self->{Translation}->{'Delete Account'} = 'Delete Account';
    $Self->{Translation}->{'OAuth2 Token backed Accounts'} = 'OAuth2 Token backed Accounts';
#    $Self->{Translation}->{'total'} = 'total';
    $Self->{Translation}->{'There are no OAuth2 accounts defined.'} = 'There are no OAuth2 accounts defined.';
#    $Self->{Translation}->{'Account Name'} = 'Account Name';
#    $Self->{Translation}->{'Flow'} = 'Flow';
    $Self->{Translation}->{'Has Token?'} = 'Has Token?';
    $Self->{Translation}->{'Refresh Token Expires'} = 'Refresh Token Expires';
    $Self->{Translation}->{'Renew Token'} = 'Renew Token';
#    $Self->{Translation}->{'Refresh'} = 'Refresh';
#    $Self->{Translation}->{'No matches found.'} = 'No matches found.';
    $Self->{Translation}->{'Add Invoker Account'} = 'Add Invoker Account';
    $Self->{Translation}->{'Edit Invoker Account'} = 'Edit Invoker Account';
    $Self->{Translation}->{'The unique name for this Account.'} = 'The unique name for this Account.';
    $Self->{Translation}->{'The OpenID Connect Provider to use for this functional account.'} = 'The OpenID Connect Provider to use for this functional account.';
    $Self->{Translation}->{'The OAuth2 grant_type to use for acquiring tokens for this account.'} = 'The OAuth2 grant_type to use for acquiring tokens for this account.';
    $Self->{Translation}->{"Selecting 'authorization_code' will redirect you to your OpenID Connect Provider's Login Page to validate your account once you click 'Save'."} = "Selecting 'authorization_code' will redirect you to your OpenID Connect Provider's Login Page to validate your account once you click 'Save'.";
    $Self->{Translation}->{'OIDC Profile'} = 'OIDC Profile';
    $Self->{Translation}->{'Grant Type'} = 'Grant Type';
#    $Self->{Translation}->{'Username'} = 'Username';
    $Self->{Translation}->{'The username if grant type is \'password.\'.'} = 'The username if grant type is \'password\'.';
    $Self->{Translation}->{'The password to use if grant type is \'password\'.'} = 'The password to use if grant type is \'password\'.';

#    $Self->{Translation}->{'Password'} = 'Password';
    $Self->{Translation}->{'OAuth2 Scopes'} = 'OAuth2 Scopes';
    $Self->{Translation}->{'Space separate list of OAuth2 scopes to use. Usual values include openid, email, profile, and roles.'} = 'Space separate list of OAuth2 scopes to use. Usual values include openid, email, profile, and roles.';
    $Self->{Translation}->{'Advanced Invoker Settings'} = 'Advanced Invoker Settings';
    $Self->{Translation}->{'Resources'} = 'Resources';
    $Self->{Translation}->{'Optional (space seperated list) for the resource paramater if required. Leave empty unless instructed otherwise.'} = 'Optional (space seperated list) for the resource paramater if required. Leave empty unless instructed otherwise.';
    $Self->{Translation}->{'Resource Parameter Name'} = 'Resource Parameter Name';
    $Self->{Translation}->{'Name of the resource parameter to use. Defaults to \'resource\'. Do not change unless instructed.'} = 'Name of the resource parameter to use. Defaults to \'resource\'. Do not change unless instructed.';
    $Self->{Translation}->{'Token Type'} = 'Token Type';
    $Self->{Translation}->{'The token type to use for externall API calls. Usually \'access_token\'.'} = 'The token type to use for externall API calls. Usually \'access_token\'.';

    # AdminGenericInterfaceTransportHTTPREST.tt
    $Self->{Translation}->{'OAuth2 Functional Account'} = 'OAuth2 Functional Account';
    $Self->{Translation}->{'Select the'} = 'Select the';
    $Self->{Translation}->{'Account to use for OAuth2 authentication.'} = 'Account to use for OAuth2 authentication.';
}

1;
