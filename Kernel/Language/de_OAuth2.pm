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

package Kernel::Language::de_OAuth2;

use strict;
use warnings;
use utf8;

sub Data {
    my $Self = shift;

    # AdminOAuthTokenStore.pm
    $Self->{Translation}->{'Account Name is missing!'} = 'Konto Name ist erforderlich!';
    $Self->{Translation}->{'Username is required!'} = 'Username ist erforderlich!';
    $Self->{Translation}->{'Password is required!'} = 'Password ist erforderlich!';
    $Self->{Translation}->{'Account Name is taken!'} = 'Konto Name ist bereits vergeben!';
    $Self->{Translation}->{'Error creating/updating %s!'} = 'Fehler beim Erstellen/Aktualisieren von %s!';
    $Self->{Translation}->{'Unable to generate OIDC Provider Authentication URL for Login. Invalid OICD Configuration!'} = 'Der OIDC Provider Authentication URL zum Login konnte nicht generiert werden. Invalide OICD Konfiguration!';
    $Self->{Translation}->{'Account %s deleted!'} = 'Konto %s gelöscht!';
    $Self->{Translation}->{'Token %s updated!'} = 'Token %s aktualisiert!';
    $Self->{Translation}->{'Invalid OAuth State!'} = 'Invalider OAuth State!';
    $Self->{Translation}->{'Invalid Account %s for Token!"'} = 'Invalides Konto %s für Token!"';
    $Self->{Translation}->{'Invalid Issuer %s for Token %s!'} = 'Invalider Issuer %s für Token %s!';
    $Self->{Translation}->{'Error fetching initial Token for %s!'} = 'Fehler beim bereitstellen des initialen Tokens für %s!';

    # TokenProvider.pm
    $Self->{Translation}->{'AccountID %s not found!'} = 'Konto mit ID %s nicht gefunden!';
    $Self->{Translation}->{'No valid refresh_token for Account %s using grant_tpye \'authorization code\' !'} = 'Es exisitier kein valides refresh_token für das Konto %s und grant_tpye \'authorization code\' !';
    $Self->{Translation}->{'Need functional account Invoker settings in SysConfig for %s.'} = 'Fehlende Einstellungen für das funktionale Konto %s in der System Konfiguration.';
    $Self->{Translation}->{'Could not get the OAuth2 token_endpoint for Invoker.'} = 'Der OAuth2 token_endpoint konnte nicht bereit gestellt werden.';
    $Self->{Translation}->{'Error fetching Token for Invoker: %s'} = 'Fehler beim Abholen des OAuth2 Token for Invoker: %s';
    $Self->{Translation}->{'Did not receive the desired TokenType \'%s\' in OIDC provider response for Invoker %s!'} = 'Der erwartete Token Typ \'%s\' für %s war in der OIDC Provider Antwort nicht enthalten!';
    $Self->{Translation}->{'Time left on fresh token is: %s s for Invoker %s!'} = 'Verbleibende Zeit für aktuelles Token ist: %s s für Invoker %s!';
    $Self->{Translation}->{'Need ClientID and ClientSecret!'} = 'ClientID and ClientSecret fehlen in der OIDC Profil Konfiguration!';
    $Self->{Translation}->{'Got no content when requesting Token. Response Code: %s'} = 'Leere Antwort in der Token Anfrage. Response Code: %s';
    $Self->{Translation}->{'Got no JSON object when requesting Token. Response: %s'} = 'Die Antwort in der Token Abrage enthielt kein JSON Objekt. Response: %s';
    $Self->{Translation}->{'Error: %s. Description: %s'} = 'Fehler: %s. Beschreibung: %s';

    # K/GI/O/S/Common.pm
    $Self->{Translation}->{'OpenID Connect Config is Invalid.'} = 'OpenID Connect Konfiguration ist invalid.';
    $Self->{Translation}->{'Invalid OpenID Connect Config - missing $Needed.'} = 'Invalide OpenID Connect Konfiguration - es fehlt %s.';
    $Self->{Translation}->{'Token invalid: claim %s not included.'} = 'Token invalid: claim %s nicht enthalten.';
    $Self->{Translation}->{'<iat> claim invalid. Token creation time is in the future. Token: %s; Current: $%s;'} = '<iat> claim invalid. Erstellungszeit des Tokens ist in der Zukunft. Token: %s; Jetzt: $%s;';
    $Self->{Translation}->{'<exp> invalid. Token expired. Expiration Time: %s; Current: %s;'} = '<exp> invalid. Token abgelaufen. Ablaufzeitpunkt: %s; Jetzt: %s;';

    # K/GI/T/H/REST.pm

    $Self->{Translation}->{'Error fetching the OAuth2 Token'} = 'Fehler beim Abholen des OAuth2 Token';
    $Self->{Translation}->{'Attached OAuth2 Bearer Token'} = 'OAuth2 Bearer Token hinzugefügt';

    # AdminOAuthTokenStore.tt

    $Self->{Translation}->{'OAuth2 Token Management (OIDC)'} = 'OAuth2 Token Management (OIDC)';
    $Self->{Translation}->{'OpenID Connect Functional OAuth2 Account Management'} = 'OpenID Connect Management für Funktionale Konten';
    $Self->{Translation}->{'Add Account'} = 'Konto hinzufühgen';
    $Self->{Translation}->{'Edit Account '} = 'Konto bearbeiten: ';
    $Self->{Translation}->{'About OIDC Functional Accounts'} = 'OIDC Funktionale Konten';
    $Self->{Translation}->{'This page displays an overview of configured functional OAuth Accounts and their corresponding Token Status.'} = 'Überblick über die konfigurierten funktioinalen OAuth2 Konten und deren aktuellem Token Status.';
    $Self->{Translation}->{"You can test your Configuration with a click on the 'Renew' Button, which will try to fetch or refresh a new Token."} = 'Mit einem Klick auf den \'Aktualisieren\' Button kann die jeweilige Konfiguratiuon überprüft werden.';
#    $Self->{Translation}->{'Add'} = 'Add';
    $Self->{Translation}->{'Delete Account'} = 'Konto Löschen';
    $Self->{Translation}->{'OAuth2 Token backed Accounts'} = 'OAuth2 Token basierende funktionale Konten';
#    $Self->{Translation}->{'total'} = 'total';
    $Self->{Translation}->{'There are no OAuth2 accounts defined.'} = 'Es sind noch keine funktionalen OAuth2 Konten definiert.';
    $Self->{Translation}->{'Account Name'} = 'Konto Name';
#    $Self->{Translation}->{'Flow'} = 'Flow';
    $Self->{Translation}->{'Has Token?'} = 'Token vorhanden?';
    $Self->{Translation}->{'Refresh Token Expires'} = 'Refresh Token Gültig bis';
    $Self->{Translation}->{'Renew Token'} = 'Aktualisiere Token';
    $Self->{Translation}->{'Renew'} = 'Aktualisieren';
#    $Self->{Translation}->{'No matches found.'} = 'No matches found.';
    $Self->{Translation}->{'Add Invoker Account'} = 'Invoker Konto hinzufügen';
    $Self->{Translation}->{'Edit Invoker Account'} = 'Invoker Konto bearbeiten';
    $Self->{Translation}->{'The unique name for this Account.'} = 'Der eindeutige Name für dieses Konto.';
    $Self->{Translation}->{'The OpenID Connect'} = 'Der OpenID Connect';
    $Self->{Translation}->{'to use for this functional account.'} = 'der für dieses funktionale Konto benutzt werden soll.';
    $Self->{Translation}->{'The OAuth2 grant_type to use for acquiring tokens for this account.'} = 'Der OAuth2 grant_type für dieses Konto.';
    $Self->{Translation}->{"Selecting 'authorization_code' will redirect you to your OpenID Connect Provider's Login Page to validate your account once you click 'Save'."} = "Die Auswahl von 'authorization_code' löst einen Brwoser Redirect zur Login Seite Ihres OIDC Providers.";
    $Self->{Translation}->{'OIDC Profile'} = 'OIDC Profil';
    $Self->{Translation}->{'Grant Type'} = 'Grant Type';
#    $Self->{Translation}->{'Username'} = 'Username';
    $Self->{Translation}->{'The username if grant type is \'password.\'.'} = 'Der Username bei grant type gleich \'password\'.';
    $Self->{Translation}->{'The password to use if grant type is \'password\'.'} = 'Das Passwort bei grant type gleich \'password\'.';

#    $Self->{Translation}->{'Password'} = 'Password';
    $Self->{Translation}->{'OAuth2 Scopes'} = 'OAuth2 Scopes';
    $Self->{Translation}->{'Space separate list of OAuth2 scopes to use. Usual values include openid, email, profile, and roles.'} = 'Leerzeichen getrennte Liste von OAuth2 scopes. Übliche Werte sind openid, email, profile, und roles.';
    $Self->{Translation}->{'Advanced Invoker Settings'} = 'Erweiterte Invoker Einstellungen';
    $Self->{Translation}->{'Resources'} = 'Resources';
    $Self->{Translation}->{'Optional (space seperated list) for the resource paramater if required. Leave empty unless instructed otherwise.'} = 'Optionale, Leerzeichen getrennte Liste für den Resource Paramater, sofern benötigt.';
    $Self->{Translation}->{'Resource Parameter Name'} = 'Resource Parameter Name';
    $Self->{Translation}->{'Name of the resource parameter to use. Defaults to \'resource\'. Do not change unless instructed.'} = 'Name des Resource Parameters. Voreingestellt ist \'resource\'. Ändern Sie diesen Wert nur auf Anfrage.';
    $Self->{Translation}->{'Token Type'} = 'Token Typ';
    $Self->{Translation}->{'The token type to use for externall API calls. Usually \'access_token\'.'} = 'Der Token Typ der für ausgehende WSebService Aufrufe verwendet werden soll. Üblicherweise \'access_token\'.';

    $Self->{Translation}->{"You can create OIDC Profiles to connect to your OIDC Functional Account"} = 'Um neue OIDC Profile zum Verknüpfen mit Functional Accounts zu erstellen, klicke';
    $Self->{Translation}->{"here"} = 'hier';
    $Self->{Translation}->{"Since you do not have any OIDC Provider profiles configured, you cannot add an OAuth2 Functional Account. Xou have to first configure at least one OIDC Provider profile"} = 'Da nock keine OIDC Profile hinterlegt sind, kann kein neuer Functional Account angelegt werden. Um ein neues OIDC Profil zu erstllen, klicke';
    $Self->{Translation}->{"Profile Name"} = 'Profil Name';

    # AdminOIDCProfiles.tt
    $Self->{Translation}->{"OpenID Connect Provider Profiles Management"} = 'OpenID Connect Provider Profil Management';
    $Self->{Translation}->{'Add Profile'} = 'Profil hinzufügen';
    $Self->{Translation}->{'Edit Profile'} = 'Profil bearbeiten';
    $Self->{Translation}->{"About OIDC Provider Profiles"} = "OIDC Provider Profile";
    $Self->{Translation}->{"This page displays an overview of configured OIDC Provider Profiles."} = 'Überblick über die konfigurierten OIDC Provider Profile.';
    $Self->{Translation}->{'You can connect OIDC Profiles with a OIDC Functional Account'} = 'Um OIDC Profile mit einem Funktionalen Account zu verknüpfen, klicke';
    $Self->{Translation}->{"Delete Profile"} = "Profil löschen";
    $Self->{Translation}->{'OpenID Connect Provider Profiles for outgoing Webservice calls (GenericInterface Invoker)'} = 'OpenID Connect Provider Profile für ausgehende Webservices (GenericInterface Invoker)';
    $Self->{Translation}->{'There are no OIDC Provider profiles defined.'} = 'Es sind keine OIDC Provider Profile definiert';
    $Self->{Translation}->{"Profile Name"} = 'Profil Name';
    $Self->{Translation}->{"Client ID"} = "Client ID";
    $Self->{Translation}->{"Provider"} = "Provider";
#    $Self->{Translation}->{"Valid"} = '';
    $Self->{Translation}->{"Add OIDC Provider Profile"} = 'OIDC Provider Profil hinzufügen';
    $Self->{Translation}->{"Edit OIDC Provider Profile"} = 'OIDC Provider Profil bearbeiten';
    $Self->{Translation}->{"Since you are using OIDC as Authentication module, these values have been pre-populated with the OIDC Provider Configuration used for Login."} = 'Da OIDC für den Login verwendet wird, wurden einige Parameter basierend auf ihrer OIDC Login Konfiguration vor-ausgefüllt.';
    $Self->{Translation}->{"The unique name for this Profile."} = 'Der eindeutige Name für dieses Profil.';
    $Self->{Translation}->{"Metadata Url."} = "Metadata Url.";
    $Self->{Translation}->{"The Well-Known Provider Metadata Url."} = "Der 'Well-Known' Provider Metadata Url.";
    $Self->{Translation}->{"The Client ID of your OAuth2 application."} = "Die 'Client ID' Ihrer OAuth2 Applikation.";
    $Self->{Translation}->{"The Client Secret of your OAuth2 application."} = "Das 'Client Secret' Ihrer OAuth2 Applikation.";
    $Self->{Translation}->{"Cache TTL"} = "Cache TTL";
    $Self->{Translation}->{"Time in seconds for caching provider data."} = 'Zeit in Sekunden für die Provider Daten gecached werden.';
    $Self->{Translation}->{"SSL Options (Optional)"} = "SSL Optionen (Optional)";
    $Self->{Translation}->{"SSL Certificate"} = "SSL Zertifikat";
    $Self->{Translation}->{"SSL certificate path."} = "SSL Zertifikat Pfad.";
    $Self->{Translation}->{"SSL Certificate Key"} = "SSL Zertifikat Schlüssel.";
    $Self->{Translation}->{"SSL certificate private key path."} = "Pfad zum SSL Zertifikat Schlüssel (private key).";
    $Self->{Translation}->{"SSL Password"} = "SSL Passwort";
    $Self->{Translation}->{"The SSL password."} = "Das SSL Passwort.";
    $Self->{Translation}->{"SSL CA File"} = "SSL CA Datei";
    $Self->{Translation}->{"SSL Certificate Authority file path."} = "Pfad zur SSL Zertifikats Authority Datei (CA).";
    $Self->{Translation}->{"SSL CA Directory"} = "SSL CA Verzeichnis";
    $Self->{Translation}->{"SSL Certificate Authority directory path."} = 'Pfad zum Verzechnis mit den SSL Zertifikats Authority Dateien.';
    $Self->{Translation}->{"SSL Verify Hostname"} = "SSL Verifizierung des Hostnames";
    $Self->{Translation}->{"Enable or disable SSL hostname verification. Only disable for debugging purposes!"} = 'Zum Testen oder zur Fehlersuche kann die Verifizierung von SSL Hostnamen deaktiviert werden.';
    $Self->{Translation}->{"SSL Verify Mode"} = 'SSL Verifizierungsmodus';
    $Self->{Translation}->{"Enable or disable SSL verification. Only disable for debugging purposes!"} = 'Zum Testen oder zur Fehlersuche kann die Verifizierung von SSL Zertifikaten deaktiviert werden.';
    $Self->{Translation}->{"Misc Options (Optional)"} = 'Erweiterte Optionen (Optional)';
    $Self->{Translation}->{"Use Nonce"} = 'Benutze Nonce';
    $Self->{Translation}->{"Do not use Nonce"} = 'Keine Nonce';
    $Self->{Translation}->{"Rand Length"} = 'Zufallszeichenfolgenlänge';
    $Self->{Translation}->{"Random string length used for state and nonce parameters. Default is '22'."} = "Zufallszeichenfolgenlänge benutz zum Erstellen von Nonce und State Zufallsfolgen. Der Default Wert ist '22'.";
    $Self->{Translation}->{"Rand TTL"} = 'Authentifizierungs-Timeout';
    $Self->{Translation}->{"Time-to-live for state and nonce in seconds. Default is '300' (5 min)."} = "Lebensdauer für State und Nonce Zufallswerte beim Login. Der Default is '300' (5 Min).";
    $Self->{Translation}->{'Leeway'} = 'Spielraum';
    $Self->{Translation}->{"Time drift allowance between servers to be allowed. Default '2' seconds."} = 'Tolerierte Zeitabweichung beim Abgleich von Zeitstempeln von versiedenen Servern. Der Default Wert ist 2s.';
    $Self->{Translation}->{"Skip"} = 'Deaktivieren';
    $Self->{Translation}->{"Verify Hostname"} = 'Aktivieren';
    $Self->{Translation}->{"Verify Certificates"} = 'Aktivieren';
    $Self->{Translation}->{"Profile %s could not be deleted - do you have any Functional Accounts referencing this Profile?"} = "Profil %s konnte nicht gelöscht werden. Sind noch Funktionale Accounts konfiguriert, die dieses Profil verwenden?";
    $Self->{Translation}->{"Profile %s deleted!"} = "Profil %s gelöscht.";
    $Self->{Translation}->{"Error creating/updating Profile %s!"} = "Fehler beim Erstellen/Bearbeiten des Profils %s.";

    # AdminOIDCProfiles.pm
    $Self->{Translation}->{'Profile Name is missing!'} = 'Profil Name fehlt.';
    $Self->{Translation}->{'Provider metadata url is missing'} = 'Der URL zu den Provider Metadaten fehlt.';
    $Self->{Translation}->{'Provider client id is missing!'} = 'Die Client ID fehlt.';
    $Self->{Translation}->{'Provider client secret is missing!'} = 'Das Client Secret fehtl.';
    $Self->{Translation}->{'Profile Name is taken!'} = 'Der Profil Name ist bereits vergeben.';

    # AdminGenericInterfaceTransportHTTPREST.tt
    $Self->{Translation}->{'OAuth2 Functional Account'} = 'OAuth2 Konto';
    $Self->{Translation}->{'Select the'} = 'Auswahl des';
    $Self->{Translation}->{'Account to use for OAuth2 authentication.'} = 'Kontos für die OAuth2 Authentifizierung.';
    $Self->{Translation}->{'OAuth Functional Accounts'} = 'OAuth Funktionale Accounts';
    $Self->{Translation}->{'Functional Account and Token Management.'} = 'Funktionale Account und OAuth Tokens verwalten.';

    # SysConf xml

    $Self->{Translation}->{'OIDC Profile Management'} = 'OIDC Profil Verwaltung';
    $Self->{Translation}->{'Manage OpendID Connect OAuth2 Profiles.'} = 'OpenID Connect Profile bearbeiten';
    $Self->{Translation}->{'OAuth Functional Accounts'} = 'OAuth Funktionale Accounts';
    $Self->{Translation}->{'Functional Account and Token Management.'} = 'Funktionale Accounts und OAuth2 Tokens';
}

1;
