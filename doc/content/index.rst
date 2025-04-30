.. image:: ../images/otobo-logo.png
   :align: center

.. toctree::
    :maxdepth: 2
    :caption: Contents

Sacrifice to Sphinx
===================
.. This chapter must always be empty. Any content is lost when creating the final version of the documentation.

Overview
========
The Otobo OAuth2 packages adds support for OpenID Connect based authentication for incoming and outgoing webservice calls via Otobo's GenericInterface.

Summary
-------
With the Otobo OAuth2 package, webservice authentication using an OpenID Connect (OICD) provider can be enabled and configured. Otobo then can use OAuth2 tokens from your OICD provider to make authenticated outgoing webservice calls (GenericInterface Invokers), or validate such OAuth2 tokens for incoming webservice calls (GenericInterface Provider).


Introduction
------------

Use this package if

- you are using an OpenID Connect (OIDD) Provider for Identity Management like MS Azure, Google, or a self hosted solution like keycloak.

- you want to use OIDC token based authentication for outgoing or incoming webservice calls using Otobo's GenericInterface

This packages is *not* needed if you are just looking for using OIDC as a login mechanism for Otobo. Login via OIDC is already built into Otobo core.


Common Usecases
---------------

Usecase scenarios for this package include integration topics utilizing API communication via webservices, called GenericInterface in Otobo.

- Make Otobo provide webservice API endpoints to fetch Data from Otobo, authenticated using OAuth2 bearer tokens from your OIDC provider. Example: *GetTicket endpoint*

- Make Otobo provide webservice API endpoints to call Otobo operations, authenticated using OAuth2 bearer tokens from your OIDC provider. Example: *UpdateTicket endpoint*

- Make Otobo invoke other system's webservice API endpoints, passing data from the event trigger to the external system, and (possibly) doing something with whatever data returned, authenticated using OAuth2 bearer tokens from your OIDC provider. Example: *Pass Ticket data to remote system whenever ticket is updated.*


Further Reading
---------------

Integration with OpendID Connect (OIDC) and OAuth2 is a huge topic. General questions about OAuth2 and OIDC are outside the scope of this documentation.

A good entry point on 'What is OpenID Connect and what do I need it for?' can be found on the openid foundation website:

`How OpenID Connect works <https://openid.net/developers/how-connect-works/>`__


Configuration
=============

There are two main ways to configure Otobo for OIDC based API calls, one for Providers handling incoming API requests, and one for Invokers handling outgoing API requests.


System requirements
-------------------

Framework
^^^^^^^^^

OTOBO 11.0.x

Packages
^^^^^^^^

This package does not depend on other packages.


Third-party software
^^^^^^^^^^^^^^^^^^^^

This package depends on the external OpenID Connect Provider of your choice.


Basic Configuration (Both Provider and Invoker)
-----------------------------------------------

Your system-administrator should configure one (or more) OAuth2 Application(s) with their relevant OIDC provider and give you the following configuration details:

- the well-known provider metadata discovery url as described in the `openid spec <https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfigurationRequest>`__  Example: '\https://keycloak:8443/realms/master/.well-known/openid-configuration' 
- ``client_id`` and ``client_secret`` parameters for your OAuth2 Application
- the ``UID`` identifier of an OAuth2 JWT token claim that can be mapped to an Otobo UserLogin identifier. Usual values include 'sub', 'email', or 'uid'. Use 'sub' if in doubt.

If your planning to use functional accounts (aka System Users) to authorize outgoing API calls triggered by Otobo:

- the ``grant_type`` which will be one of: 'client_credentials' or 'password' or 'authorization_code'. if grant_type is 'password', you will also get username/password credentials
- optionally, a set of ``scope`` parameters to use. When using OIDC this likely will include 'openid'
- optionally, a set of ``resource`` ids to use. 

**Important**

If you are using the 'authorization_code' flow, which will redirect your browser to the Provider login page to authenticate, the OIDC Provider will redirect you back to your Otobo instance when the authentication was successful.
For this to work the 'redirect_uri' that points back to you Otobo instance must be an allowed redirect_uri configured for your OAuth2 OIDC application. The generated URL will be
``http(s)://your-otobo.fqdn/otobo/index.pl?Action=AdminOAuthTokenStore&Subaction=OAuth'``. 

Note this is in addition to the Login redirect_uri which usually is
``http(s)://your-otobo.fqdn/otobo/index.pl?Action=Login'``. 

Some Provider allow simple wildcards in the redirect_uri setting, like ``http(s)://your-otobo.fqdn/otobo/index.pl*`` - Please
consult your OIDC Provider documentation for details.


Otobo as Provider
=================

Basic OpenID Connect Provider Configuration in Otobo
----------------------------------------------------

For incoming OAuth2 API calls, Otobo has to authenticate the incoming OAuth2 Tokens and map them to an Otobo user.
For API calls this works using the same Authentication Modules ('AuthModule' in Config.pm) as used for Login via OpenID Connect.
If you already using Otobo for OIDC based login, you should already have a valid OIDC configuration like from the example above and **you are all set**. 

Otherwise, in case you are not using OIDC for Login, but still want to use OIDC for API calls, or if you want to use a OIDC provider for API calls 
different from your default OIDC configuration used for login, add an additional AuthModule for OIDC.

Refer to the examples for configuring OIDC that come with your Otobo installation. The examples are in Kernel/Config/Defaults.pm line 518ff,
and this needs to be configured in ``Config.pm``.

::

   # This is an example configuration for authorization via OpenIDConnect
   # see https://openid.net/specs/openid-connect-core-1_0.html
    $Self->{AuthModule} = 'Kernel::System::Auth::OpenIDConnect';
    # Define the authentication flow, currently supported are the authorization code flow...
    $Self->{'AuthModule::OpenIDConnect::AuthRequest'}->{ResponseType} = [ 'code' ];
    # Define the additional scope (openid is added automatically and does not need to be
    # defined here). Make sure to add everything you want to interpret later.
    $Self->{'AuthModule::OpenIDConnect::AuthRequest'}->{AdditionalScope} = [
        qw/profile email/
    ];
    # Set the ClientID and Redirect URI exactly as defined on the authorization server
    # for the latter the Action must be "Login"
    $Self->{'AuthModule::OpenIDConnect::Config'}{ClientSettings} = {
        ClientID    => 'abc123',
        RedirectURI => 'https://my.otobo.server/otobo/index.pl?Action=Login',
    };
    # For the authorization code flow the client secret has to be provided
    $Self->{'AuthModule::OpenIDConnect::Config'}{ClientSettings}{ClientSecret} = 's3cr3t';
    # Provide the URL of the well-known openid-configuration of the OpenID provider
    $Self->{'AuthModule::OpenIDConnect::Config'}{ProviderSettings} = {
        OpenIDConfiguration => 'https://keycloak:8080/auth/realms/MyRealm/.well-known/openid-configuration',
        TTL                 => 60 * 30,      # optional: time period the extracted openid-configuration is cached
        Name                => 'Intern4',    # optional: necessary only if one needs to differentiate between User and CustomerUser configuration e.g.
        SSLOptions          => {             # if special ssl options are needed; SSLVerifyHostname => 0 and SSLVerifyMode => 0 are also possible but should only be used for testing purposes
            SSLCertificate => 'SSL_cert_file',     # client certificate
            SSLKey         => 'SSL_key_file',      # client cert key
            SSLPassword    => 'SSL_passwd_cb',     # password for client cert key
            SSLCAFile      => 'SSL_ca_file',       # CA certificate
            SSLCADir       => 'SSL_ca_path',       # CA cert directory
        },
    };
    # Set the token claim to be used as identifier
    $Self->{'AuthModule::OpenIDConnect::UID'} = 'sub';
    # Some optional additional settings
    $Self->{'AuthModule::OpenIDConnect::Config'}{Misc} = {
        UseNonce   => 1,      # add a nonce to request and token (this is primarily important for the implicit flow where it is enabled by default)
        RandLength => 22,     # length for state and nonce random strings - default: 22
        RandTTL    => 60 * 5, # valid time period for state and nonce (roughly the time a user can take to authenticate) - default: 300 s
        Leeway     => 2,      # leeway for small time differences between the OTOBO server and the OpenID provier - default: 2 s
    };
    # Optionally enable user authorization via the id token - hashes can be used for complex claims
    $Self->{'AuthModule::OpenIDConnect::RoleMap'} = {
        TokenAttribute => {
            TokenRole1 => 'OTOBORole1',
            TokenRole2 => 'OTOBORole2',
        },
        TokenAttribute2 => {
            abc123 => {
                TokenRole1 => 'OTOBORole1',
                TokenRole3 => 'OTOBORole3',
            }
        },
    };
    # Optionally enable user creation - this currently does not support complex claims; email is mandatory
    $Self->{'AuthModule::OpenIDConnect::UserMap'} = {
        email       => 'UserEmail',
        given_name  => 'UserFirstname',
        family_name => 'UserLastname',
    };
    # For debugging purposes and to help with building the RoleMap e.g. you can dump all IDTokens received to the log
    $Self->{'AuthModule::OpenIDConnect::Debug'}->{'LogIDToken'} = 1;


Provider Restrictions (optional)
--------------------------------

Every valid Token needs to be mapped to a system user. If an API system user does not exist for an incoming webservice call, it will be created provided the Token 
passes validation and any further restrictions.

To add restrictions which valid tokens are accepted for incoming webservice calls, restrict by these fields in Config.pm:

- ``UserLogin``: only accept tokens of this particular login. This must match the UserLogin value in the Otobo System (UserLogin attribute of the User entity).

- ``Scope``: a space separated list listing token's 'scope' claims that must be present in incoming tokens to be allowed

- ``Audience``: a space separated list listing token's 'aud' claims that must be present in incoming tokens to be allowed

- ``AuthorizedParty``: simple identifier that must match the token's 'azp' claim to be allowed

Usually, you would either restrict to a specific user login, or to a combination of the other values, depending on your needs.

Example for Config.pm:

::

   $Self->{'AuthModule::OpenIDConnect::Webservice::Restrictions'} = {
        UserLogin => '',
        Scope => '',
        AuthorizedParty => '',
        Audience => ''
   };



Provider Example
----------------

With above configuration for Providers in place, follow these steps to set up a *Test Provider Webservice* in Otobo:

- Navigate to **Webservices** in Admin UI
- Select **Add New Webservice** and give it Name and Description of 'Test'
- Under **Otobo as Provider**, select '\HTTP::REST' as Transport
- Click **Save**
- Add an operation and choose 'Ticket::TicketGet'
- Set Name and Description fields to 'TicketGet'
- Choose 'Simple' for both mapping types
- Click **Save and Finish**
- Click again on the previous button to configure *Network Transport: HTTP::REST*
- Enter '/GetTicket/:TicketID' for the route mapping
- Select 'GET' as the single valid request method
- Click **Save and Finish**

At this point Otobo should be set up to accept incoming calls with OAuth2 tokens for the /GetTicket/:TikcetID endpoint.

First get a token from your provider. How that works in practice depends on your OIDC provider and your remote setup, but for testing a curl call with client_credentials grant type might look similar to this example (keycloak):

::

   curl -s -k -d 'client_id=someapi' -d 'client_secret=s3cr3t' -d 'username=test1@example.com' -d 'password=test' -d 'grant_type=password' -d 'scope=openid' 'https://localhost:8443/realms/master/protocol/openid-connect/token' |jq
   
   # outputs
   {
     "access_token": "eyJhbG .....",
     "expires_in": 60,
     "refresh_expires_in": 1800,
     "refresh_token": "eyJh...",
     "token_type": "Bearer",
     "id_token": "eyJhb...",
     "not-before-policy": 0,
     "session_state": "3d45911d-4ea5-42a8-814c-133cba55bf8f",
     "scope": "openid email profile roles"
   }

You should receive at least an ``access_token``, whether you also get ``refresh_token`` and ``id_token`` depends on your provider settings. In most cases you would use the access_token to make webservice calls, but in some environments also passing id tokens can make sense.

Now that we have a token, invoke the *GetTicket* API endpoint we configured above. Note we pass '1' as the TicketID, which is usually present on all Otobo system-administrator
as it is the 'Welcome to OTOBO' test email. Xou can pass any TicketID that exists in your system, of course.

::

   curl -k -X GET -H'Authorization: Bearer <token from above>' 'http://localhost/otobo/nph-genericinterface.pl/Webservice/Test/GetTicket/1' | jq
     
   # Outputs:
   {
     "Ticket": [
       {
         "StateID": 4,
         "LockID": 2,
         "CreateBy": 1,
         "RealTillTimeNotUsed": 0,
         "UntilTime": 0,
         "TypeID": 1,
         "StateType": "open",
         "CustomerUserID": null,
         "ChangeBy": 4,
         "OwnerID": 2,
         "Title": "Hello otobo welcome1",
         "ResponsibleID": 1,
         "QueueID": 2,
         "ServiceID": "",
         "GroupID": 1,
         "EscalationTime": 0,
         "Responsible": "root@localhost",
         "TicketID": 1,
         "EscalationSolutionTime": 0,
         "State": "open",
         "CustomerID": null,
         "EscalationUpdateTime": 0,
         "TicketNumber": "2015071510123456",
         "Age": 3464340,
         "Type": "Unclassified",
         "PriorityID": 3,
         "Created": "2025-03-07 08:38:24",
         "Priority": "3 normal",
         "Queue": "Raw",
         "ArchiveFlag": "n",
         "Owner": "9dd07755-941e-4b84-ac08-4636f036d26c",
         "Changed": "2025-04-15 07:53:31",
         "SLAID": "",
         "EscalationResponseTime": 0,
         "Lock": "lock",
         "TimeUnit": 0,
         "UnlockTimeout": 1744703611
       }
     ]
   }


Otobo as Invoker
================

Whereas Otobo as Provider only has to validate incoming OAuth2 tokens, in order to make outgoing calls as Invoker Otobo needs to obtain and manage OAuth2 tokens  for one or more functional accounts. 
Functional accounts for Invokers and their tokens can be managed via the dedicated Amin UI module **OAuth Functional Accounts**. Unlike Providers for incoming calls,
which use the OIDC Profile configured for authentication, the outgoing (Invoker) Webservices require a dedicated OIDC Profile setup, which can be done in 
antoher  dedicated Admin UI module named **OIDC Profile Management**. First, configure an OIDC Provider Profile:

In the **Admin UI**, navigate to **OIDC Profile Management**

.. image:: ../images/profiles-overview.png
   :alt: Profiles Overview

To create a new Profile, choose **Add** from the left navigation bar. 

.. image:: ../images/profile-add.png
   :alt: Add Profile

If you are already using OIDC for Login, some values will be prepopulated. You have to provide a valid, unique Profile name and also provide the OAuth2 application
client_secret value, which is not pre-populated for security reasons. Usually you can keep all the defaults, especially for the optional SSL- and Misc settings.

Now that we have an OIDC Provider Profile, we can set up a Functional Account. There can be more than one Functional Account per Profile.

In the **Admin UI**, navigate to **OAuth Functional Accounts**


.. image:: ../images/functional-account-overview.png
   :alt: Functional Account Overview

To create a new Account, choose **Add** from the left navigation bar.

.. image:: ../images/functional-account-detail.png
   :alt: Functional Account Details

Here you give your account a Name and choose one of the OIDC Provider profiles configured earlier. 
Choose the ``GrantType`` as instructed by your system administrator, and provide the ``Scope`` parameter as required. ``Scope`` will
often contain 'openid' and 'offline_access', other common values are 'email' and 'profile'.

In the **Advanced** section you can configure additional details, if needed:

- ``Resources`` : a space sperated list of resource ids to request access  for. not used in all OIDC environments
- ``ResoureParamName`` : usually 'resource', but can be overriden here
- ``TokenType``: usually 'access_token', but in some environments 'id_token' may be used

Only change advanced settings if instructed by your system administrator.


Invoker Example
---------------

Assuming you have configured at least one functional account for Invokers as per above paragraph, we can now configure a *Test Invoker Webservice*. 

- Navigate to **Webservices** in Admin UI
- Select **Add New Webservice** and give it Name and Description of 'Test'
- Under **Ootobo as Requester**, select ''\HTTP::REST' as Transport
- Click **Save**
- Under **Invokers**, select the 'Generic::Passthrough' option from the dropdown
- Set Name and Description fields to 'Passthrough'
- Choose 'Simple' for both mapping types
- Click **Save**
- Under **Add Event Trigger**, choose 'Ticket' and 'ArticleEdit', remove the checkbox labeled 'Asynchronous' and click the circled plus sign **(+)**
- Click **Save and Finish**
- Click the button to configure **Network Transport: HTTP::REST**
- Enter the FQDN of the remote system to call, eg '\http://echoservice.mycompany.net', without trailing slash, under **Endpoint**
- From the **Authentication** dropdown choose 'OAuth'
- Select one of the functional accounts to use from the **OAuth2 Functional Account** dropdown
- Provide the HTTP path for the endpoint to call, eg '/rest/api/endpoint' under **Controller Mapping**
- Select 'POST' as value for **valid request commands**
- Click **Save and Finish**

At this point, Otobo should try to make an outgoing HTTP API call every time an article in a ticket gets updated, and automatically attach an OAuth2 Bearer Token to the request in the Authorization HTTP header. 
To try it out:

- Select a ticket
- Add a note
- Modify the body of the note

Everytime you modify the note, your API endpoint at ``http://echoservice.mycompany.net/rest/api/endpoint`` now should receive a POST request with the article data as JSON payload in the post body.

.. image:: ../images/webservice-invoker.png
   :alt: Invoker Webservice Config


Appendix
========

Debugging Webservice Calls
------------------------------------------

Please note that Webservice calls using OAuth2 tokens can be debugged as usual using the built in Otobo webservice Debugger. To open the debugger for a specific webservice,
navigate to **WebServices** in the Admin UI, choose the desired webservice, and click on **Debugger** in the lefthand navigation bar.

Cronjob for updating refresh_tokens
-----------------------------------

The Cron job that keeps OAuth2 tokens up to date by making regular use of refresh_tokens ca be configured in the **System Settings** under the key ``Daemon::SchedulerCronTaskManager::Task###TokenStoreUpdater``.
By default the cronjob executes once very 60 minutes. In case your refresh_tokens expire sooner than 60 minuts, you'll need to adapt.

The only parameters to tune are the Cron Schdule expression itself, and the ``Interval`` Param. The cron expression can be any valid cron expression, examples include:

- '0 * * * *'    - runs once per hour, at minute 0
- '0 0 * * *'    - runs once per day, at midnight
- '*/10 * * * *' - runs every 10 minutes

See https://en.wikipedia.org/wiki/Cron for further details on crontab format.

For the ``Interval`` parameter set it to the time period between two scheduled task runs, in seconds. Running the cronjob once per hour gives you 
60 * 60 = 3600 seconds between each run, and thus the ``Interval`` Param should be set to 3600.

.. image:: ../images/tokenstore-cron.png
   :alt: Invoker Webservice Config



Advanced User Import
--------------------

In case of problems with the automated User import for incoming webservice calls (Provider), there is a console command to manually import a specific User
into the system. This console command can also be used for debugging OIDC/OAuth2 problems. The command comes with a '-dry-run' option that will only simulate
the import, it will do the actual handshake with the OIDC provider, but it will not actually import the user.


::

   otobo@87e0d136371d:~$ bin/otobo.Console.pl Admin::OAuth2::ImportUser --help
   
   Import a Functional User Account from an OpenID Connect Provider.
   
   Usage:
    otobo.Console.pl Admin::OAuth2::ImportUser --grant-type ...  [--openid-config ...] 
    [--username ...] [--password ...] [--scope ...] [--resource ...] 
    [--resource-param-name ...] [--token-type ...] [--user-map ...] 
    [--role-map ...] [--uid ...]
   
   Options:
    [--openid-config ...]          - The name of OpenID Config to use. Defaults to 
                                     'AuthModule::OpenIDConnect::Config' for using the 
                                     default OIDC login provider if this system uses 
                                     OIDC for login purposes. Otherwise use one of 
                                     'OpenIDConnect::UserMapping###Custom1' ... 
                                     CustomN Keys. 
    --grant-type ...               - Specify the OAuth2 grant-type (one of 
                                     password|client_credentials).
    [--username ...]               - Specify the OAuth2 username if grant-type is 'password'.
    [--password ...]               - Specify the OAuth2 password if grant-type is 'password'.
    [--scope ...]                  - Specify the OAuth2 scope(s) as a space separated list. 
                                     optional.
    [--resource ...]               - Specify the OAuth2 resource parameter as a 
                                     space separated list. optional.
    [--resource-param-name ...]    - Specify the OAuth2 resource parameter name, that is the 
                                     name of the parameter itself. optional, defaults to 'resource'
    [--token-type ...]             - Specify the OAuth2 token type, can be 'access_token' 
                                     or 'id_token'. defaults to 'id_token'.
    [--user-map ...]               - Specify the name of the UserMap system configuration 
                                     setting. defaults to 'AuthModule::OpenIDConnect::UserMap'.
    [--role-map ...]               - Specify the name of the RoleMap system configuration 
                                     setting. defaults to 'AuthModule::OpenIDConnect::RoleMap'.
    [--uid ...]                    - Specify the name of jwt token claim to be mapped to the 
                                     Otobo UserLogin. Defaults to 'sub'
    [--help|h]                     - Display help for this command.
    [--no-ansi]                    - Do not perform ANSI terminal output coloring.
   [--quiet]                      - Suppress informative output, only retain error messages.



About
=======

Contact
-------
| Rother OSS GmbH
| Email: hello@otobo.io
| Web: https://otobo.io

Version
-------
