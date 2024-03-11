Active API Armour
=================

The Active API Armour is an automated defense software, designed for APIs dealing with the most sensitive data. It allows developers to securely implement mutual authentication with entangled identity, real-time authorization, and end-to-end encryption with perfect forward secrecy, using just one, streamlined and fail-proof binary program.

The Armour reduces any room for errors in API security implementation and configuration, and completely eliminates the hassle and cost for key management.

Why should you consider using the Armour?
-----------------------------------------

API security is emerging as a significant business issue that translates into new development challenges for many modern systems and services. The existing toolkit, including OAuth / OpenID, signed JWT tokens, or mTLS, presents some important vulnerabilities that are exploited by adversaries and require a lot of work, often cumbersome and non-value-adding, from the development and security teams.

By adding the Armour to your API workflow and architecture you can efficiently enforce zero trust posture with a streamlined and fail-proof authentication, authorization, and encryption – all in one software. 

Minimal example
---------------
Run service:

    docker pull relock/armour
    docker run -it relock/armour --host 172.72.0.1 --port 443

You can install python package in the usual way using `pip`:

    pip install relock

Typical request may look like this:

    from relock import Armour

    with Armour('172.72.0.1') as armour:
        if ticket := armour.ticket():
            if response := requests.get('https://awesome.api.com/secure/endpoint',
                                        headers=ticket.headers()):
                if ticket := armour.stamp(response):
                    print(response.json())

Links
-----

-   Docker: https://armour.relock.id/
-   Documentation: https://armour.relock.id/
-   Source Code: https://github.com/relockid/armour
-   Issue Tracker: https://github.com/relockid/armour/issues
-   Website: https://relock.id/