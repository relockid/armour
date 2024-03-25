Active API Armour
=================

The Active API Armour is an automated defense software, designed for APIs dealing with the most sensitive data. It allows developers to securely implement mutual authentication with entangled identity, authorization, and end-to-end encryption with perfect forward secrecy, using just one, streamlined and fail-proof elegant binary program.

The Armour reduces any room for errors in API security implementation and configuration, and completely eliminates the hassle and cost for key management.

Why should you consider using the Armour?
-----------------------------------------

API security is emerging as a significant business issue that translates into new development challenges for many modern systems and services. The existing toolkit, including OAuth / OpenID, signed JWT tokens, or mTLS, presents some important vulnerabilities that are exploited by adversaries and require a lot of work, often cumbersome and non-value-adding, from the development and security teams.

By adding the Armour to your API workflow and architecture you can efficiently enforce zero trust posture with a streamlined and fail-proof authentication, authorization, and encryption – all in one software. 

Minimal example
---------------
Run service:

    docker pull relock/armour
    docker run --privileged --network host -it relock/armour run \
           --host 127.0.0.1 --port 8111 \
           --multiprocessing

Python:

    python3 -m pip install relock
    
    from relock import TCP as Armour

    http = requests.Session()
    armour = Armour(host='127.0.0.1',
                    port=8111,
                    name='Alice',
                    pool=1)

    with armour('<ticket>', '<api url>', 80) as arm:
        if response := http.get('http://' + host,
                                headers={'Content-Type': 'application/json',
                                          **arm.headers()},
                                json={'time': arm.encrypt(time.time())}):
            if ticket := arm.stamp(response.headers):
                logging.info('Decrypted %s', arm.decrypt(response.json().get('time')))


GitHub repository
-----------------

This repository contains ready-to-use, minimal implementation of the producer server and the consumer for test purpose of re:lock Armour. This minimal implementation makes it easy to check how the failsafe-disconnect system works in practice.

You can run the demo solution on one machine, as consumer and producer may use the same enclave for this purpose.

Links
-----

-   Docker: https://hub.docker.com/r/relock/armour
-   Documentation: https://armour.relock.id/
-   Demo Source Code: https://github.com/relockid/armour
-   Issue Tracker: https://github.com/relockid/armour/issues
-   Website: https://relock.id/