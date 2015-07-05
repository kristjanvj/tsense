# This is the home of the **TSense** project -- trusted sensor and support infrastructure. #

The TSense project is currently active and expected to close in september 2010. The project is supported by a Student Innovation Fund grant from the Icelandic research fund ([Rannis](http://www.rannis.is)).

**This site and the code is currently under construction.**


# About TSense #

The purpose of the _Trusted Sensors project (TSense)_ is to construct a simple PoC that can provide end-to-end integrity, and optionally confidentiality, for a simple networked measurement system. A client-server model is used. Trusted sensor modules are plugged into untrusted clients. This combination sends authenticated messages to a trusted measurement server. The basic building blocks of the system are sketched below.

We will work on two models:
  * a strict client/server model, with a single measurement server and a number of client/sensor pairs.
  * a clustered model with an arbitrary network of trusted clusterheads. Each clusterhead is in essence equivalent to the server in the previous model.

## Trusted sensor ##

The trusted sensor is a small embedded device, which we assume to be tamperproof (the prototype will not be tamperproof, but we would expect production models to be so). We base our prototype on an Arduino processor board with an Atmel ATMega328 processor. The trusted sensor has onboard cryptographic keys which are known only to the manufacturer. The manufacturer in turn provides session keys (or public key counterparts in asymmetric setting) to the measurement server. The messages produced by the sensor can thus be end-to-end encrypted and authenticated.

In the current project, we will use only symmetric crypto, the reason being the more efficient nature of such algorithms. While asymmetric cryptographic algorithms are certainly feasible, even on small hardware, they involve more complex mathematical operations, requiring more CPU power, memory and chip area. Therefore, we feel that efficient symmetric algorithms are more in the spirit of the current project -- to produce a tiny (essentially disposable) device, which is nevertheless capable of producing a secure output.

## Client ##

The client is a generic PC with a small piece of software, which interfaces with the trusted sensor. In the prototype, we assume USB connection of the sensor to the client. The PC platform as a whole and the client software are considered untrusted, as is the communications channel to the measurement server. The client can query the sensor for measurements and forward them to the measurement server. The cryptographic primitives applied by the sensor software are supposed to ensure that a client compromized by an adversary can only drop messages, not manufacture arbitrary messages or modify ones received. A byzantine failure model for the client is therefore transformed into a crash failure model. In essence, a compromized client is a man-in-the-middle -- our task is to limit the influence a collection of such compromized clients can have on the aggregate measurement result.

The sensor is capable of operating in two modes. In the first one, it produces a verifiable output -- sending the measurements in cleartext, while applying a MAC or signature to enable verification. In this case, the compromised node is prevented from modifying the message, but can certainly (at least occasionally) simulate crash failures and drop the message. Further, it can do so selectively, for example dropping only low readings. In the second mode of operation, the sensor additionally encrypts the message. This certainly provides end-to-end security, which may be important for some applications. Additionally, encryption prevents the compromised node from selectively dropping messages. It can still simulate crash failures, but its capabilities are reduced to randomly selecting messages to drop. In conjunction with mechanisms to eject non-responding nodes, we can conclude that encryption and authentication of messages significantly reduces the adversaries capabilities to influence the system.

## Measurement sink / cluster head ##

The measurement server authenticates sensor/client combinations (both of these must have strong, verifiable identities), receives and validates received measurements. Security against outsider attackers (active and passive) is provided by the encryption applied by the trusted sensor. An additional layer of security can be added by applying TLS/SSL between client and sink. Note that a tunnel between client and sink does nothing to protect against insider adversaries (the ones we are interested in).

The sensor has a strong and verifiable identity and functions as an unique unforgeable identity for the client on insertion into an active measurement system. The reason for the unique identity requirement is to prevent attacks involving cloned or simulated (Sybil) sensor nodes. The sink verifies each client/sensor pair on insertion with the assistance of the authentication server.

In the single server model, we must regard the sink as trusted. Nevertheless, we use a separate authentication entity, as described below. In the clusterhead model, such an entity is certainly necessary as compromise of any single clusterhead should not compromise the future integrity of the system.

## Authentication service ##

We propose a separate highly trusted authentication service, which securely stores the counterparts of the permanent secret keys stored on the sensors. The authentication service could be the manufacturer of the sensor or a separate trusted 3rd party. The authentication procedure at insertion into a measurement network must include interaction with this entity to positively identify the sensor and provide sensor and measurement server (cluster head) with the necessary temporary (session) keys. By using a temporary key, we can ensure that the future integrity of the system is ensured, even in the event of a cluster head compromise.

# Adversarial model #

We consider stealthy internal adversaries. The adversary can compromize an arbitrary number of clients but no sensors (it should be infeasible to compromize or emulate sensors). We apply standard transport layer security to exclude outside adversaries. The adversary has complete access to all compromized clients, including installed certificates and cryptographic keys. We also assume the adversary to know all protocols in use and be able to deviate arbitrarily. However, the aim of the adversary is to avoid detection for an extended period, so the protocol deviations must be carefully calculated. In the absence of a trusted sensor, the adversary is capable of arbitrarily injecting messages and modifying intercepted ones.

# Future work #

Future work includes adapting the model to a distributed hieararchial aggregation architecture. However, this is non-trivial due to difficulties in ensuring any kind of equivalence to end-to-end security in the hierarchial in-network aggregation model. We bypass those difficulties in the TSense prototype by assuming a strict client/server model. We can view the client as an aggregator, albeit a very simple one which receives only a single input (from an internal leaf if we place this in the context of in-network aggregation). In terms of aggregation networks, we can view the topology as a cluster with the trusted measurement server as a cluster head.