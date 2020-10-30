# secomm-tls-java
A Simple TLS library

I needed a TLS implementation for the Tor Java Relay project. I got tired of fighting with a certain well-known TLS library (If you're going to provide zero documentation, the least you could do would be to put a few comments in the code). Thus was born this project.

It's going to start as a bare-bones TLS 1.2 implementation. It might be useful to someone else as well.

If you do decide to use this and you would like to see a feature added, just leave me a message and I'll see what I can do.

Using the library is very simple. These are the steps to start a basic client


TlsClientContext tlsClientContext = TlsContext.initializeClient();

TlsClient tlsClient = tlsClientContext.connect("somewhere.com");

tlsClient.write("Hi There!");

String response = tlsClient.readAll()

If you need to connect to a port other than the default (443), this is available

TlsClient tlsClient = tlsClientContext.connect("somewhere.com", 1024);

A basic server looks like this

TlsServerContext tlsServerContext = TlsContext.initializeServer();

TlsServer tlsServer = tlsServerContext.listen(port);

TlsPeer tlsPeer = tlsServer.get();

String request = tlsPeer.readAll();

tlsServer.write("I hear you!", tlsPeer);

More to come when I can spend more time on it.
