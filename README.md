# secomm-tls-java
**A Simple TLS library**

I needed a TLS implementation for the Tor Java Relay project. I got tired of fighting with a certain well-known TLS library (If you're going to provide zero documentation, the least you could do would be to put a few comments in the code). Thus was born this project.

It's going to start as a bare-bones TLS 1.2 implementation. It might be useful to someone else as well.

If you do decide to use this and you would like to see a feature added, just leave me a message and I'll see what I can do.

Using the library is very simple. These are the steps to start a basic client

`TLsClientContext clientContext = TlsContext.initializeClient(SecureRandonrandom);`

`TlsPeer peer = clientContext.connect("somewhere.com);`

`peer.send("Hi There!");`

`String response = peer.readAll();`

The Java IO Stream API can be used as well.

`TlsOutputStream outputStream = client.getOutputStream();`

`TlsInputStream inputStream = client.getInputStream();`

If you need to connect to a port other than the default (443), this is available

`TlsPeer peer = tlsClientContext.connect("somewhere.com", 1024);`

A basic server looks like this

`TlsServerContext serverContext = TlsContext.initializeServer(SecureRandom random);`

`TlsServer server = serverContext.listen()`;

`TlsPeer peer = server.accept();`

`String request = peer.readAll();`

`peer.write("I hear you!");`

As above, the stream API can be used

`TlsOutputStream outputStream = peer.getOutputStream();`

`TlsInputStream inputStream = peer.getInputStream();`

The server can listen on ports other than the SSL default;

`TlsServer server = serverContext.listen(1024);`

There is also a conversation API

`TlsConversation conversation = peer.getConversation()`

`String response = conversation.exchange("Hi There!)`

More to come when I can spend more time on it.
