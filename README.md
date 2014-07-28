ECC-25519
=========

This project helps to use elliptic curve cryptography (ECC) with Curve25519 by Daniel J Bernstein. It combines multiple libraries.

All credit goes to following libraries. **Please respect their licenses!**

**Android:**
* https://github.com/dazoe/Android.Ed25519
* https://code.google.com/p/curve25519-java/

**Java:**
* https://github.com/krm2/ed25519-java
* https://github.com/str4d/ed25519-java/tree/ref10
* https://code.google.com/p/curve25519-java/

Download
--------

Grab via Gradle or [Maven][1].

```groovy
dependencies {
    compile 'net.vrallev.ecc:ecc-25519-android:1.0.0' 	// Android
    compile 'net.vrallev.ecc:ecc-25519-java:1.0.0' 		// JVM
}
```

```xml
<dependency>
    <groupId>net.vrallev.ecc</groupId>
    <artifactId>ecc-25519-android</artifactId>
    <version>1.0.0</version>
</dependency>

<!-- OR -->

<dependency>
    <groupId>net.vrallev.ecc</groupId>
    <artifactId>ecc-25519-java</artifactId>
    <version>1.0.0</version>
</dependency>
```

Usage Android
-------------

```java
byte[] seed = "My random seed".getBytes();
byte[] privateKey = KeyHolder.createPrivateKey(seed); // creates a valid private key (seed hashed with SHA-256) 

KeyHolder keyHolder = new KeyHolder(privateKey); // computes valid public keys
Ecc25519Helper helper = new Ecc25519Helper(keyHolder); // generate our helper class 

byte[] sharedSecret = helper.diffieHellman(); // you can also pass a private and public key

byte[] message = "My message".getBytes();
byte[] signature = helper.sign(message); // computes the signature with the private key
boolean validSignature = helper.isValidSignature(message, signature); // checks the message with the public key from keyHolder instance
```

Usage Java
----------

Same API like Android, but you have the option to exchange the Ed25519 provider.

The slow version uses this implementation: https://github.com/krm2/ed25519-java

The fast implementation uses this implementation (**WARNING**: the implementation is not proved to work correctly): https://github.com/str4d/ed25519-java/tree/ref10

```java
byte[] privateKey = KeyHolder.createPrivateKey("my seed".getBytes());
Ecc25519Helper helper = new Ecc25519Helper(privateKey);
// or
helper = new Ecc25519HelperFast(privateKey);
```

License
-------

    Licensed under the Apache License, Version 2.0 (the "License");
    you may not use this file except in compliance with the License.
    You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing, software
    distributed under the License is distributed on an "AS IS" BASIS,
    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
    See the License for the specific language governing permissions and
    limitations under the License.

[1]: http://search.maven.org/#search%7Cga%7C1%7Cg%3A%22net.vrallev.ecc%22