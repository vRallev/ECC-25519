ECC-25519
=========

This project helps to use elliptic curve cryptography (ECC) with Curve25519 by Daniel J Bernstein. It combines multible libraries.

All credit goes to following libraries. Please respect their licenses! 

https://github.com/dazoe/Android.Ed25519
https://github.com/krm2/ed25519-java
https://github.com/str4d/ed25519-java/tree/ref10
https://code.google.com/p/curve25519-java/

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

The fast implementation uses this implementation (**warning**: the implementation is not proved to work correctly): https://github.com/str4d/ed25519-java/tree/ref10

```java
byte[] privateKey = KeyHolder.createPrivateKey("my seed".getBytes());
Ecc25519Helper helper = new Ecc25519Helper(privateKey);
// or
helper = new Ecc25519HelperFast(privateKey);
```

Maven Repo
----------

I've uploaded the `.aar` (Android) and `.jar` (Java, JVM) in my maven repository. You only need to add following lines to your `build.gradle` to add the dependency:
```groovy
repositories {
    maven {
        url 'https://raw.github.com/vRallev/mvn-repo/master/'
    }
}

dependencies {
    compile 'net.vrallev.android.library:ecc-25519:1.0.1' // Android
    compile 'net.vrallev.java.library:ecc-25519:1.0.1' // JVM
}
```