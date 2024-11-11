# jinahya-bcprov

[![Java CI with Maven](https://github.com/jinahya/jinahya-bouncycastle-utils/actions/workflows/maven.yml/badge.svg)](https://github.com/jinahya/jinahya-bouncycastle-utils/actions/workflows/maven.yml)
[![Quality Gate Status](https://sonarcloud.io/api/project_badges/measure?project=jinahya_jinahya-bcprov&metric=alert_status)](https://sonarcloud.io/summary/new_code?id=jinahya_jinahya-bcprov)
[![Maven Central Version](https://img.shields.io/maven-central/v/io.github.jinahya/jinahya-bcprov)](https://central.sonatype.com/artifact/io.github.jinahya/jinahya-bcprov)
[![javadoc](https://javadoc.io/badge2/io.github.jinahya/jinahya-bcprov/javadoc.svg)](https://javadoc.io/doc/io.github.jinahya/jinahya-bcprov)

A thin extension, for [Bouncy Castle for Java](https://www.bouncycastle.org/documentation/documentation-java/), which
is (based|verified) (on|against)

* [`org.bouncycastle:bcprov-jdk8on:latest`](https://central.sonatype.com/artifact/org.bouncycastle/bcprov-jdk18on)
* [`org.bouncycastle:bcprov-lts8on:latest`](https://central.sonatype.com/artifact/org.bouncycastle/bcprov-lts8on)

## How to build

### Java

Requires Java 21 for building, Java 11 for running.

```commandline
 $ grep '<maven.compiler' pom.xml
    <maven.compiler.source>11</maven.compiler.source>
    <maven.compiler.target>${maven.compiler.source}</maven.compiler.target>
    <maven.compiler.release>${maven.compiler.target}</maven.compiler.release>
    <maven.compiler.testSource>21</maven.compiler.testSource>
    <maven.compiler.testTarget>${maven.compiler.testSource}</maven.compiler.testTarget>
    <maven.compiler.testRelease>${maven.compiler.testTarget}</maven.compiler.testRelease>
```

### Maven coordinates

```xml
<dependency>
  <groupId>io.github.jinahya</groupId>
  <artifactId>jinahya-bcprov</artifactId>
  <version>x.y.z</version> <!-- see the badge, above -->
</dependency>
```

## How to use

There are three layers of APIs you can choose to use.

### Jinahya\<CIPHER>Utils

The lowest layer, of this module, which is the closest to the Bouncy Castle's low-level lightweight API.

e.g.

```java
class Test {

    @Test
    void __() {
        final byte[] key = key();
        final byte[] iv = iv();
        final var cipher = new PaddedBufferedBlockCipher(
                CBCBlockCipher.newInstance(new AESEngine()),
                new PKCS7Padding()
        );
        final var params = new ParametersWithIV(
                new KeyParameter(key),
                iv
        );
        final byte[] plain = getPlain();
        // -----------------------------------------------------------------------------------------
        final byte[] encrypted;
        {
            cipher.init(true, params);
            final byte[] out = new byte[cipher.getOutputSize(plain.length)];
            final int outlen = JinahyaBufferedBlockCipherUtils.processBytesAndDoFinal(
                    cipher,
                    plain, 0, plain.length,
                    out, 0
            );
            encrypted = java.util.Arrays.copyOf(out, outlen);
        }
        final byte[] decrypted;
        {
            cipher.init(false, params);
            final byte[] out = new byte[cipher.getOutputSize(encrypted.length)];
            final int outlen = JinahyaBufferedBlockCipherUtils.processBytesAndDoFinal(
                    cipher,
                    encrypted, 0, encrypted.length,
                    out, 0
            );
            decrypted = java.util.Arrays.copyOf(out, outlen);
        }
    }
}
```

### Jinahya\<CIPHER>Crypto

The second-lowest layer, of this module, uses the `Jinahya<CIPHER>Utils` classes.

```java
class Test {

    @Test
    void __() {
        final byte[] key = key();
        final byte[] iv = iv();
        final var cipher = new PaddedBufferedBlockCipher(
                CBCBlockCipher.newInstance(new AESEngine()),
                new PKCS7Padding()
        );
        final var params = new ParametersWithIV(
                new KeyParameter(key),
                iv
        );
        final var plain = plain();
        // -----------------------------------------------------------------------------------------
        final var crypto = new JinahyuaBufferedBlockCipherCrypto(cipher, params); // !!!
        final byte[] encrypted = crypto.encrypt(plain);                           // !!!
        final byte[] decrypted = crypto.decrypt(encrypted);                       // !!!
    }
}
```

### Jinahya\<ALGORITHM>Utils

A miscellaneous algorithm-specific APIs use the `Jinahya<CIPHER>Crypto` classes.

```java
class Test {

    @Test
    void __() {
        final byte[] key = key();
        final byte[] iv = iv();
        final byte[] plain = plain();
        // -----------------------------------------------------------------------------------------
        final byte[] encrypted = JinahyaAESUtils.encrypt_CBC_PKCS7Padding(key, iv, plain);     // !!!
        final byte[] decrypted = JinahyaAESUtils.decrypt_CBC_PKCS7Padding(key, iv, encrypted); // !!!
    }
}
```

---

## Links

* [docs.oracle.com](https://docs.oracle.com)
    * [Java Platform, Standard Edition / Security Developer’s Guide](https://docs.oracle.com/en/java/javase/21/security/index.html)
* [Bouncy Castle – Open-source cryptographic APIs](https://www.bouncycastle.org/)
    * [Bouncy Castle Specification & Interoperability](https://www.bouncycastle.org/documentation/specification_interoperability/)
    * [Bouncy Castle for Java  Documentation](https://www.bouncycastle.org/documentation/documentation-java/)
        * [API Documentation](https://downloads.bouncycastle.org/java/docs/bcprov-jdk18on-javadoc/)
        * [org.bouncycastle.crypto.modes.CFBBlockCipher](https://downloads.bouncycastle.org/java/docs/bcprov-jdk18on-javadoc/org/bouncycastle/crypto/modes/CFBBlockCipher.html)
* [NIST](https://www.nist.gov/)
    * [NIST SP 800-38G Recommendation for Block Cipher Modes of Operation: Methods for Format-Preserving Encryption](chrome-extension://efaidnbmnnnibpcajpcglclefindmkaj/https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-38G.pdf)
* [IETF Datatracker](https://datatracker.ietf.org)
    * [RFC: 8017 / PKCS #1: RSA Cryptography Specifications Version 2.2](https://datatracker.ietf.org/doc/html/rfc8017)
* Wikipedia
    * [Block cipher mode of operation](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation)
        * [Cipher block chaining (CBC)](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Cipher_block_chaining_(CBC))
        * [CCM mode](https://en.wikipedia.org/wiki/CCM_mode)
        * [Cipher feedback (CFB)](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Cipher_feedback_(CFB))
    * [RSA (cryptosystem)](https://en.wikipedia.org/wiki/RSA_(cryptosystem))
        * [Operation](https://en.wikipedia.org/wiki/RSA_(cryptosystem)#Operation)
* [KISA 암호이용활성화](https://seed.kisa.or.kr)
    * [LEA](https://seed.kisa.or.kr/kisa/algorithm/EgovLeaInfo.do)
* GitHub
    * [The Bouncy Castle Crypto Package For Java](https://github.com/bcgit/bc-java)
        * [[QUESTION] ZeroBytePadding with Zero-Ending Input? #1871](https://github.com/bcgit/bc-java/issues/1871)
* [StackExchange](https://stackexchange.com)
    * [Is it possible to combine true streaming with AEAD?](https://crypto.stackexchange.com/questions/24876/is-it-possible-to-combine-true-streaming-with-aead)
    * [AES-GCM recommended IV size: Why 12 bytes?](https://crypto.stackexchange.com/q/41601/39160)
* https://data-make.tistory.com/
    * [[JAVA] KISA SEED CBC 암/복호화](https://data-make.tistory.com/759)
* [RetroTV's Dev Blog](https://blog.retrotv.dev/)
    * [[JAVA] Bouncy Castle로 LEA/ARIA 블록 암호화 하기](https://blog.retrotv.dev/bouncy-castlero-lea-aria-encryption/)