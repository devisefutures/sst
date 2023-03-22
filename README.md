# Secure Signing Tool
A command line tool which should be able to communicate with and use HSM's locally to execute signing operations and return the signature in Base64 format. The first version should support the Pure Ed25519 implementation. Hash algorithm should be set to NONE.

# Install
Compile with:
> mvn compile

Package jar with:
> mvn package
(Resulting jar in /target folder. Use the jar with dependencies)

Clean with:
> mvn clean

# Load PKCS11 Configuration
Load the configuration before running jar.
> export CS_PKCS11_R2_CFG=/etc/utimaco/cs_pkcs11_R2.cfg

# Examples
Version:
```java -jar sst.jar version```

Help Screen:
```java -jar sst.jar -h```

List Private Keys:
```java -jar sst.jar listKeys -hsm_slot 3 -hsm_slot_pwd 1234 -p11library ”/etc/utimaco/libcs2_pkcs11.so“```

Sign file:
```java -jar sst.jar sign -hsm_slot 3 -hsm_slot_pwd 1234 -p11library ”/etc/utimaco/libcs2_pkcs11.so“ -key_ref 6 -hash_algorithm NONE -path ”/home/user/Documents/ED25519IssuingCA-chain.pem“```

Sign file Verbose:
```java -jar sst.jar sign -verbose -hsm_slot 3 -hsm_slot_pwd 1234 -p11library ”/etc/utimaco/libcs2_pkcs11.so“ -key_ref 6 -hash_algorithm NONE -path ”/home/user/Documents/ED25519IssuingCA-chain.pem“```
