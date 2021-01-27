# Crypto

Cryptography in Swift

## Package.swift

```swift
.package(url: "https://github.com/swift-stack/crypto.git", from: "fiber")
```

## SHA1

```swift
var sha1 = SHA1()
sha1.update(bytes)
let hash = sha1.final()
```

#### Convert to Array or String
```swift
_ = [UInt8](hash)
_ = String(hash)
```

#### Convenience extensions
```swift
let hash = bytes.sha1()
```

## UUID

```swift
_ = UUID().uuidStirng
_ = UUID(uuidStirng: "96888CEE-9705-490D-E38A-B407C8A9DA65")
```

## Acknowledgments

The implementation of SHA1 was ported from OpenSSL
