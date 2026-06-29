# AegisVault: Sigurni Trezor za Datoteke 🛡️

**AegisVault** (Aegis = stit) je desktop aplikacija bazirana na WPF-u i Caliburn.Micro frameworku, namijenjena sigurnom lokalnom cuvanju osjetljivih podataka pomocu post-kvantnih i klasicnih hibridnih kriptografskih standarda.

> **Napomena:** Ovaj projekat je primarno razvijen u akademske svrhe kao prakticni dio rada na temu: 
> *"Primjena kriptografskih algoritama u zastiti osjetljivih podataka"*.

## Kljucne funkcionalnosti
- **Hibridna PQC Arhitektura:** Aplikacija koristi najnovije post-kvantne (PQC) mehanizme iz .NET 10 okruzenja: **ML-KEM-768** za asimetricnu razmjenu i enkapsulaciju kljuceva po fajlu, te **ML-DSA-65** za validaciju digitalnih potpisa (*Encrypt-then-Sign*).
- **AES-GCM Streaming:** Za samu enkripciju sadrzaja fajlova koristi se autentificirana AES-256-GCM enkripcija. Aplikacija enkriptuje fajlove u *chunkovima* od 4MB uz jedinstveni Nonce i Tag za svaki blok, sto omogucava sigurnu obradu velikih datoteka (streaming uz ArrayPool) uz O(1) RAM potrosnju (~8-12 MB maksimum).
- **Argon2id derivacija (KDF):** Lozinka korisnika (KEK - Key Encryption Key) derivira se pomocu Argon2id algoritma otpornog na *brute-force* napade (Memory: 64MB, Parallelism: 4, Iterations: 3). Izvedeni kljuc se koristi iskljucivo za dekripciju ML-KEM i ML-DSA privatnih kljuceva iz keystore-a.
- **Pinovanje i zeriranje u memoriji:** Dekriptovani privatni PQC kljucevi (`sk_kem`, `sk_sig`) se **pinuju** u memoriji pomocu `GCHandle` mehanizma (kako bi se sprijecilo da ih Garbage Collector premjesti i ostavi kopiju). Prilikom gasenja sesije, memorija se direktno prepisuje nulama koristeci `CryptographicOperations.ZeroMemory` prije nego sto se oslobodi GCHandle, sto minimizira izlozenost *cold boot* napadima.
- **Single-User dizajn:** Aplikacija je dizajnirana za jednog korisnika po sistemu. Registracijom novog korisnika automatski se brisu stari kljucevi i enkriptovane datoteke kako bi se osigurala maksimalna sigurnost.

## Tehnicki stack
- **Jezik:** C# (.NET 10)
- **UI Framework:** WPF uz Caliburn.Micro za MVVM arhitekturu
- **Kriptografija:** 
  - Ugradjene .NET 10 klase za `MLKem`, `MLDsa`, `AesGcm` i upravljanje memorijom.
  - [Konscious.Security.Cryptography.Argon2](https://github.com/kmaragon/Konscious.Security.Cryptography) za derivaciju glavnog kljuca (KEK).

## Upotreba
1. **Registracija:** Prilikom prvog pokretanja (ili prelaska na novog korisnika), generise se PQC par kljuceva (ML-KEM-768 i ML-DSA-65). Njihovi privatni dijelovi se stite pomocu KEK-a (dobijenog Argon2id derivacijom korisnicke lozinke) i spremaju u binarni `vault.keystore`.
2. **Login:** Pri loginu, derivira se KEK. Pomocu AES-GCM-a se otkljucavaju i ucitavaju ML-KEM i ML-DSA kljucevi u radnu memoriju gdje se istog trenutka pinuju, dok se KEK brise.
3. **Trezor (Vault):** Unutar trezora, datoteke se mogu osigurati klikom na Encrypt. Generise se Data Encryption Key (DEK) koristenjem ML-KEM enkapsulacije za taj specificni fajl. Nakon AES-GCM enkripcije sadrzaja, cijeli izlaz se potpisuje koristeci ML-DSA-65. Pri dekripciji, **potpis se strogo provjerava prije dekapsulacije** kako bi se izbjeglo curenje privatnog KEM kljuca preko *Chosen Ciphertext* (CCA) napada.

## Struktura `vault.keystore`
Keystore fajl je prilagodjeni binarni format optimizovan za brzinu i sigurnost:
```
[4B magic "VKEY"] [16B salt] 
[12B nonce] [16B tag] [Encrypted "VAULT_VERIFIED" string]
[12B nonce] [16B tag] [4B len] [Encrypted sk_kem]
[12B nonce] [16B tag] [4B len] [Encrypted sk_sig]
[4B len] [Plaintext pk_kem]
[4B len] [Plaintext pk_dsa]
```

## Akademski kontekst
Cilj ovog projekta je demonstracija prelaznog hibridnog (klasicnog + kvantno otpornog) pristupa u praksi. Kroz *Encrypt-then-Sign* paradigmu (AES-256 + ML-DSA), *Key Encapsulation* mehanizme (ML-KEM) per-file, zastitu memorijskog curenja uz *GCHandle* pinning i *Memory-Hard* KDF funkcije (Argon2id), aplikacija anticipira sigurnosne zahtjeve predstojeceg post-kvantnog doba.

