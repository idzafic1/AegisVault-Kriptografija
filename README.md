# AegisVault: Sigurni Trezor za Datoteke 🛡️

**AegisVault** (Aegis = štit) je desktop aplikacija bazirana na WPF-u i Caliburn.Micro frameworku, namijenjena sigurnom lokalnom čuvanju osjetljivih podataka pomoću modernih kriptografskih standarda.

> **Napomena:** Ovaj projekat je primarno razvijen u akademske svrhe kao praktični dio rada na temu: 
> *"Primjena kriptografskih algoritama u zaštiti osjetljivih podataka"*.

## Ključne funkcionalnosti
- **Single-User arhitektura:** Aplikacija je dizajnirana za jednog korisnika po sistemu. Registracijom novog korisnika automatski se brišu stari ključevi i enkriptovane datoteke kako bi se osigurala maksimalna sigurnost.
- **Argon2id derivacija ključa:** Lozinka korisnika prolazi kroz snažnu Argon2id derivaciju (prema OWASP preporukama) kako bi se osigurao 256-bitni ključ otporan na *brute-force* napade (Memory: 64MB, Parallelism: 4, Iterations: 3).
- **AES-GCM (Galois/Counter Mode) enkripcija:** Za enkripciju samih fajlova koristi se autentificirana AES-GCM enkripcija, koja garantira i tajnost i integritet podataka. Aplikacija enkriptuje fajlove u *chunkovima* od 4MB uz jedinstveni Nonce i Tag za svaki blok, što omogućava sigurnu obradu velikih datoteka bez opterećenja RAM memorije.
- **Sigurno brisanje iz RAM-a:** Izvučeni kriptografski ključevi čuvaju se u radnoj memoriji isključivo dok je ekran trezora otvoren. Prilikom gašenja sesije, memorija se nulira pomoću `CryptographicOperations.ZeroMemory`, sprječavajući napade na izvođenje (tzv. *cold boot* napade).

## Tehnički stack
- **Jezik:** C# (.NET 10)
- **UI Framework:** WPF uz Caliburn.Micro za MVVM arhitekturu
- **Kriptografija:** 
  - Ugrađene .NET klase za `AesGcm` i sigurno upravljanje memorijom.
  - [Konscious.Security.Cryptography.Argon2](https://github.com/kmaragon/Konscious.Security.Cryptography) za derivaciju ključeva.

## Upotreba
1. **Registracija:** Prilikom prvog pokretanja (ili prelaska na novog korisnika), generiše se unikatni *salt*, a iz unesene lozinke derivira se Master ključ. Verifikacioni metapodaci se spašavaju u lokalni `vault.keystore`.
2. **Login:** Pri loginu, aplikacija derivira ključ pomoću pohranjenog salta i unesene lozinke, i potom ga testira pokušajem dekripcije verifikacionog bloka u keystore-u.
3. **Trezor (Vault):** Unutar trezora, korisnici mogu birati datoteke koje žele osigurati. Rezultujuće `.enc` datoteke pohranjuju se na definisanu sigurnu lokaciju u `%AppData%`. 

## Struktura `vault.keystore`
Keystore fajl koristi binarni format za pouzdanost i brzinu učitavanja:
`[4B magic "VKEY"] [16B salt] [12B nonce] [16B tag] [Encrypted "VAULT_VERIFIED" string]`

## Akademski kontekst
Cilj ovog projekta je demonstracija pravilne i sigurne primjene *state-of-the-art* kriptografskih principa u praksi. Kroz upotrebu naprednih koncepata poput AEAD (Authenticated Encryption with Associated Data) shema, zaštite radne memorije i Memory-Hard funkcija za ublažavanje offline napada, aplikacija odgovara na sve moderne sigurnosne izazove u lokalnoj zaštiti osjetljivih fajlova.
