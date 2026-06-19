using System;
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using Konscious.Security.Cryptography;

namespace Zavrsni.Services
{
    public class CryptoService
    {
        // putanja za spasavanje kljuceva
        private static readonly string KeyStoreFolder = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            "AES-GCM-Encryption-Keys");

        private static readonly string KeyStorePath = Path.Combine(KeyStoreFolder, "vault.keystore");

        // vault.keystore format:
        // [4B magic "VKEY"] [16B salt] [12B nonce] [16B tag] [ciphertext od "VAULT_VERIFIED"]
        private static readonly byte[] Magic = Encoding.ASCII.GetBytes("VKEY");
        private static readonly byte[] VerificationPlaintext = Encoding.UTF8.GetBytes("VAULT_VERIFIED");

        private const int SALT_SIZE = 16;
        private const int NONCE_SIZE = 12;
        private const int TAG_SIZE = 16;

        // derivirani kljuc — private set jer samo CryptoService smije postavljati kljuc
        public byte[]? DerivedKey { get; private set; }

        // Derivacija KEK iz lozinke koristeci Argon2id (OWASP preporuka)
        // async jer Argon2id traje 1-2 sekunde sa 64MB memorije — ne smijemo blokirati UI thread
        public static async Task<byte[]> DeriveKekAsync(string password, byte[] salt)
        {
            // argon2 radi sa bajtovima ne tekstom
            byte[] pass = Encoding.UTF8.GetBytes(password);

            var argon2 = new Argon2id(pass)
            {
                DegreeOfParallelism = 4,
                MemorySize = 65536, // 64 MB
                Iterations = 3,
                Salt = salt
            };

            // GetBytesAsync ne blokira UI thread tokom derivacije
            byte[] kek = await argon2.GetBytesAsync(32); // AES-256 requires 32 bytes key
            return kek;
        }

        // Generisanje random salta
        public static byte[] GenerateSalt()
        {
            byte[] salt = new byte[SALT_SIZE];
            RandomNumberGenerator.Fill(salt);
            return salt;
        }

        // Provjera da li keystore postoji (da li je korisnik registrovan)
        public static bool IsRegistered()
        {
            return File.Exists(KeyStorePath);
        }

        // SINGLE-USER: brisanje svih starih podataka prilikom nove registracije
        // stari enkriptovani fajlovi postaju neupotrebljivi jer su enkriptovani starim kljucem
        private static void WipeOldUserData()
        {
            // obrisi keystore
            if (File.Exists(KeyStorePath)) File.Delete(KeyStorePath);

            // obrisi sve enkriptovane fajlove jer su enkriptovani starim kljucem koji vise ne postoji
            string encryptedFolder = EncryptionService.GetSecureStorageFolder();
            if (Directory.Exists(encryptedFolder))
            {
                foreach (string file in Directory.GetFiles(encryptedFolder, "*.enc"))
                {
                    File.Delete(file);
                }
            }
        }

        // Registracija — SINGLE-USER: nova registracija UVIJEK prebrisuje starog korisnika
        // vault.keystore: [4B magic] [16B salt] [12B nonce] [16B tag] [ciphertext]
        // enkriptujemo "VAULT_VERIFIED" sa deriviranim kljucem — pri loginu pokusamo dekriptovati
        public async Task<bool> Register(string password)
        {
            // ako postoji stari korisnik, obrisi sve njegove podatke
            if (IsRegistered())
            {
                Debug.WriteLine("Existing user found — wiping old data before re-registration.");
                WipeOldUserData();
            }

            byte[] salt = GenerateSalt();
            byte[] kek = await DeriveKekAsync(password, salt);

            // enkriptuj verifikacioni string sa deriviranim kljucem
            byte[] nonce = new byte[NONCE_SIZE];
            byte[] tag = new byte[TAG_SIZE];
            byte[] ciphertext = new byte[VerificationPlaintext.Length];
            RandomNumberGenerator.Fill(nonce);

            using var aes = new AesGcm(kek, TAG_SIZE);
            aes.Encrypt(nonce, VerificationPlaintext, ciphertext, tag);

            // spasi vault.keystore sa BinaryWriter
            if (!Directory.Exists(KeyStoreFolder))
            {
                Directory.CreateDirectory(KeyStoreFolder);
            }

            using var fs = new FileStream(KeyStorePath, FileMode.Create, FileAccess.Write, FileShare.None);
            using var writer = new BinaryWriter(fs);
            writer.Write(Magic);        // 4B magic "VKEY"
            writer.Write(salt);         // 16B salt
            writer.Write(nonce);        // 12B nonce
            writer.Write(tag);          // 16B tag
            writer.Write(ciphertext);   // ciphertext od "VAULT_VERIFIED"

            DerivedKey = kek;
            Debug.WriteLine("Registration successful — vault.keystore created.");
            return true;
        }

        // Login — ucitaj vault.keystore, deriviraj KEK, probaj dekriptovati verifikacioni string
        // ako dekriptovani plaintext == "VAULT_VERIFIED" onda je password ispravan
        public async Task<bool> Login(string password)
        {
            if (!IsRegistered())
            {
                Debug.WriteLine("No keystore found. User needs to register first.");
                return false;
            }

            // ucitaj vault.keystore sa BinaryReader
            using var fs = new FileStream(KeyStorePath, FileMode.Open, FileAccess.Read, FileShare.Read);
            using var reader = new BinaryReader(fs);

            byte[] magic = reader.ReadBytes(4);
            if (!magic.AsSpan().SequenceEqual(Magic))
            {
                Debug.WriteLine("Invalid keystore format — magic bytes do not match.");
                return false;
            }

            byte[] salt = reader.ReadBytes(SALT_SIZE);
            byte[] nonce = reader.ReadBytes(NONCE_SIZE);
            byte[] tag = reader.ReadBytes(TAG_SIZE);
            byte[] ciphertext = reader.ReadBytes(VerificationPlaintext.Length);

            // deriviraj KEK iz unesene lozinke i spasenog salta
            byte[] kek = await DeriveKekAsync(password, salt);

            // probaj dekriptovati — ako password nije ispravan AesGcm baca AuthenticationTagMismatchException
            byte[] decrypted = new byte[ciphertext.Length];
            try
            {
                using var aes = new AesGcm(kek, TAG_SIZE);
                aes.Decrypt(nonce, ciphertext, tag, decrypted);
            }
            catch (AuthenticationTagMismatchException)
            {
                // tag mismatch znaci da je password pogresan — kljuc se ne poklapa
                CryptographicOperations.ZeroMemory(kek);
                CryptographicOperations.ZeroMemory(decrypted);
                Debug.WriteLine("Invalid password — AES-GCM tag mismatch.");
                return false;
            }

            // dodatna provjera da dekriptovani plaintext odgovara ocekivanom stringu
            if (!decrypted.AsSpan().SequenceEqual(VerificationPlaintext))
            {
                CryptographicOperations.ZeroMemory(kek);
                CryptographicOperations.ZeroMemory(decrypted);
                Debug.WriteLine("Invalid password — verification string mismatch.");
                return false;
            }

            CryptographicOperations.ZeroMemory(decrypted);
            DerivedKey = kek;
            Debug.WriteLine("Login successful — key derived and loaded.");
            return true;
        }

        // potreban je public override ondeactivate iz razloga da se UKLONE IZ MEMORIJE KLJUCEVI!!!
        public void ClearSensitiveData()
        {
            if (DerivedKey != null)
            {
                CryptographicOperations.ZeroMemory(DerivedKey);
                DerivedKey = null;
            }
        }
    }
}
