#pragma warning disable SYSLIB5006 // ML-DSA is experimental in .NET 10

using System;
using System.Buffers.Binary;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using Konscious.Security.Cryptography;

namespace Zavrsni.Services
{
    public class CryptoService
    {
        private static readonly string KeyStoreFolder = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            "FileVaultKeys");

        private static readonly string KeyStorePath = Path.Combine(KeyStoreFolder, "vault.keystore");

        // vault.keystore binarni format:
        // [4B magic "VKEY"]                                           plaintext
        // [16B salt]                                                  plaintext
        // [12B nonce][16B tag][14B ciphertext]      verification       ciphertext
        // [12B nonce][16B tag][4B len][N B ciphertext]  sk_kem          ciphertext
        // [12B nonce][16B tag][4B len][M B ciphertext]  sk_sig          ciphertext
        // [4B len][P B pk_kem]                                         plaintext
        // [4B len][Q B pk_dsa]                                         plaintext
        private static readonly byte[] Magic = Encoding.ASCII.GetBytes("VKEY");
        private static readonly byte[] VerificationPlaintext = Encoding.UTF8.GetBytes("VAULT_VERIFIED");

        private const int SALT_SIZE = 16;
        private const int NONCE_SIZE = 12;
        private const int TAG_SIZE = 16;

        public byte[]? DerivedKey { get; private set; }

        // Sesijski PQC kljucevi — zive od Login() do ClearSensitiveData()
        // sk_kem/sk_sig su pinovani jer GC inace moze premjestiti niz u memoriji
        // ostavljajuci kopiju na staroj adresi koju ZeroMemory ne bi obrisao
        private MLKem? _kemDecapsulationKey;
        private MLDsa? _dsaSigningKey;
        private byte[]? _pkKemBytes;
        private byte[]? _pkDsaBytes;
        private byte[]? _skKemBytes;
        private byte[]? _skSigBytes;
        private GCHandle _skKemHandle;
        private GCHandle _skSigHandle;
        private bool _skKemPinned;
        private bool _skSigPinned;

        // True nakon uspjesnog Login(), false nakon ClearSensitiveData()
        public bool IsReady => _kemDecapsulationKey != null && _dsaSigningKey != null;

        // Argon2id KDF - CPU-bound, ~1-2s sa 64MB memorije.
        // GetBytesAsync interno koristi Task.Run
        public static async Task<byte[]> DeriveKekAsync(string password, byte[] salt)
        {
            byte[] pass = Encoding.UTF8.GetBytes(password);

            var argon2 = new Argon2id(pass)
            {
                DegreeOfParallelism = 4,
                MemorySize = 65536,
                Iterations = 3,
                Salt = salt
            };

            byte[] kek = await argon2.GetBytesAsync(32).ConfigureAwait(false);
            return kek;
        }

        public static byte[] GenerateSalt()
        {
            byte[] salt = new byte[SALT_SIZE];
            RandomNumberGenerator.Fill(salt);
            return salt;
        }

        public static bool IsRegistered() => File.Exists(KeyStorePath);

        private static void WipeOldUserData()
        {
            if (File.Exists(KeyStorePath)) File.Delete(KeyStorePath);

            string encryptedFolder = EncryptionService.GetSecureStorageFolder();
            if (Directory.Exists(encryptedFolder))
            {
                foreach (string file in Directory.GetFiles(encryptedFolder, "*.enc"))
                    File.Delete(file);
            }
        }

        // REGISTER - generisanje PQC kljuceva + enkriptovanje sa KEK
        public async Task<bool> Register(string password)
        {
            if (IsRegistered())
            {
                Debug.WriteLine("Existing user found — wiping old data before re-registration.");
                WipeOldUserData();
            }

            byte[] salt = GenerateSalt();
            byte[] kek = await DeriveKekAsync(password, salt).ConfigureAwait(false);

            // Verifikacioni string - sluzi za provjeru passworda pri Login()
            byte[] nonce_verification = new byte[NONCE_SIZE];
            byte[] tag_verification = new byte[TAG_SIZE];
            byte[] ciphertext_verification = new byte[VerificationPlaintext.Length];
            RandomNumberGenerator.Fill(nonce_verification);

            using var aesForVerification = new AesGcm(kek, TAG_SIZE);
            aesForVerification.Encrypt(nonce_verification, VerificationPlaintext, ciphertext_verification, tag_verification);

            // MLKem/MLDsa key generation je CPU-bound
            // Task.Run signalizira da ovo pripada thread poolu
            var (kemKey, dsaKey) = await Task.Run(() =>
            {
                var kem = MLKem.GenerateKey(MLKemAlgorithm.MLKem768);
                var dsa = MLDsa.GenerateKey(MLDsaAlgorithm.MLDsa65);
                return (kem, dsa);
            }).ConfigureAwait(false);

            using (kemKey)
            using (dsaKey)
            {

                byte[] nonce_kem = new byte[NONCE_SIZE];
                byte[] tag_kem = new byte[TAG_SIZE];
                byte[] skKem = kemKey.ExportDecapsulationKey();
                byte[] encrypted_sk_kem = new byte[skKem.Length];
                RandomNumberGenerator.Fill(nonce_kem);

                byte[] pkKem = kemKey.ExportEncapsulationKey();
                using (var aesForKem = new AesGcm(kek, TAG_SIZE))
                    aesForKem.Encrypt(nonce_kem, skKem, encrypted_sk_kem, tag_kem);
                CryptographicOperations.ZeroMemory(skKem);

                byte[] pkDsa = dsaKey.ExportSubjectPublicKeyInfo();

                byte[] nonce_dsa = new byte[NONCE_SIZE];
                byte[] tag_dsa = new byte[TAG_SIZE];
                byte[] skSig = dsaKey.ExportPkcs8PrivateKey();
                byte[] encrypted_sk_sig = new byte[skSig.Length];
                RandomNumberGenerator.Fill(nonce_dsa);

                using (var aesForDsa = new AesGcm(kek, TAG_SIZE))
                    aesForDsa.Encrypt(nonce_dsa, skSig, encrypted_sk_sig, tag_dsa);
                CryptographicOperations.ZeroMemory(skSig);

                // Sastavi cijeli keystore u jedan bafer, pa jedan WriteAsync poziv
                if (!Directory.Exists(KeyStoreFolder))
                    Directory.CreateDirectory(KeyStoreFolder);

                int totalSize = Magic.Length + SALT_SIZE
                    + NONCE_SIZE + TAG_SIZE + VerificationPlaintext.Length
                    + NONCE_SIZE + TAG_SIZE + 4 + encrypted_sk_kem.Length
                    + NONCE_SIZE + TAG_SIZE + 4 + encrypted_sk_sig.Length
                    + 4 + pkKem.Length
                    + 4 + pkDsa.Length;

                byte[] buf = new byte[totalSize];
                int pos = 0;

                void WriteBytes(byte[] data) { data.CopyTo(buf.AsSpan(pos)); pos += data.Length; }
                void WriteInt32(int value) { BinaryPrimitives.WriteInt32LittleEndian(buf.AsSpan(pos), value); pos += 4; }

                WriteBytes(Magic);
                WriteBytes(salt);
                WriteBytes(nonce_verification);
                WriteBytes(tag_verification);
                WriteBytes(ciphertext_verification);

                WriteBytes(nonce_kem);
                WriteBytes(tag_kem);
                WriteInt32(encrypted_sk_kem.Length);
                WriteBytes(encrypted_sk_kem);

                WriteBytes(nonce_dsa);
                WriteBytes(tag_dsa);
                WriteInt32(encrypted_sk_sig.Length);
                WriteBytes(encrypted_sk_sig);

                WriteInt32(pkKem.Length);
                WriteBytes(pkKem);
                WriteInt32(pkDsa.Length);
                WriteBytes(pkDsa);

                using var fs = new FileStream(KeyStorePath, FileMode.Create, FileAccess.Write,
                    FileShare.None, 4096, FileOptions.Asynchronous);
                await fs.WriteAsync(buf.AsMemory(0, totalSize), CancellationToken.None).ConfigureAwait(false);
                await fs.FlushAsync(CancellationToken.None).ConfigureAwait(false);
            }

            // KEK je KRATKOTRAJAN — zeriran cim zavrsi upis. Ne cuva se kao polje klase
            // jer u PQC flowu DEK dolazi per-file iz ML-KEM, ne iz deriviranog kljuca.
            CryptographicOperations.ZeroMemory(kek);
            DerivedKey = null;

            Debug.WriteLine("Registration successful — vault.keystore created with PQC keys.");
            return true;
        }

        public async Task<bool> Login(string password)
        {
            if (!IsRegistered())
            {
                Debug.WriteLine("No keystore found. User needs to register first.");
                return false;
            }

            // Citaj cijeli keystore u memoriju jednim ReadAsync pozivom
            byte[] data;
            using (var fs = new FileStream(KeyStorePath, FileMode.Open, FileAccess.Read,
                FileShare.Read, 4096, FileOptions.Asynchronous | FileOptions.SequentialScan))
            {
                data = new byte[(int)fs.Length];
                await ReadExactAsync(fs, data, data.Length, CancellationToken.None).ConfigureAwait(false);
            }

            int pos = 0;
            // da olaksamo sebi zivot malo
            Span<byte> ReadSpan(int count) { var s = data.AsSpan(pos, count); pos += count; return s; }
            int ReadInt32() { int v = BinaryPrimitives.ReadInt32LittleEndian(data.AsSpan(pos)); pos += 4; return v; }

            // Magic
            if (!ReadSpan(4).SequenceEqual(Magic))
            {
                Debug.WriteLine("Invalid keystore format — magic bytes do not match.");
                return false;
            }

            // password true?
            byte[] salt = ReadSpan(SALT_SIZE).ToArray();
            byte[] nonce_v = ReadSpan(NONCE_SIZE).ToArray();
            byte[] tag_v = ReadSpan(TAG_SIZE).ToArray();
            byte[] ct_v = ReadSpan(VerificationPlaintext.Length).ToArray();

            byte[] kek = await DeriveKekAsync(password, salt).ConfigureAwait(false);

            byte[] decrypted = new byte[ct_v.Length];
            try
            {
                using var aes = new AesGcm(kek, TAG_SIZE);
                aes.Decrypt(nonce_v, ct_v, tag_v, decrypted);
            }
            catch (AuthenticationTagMismatchException)
            {
                CryptographicOperations.ZeroMemory(kek);
                CryptographicOperations.ZeroMemory(decrypted);
                Debug.WriteLine("Invalid password — AES-GCM tag mismatch.");
                return false;
            }

            if (!decrypted.AsSpan().SequenceEqual(VerificationPlaintext))
            {
                CryptographicOperations.ZeroMemory(kek);
                CryptographicOperations.ZeroMemory(decrypted);
                Debug.WriteLine("Invalid password — verification string mismatch.");
                return false;
            }
            CryptographicOperations.ZeroMemory(decrypted);

            // Citaj enkriptovane privatne kljuceve
            byte[] nonce_kem = ReadSpan(NONCE_SIZE).ToArray();
            byte[] tag_kem = ReadSpan(TAG_SIZE).ToArray();
            int len_sk_kem = ReadInt32();
            byte[] enc_sk_kem = ReadSpan(len_sk_kem).ToArray();

            byte[] nonce_dsa = ReadSpan(NONCE_SIZE).ToArray();
            byte[] tag_dsa = ReadSpan(TAG_SIZE).ToArray();
            int len_sk_dsa = ReadInt32();
            byte[] enc_sk_sig = ReadSpan(len_sk_dsa).ToArray();

            int len_pk_kem = ReadInt32();
            byte[] pk_kem = ReadSpan(len_pk_kem).ToArray();

            int len_pk_dsa = ReadInt32();
            byte[] pk_dsa = ReadSpan(len_pk_dsa).ToArray();

 
            // sk_kem: dekriptuj → pinuj ODMAH, prije nego se predje na sk_sig
            byte[] skKemPlain = new byte[len_sk_kem];
            using (var aesKem = new AesGcm(kek, TAG_SIZE))
                aesKem.Decrypt(nonce_kem, enc_sk_kem, tag_kem, skKemPlain);

            _skKemBytes = skKemPlain;
            _skKemHandle = GCHandle.Alloc(_skKemBytes, GCHandleType.Pinned);
            _skKemPinned = true;

            // sk_sig: dekriptuj → pinuj ODMAH — sk_kem je vec siguran u ovom trenutku
            byte[] skSigPlain = new byte[len_sk_dsa];
            using (var aesDsa = new AesGcm(kek, TAG_SIZE))
                aesDsa.Decrypt(nonce_dsa, enc_sk_sig, tag_dsa, skSigPlain);

            _skSigBytes = skSigPlain;
            _skSigHandle = GCHandle.Alloc(_skSigBytes, GCHandleType.Pinned);
            _skSigPinned = true;

            _kemDecapsulationKey = MLKem.ImportDecapsulationKey(MLKemAlgorithm.MLKem768, _skKemBytes);
            _dsaSigningKey = MLDsa.ImportPkcs8PrivateKey(_skSigBytes);

            _pkKemBytes = pk_kem;
            _pkDsaBytes = pk_dsa;

            CryptographicOperations.ZeroMemory(kek);
            DerivedKey = null;

            Debug.WriteLine("Login successful — PQC keys loaded and pinned for session.");
            return true;
        }

        private static async Task ReadExactAsync(Stream s, byte[] buf, int count, CancellationToken ct)
        {
            int read = await s.ReadAtLeastAsync(buf.AsMemory(0, count), count, false, ct)
                .ConfigureAwait(false);
            if (read < count)
                throw new InvalidDataException($"Corrupted keystore — expected {count}B, got {read}B.");
        }



        /// ML-KEM encapsulacija — kreira per-file DEK
        /// dekPlaintext je KRATKOTRAJAN — pozivatelj MORA zerirati nakon upotrebe
        // CryptoService — vrati i handle, ne samo niz:
        public (byte[] dekPlaintext, byte[] dekCiphertext, GCHandle dekHandle) EncapsulateForFile()
        {
            if (_pkKemBytes == null)
                throw new InvalidOperationException("PQC keys not loaded. Login first.");

            using var senderKeys = MLKem.ImportEncapsulationKey(MLKemAlgorithm.MLKem768, _pkKemBytes);
            senderKeys.Encapsulate(out byte[] dekCiphertext, out byte[] dekPlaintext);

            var handle = GCHandle.Alloc(dekPlaintext, GCHandleType.Pinned);  // pinuj PRIJE return-a sto je sigurno sigurno je
            // uistinu GC moze ovo samo pomjereiti nebitno koliko kratko ovo trajalo moze se u random trenucima smao aktivirati
            return (dekPlaintext, dekCiphertext, handle);
        }

        /// ML-KEM decapsulacija — rekonstruise per-file DEK
        public (byte[] dekPlaintext, GCHandle dekHandle) DecapsulateForFile(byte[] dekCiphertext)
        {
            if (_kemDecapsulationKey == null)
                throw new InvalidOperationException("PQC keys not loaded. Login first.");

            byte[] dekPlaintext = _kemDecapsulationKey.Decapsulate(dekCiphertext);
            var handle = GCHandle.Alloc(dekPlaintext, GCHandleType.Pinned); // pinuj PRIJE return-a

            return (dekPlaintext, handle);
        }

        /// ML-DSA-65 potpis (Encrypt-then-Sign)
        public byte[] SignData(byte[] data)
        {
            if (_dsaSigningKey == null)
                throw new InvalidOperationException("PQC keys not loaded. Login first.");

            return _dsaSigningKey.SignData(data, null);
        }

        /// ML-DSA-65 verifikacija MORA se pozvati PRIJE DecapsulateForFile
        /// privatni KEM kljuc se ne koristi za fajlove sa nevalidnim potpisom
        public bool VerifySignature(byte[] data, byte[] signature)
        {
            if (_pkDsaBytes == null)
                throw new InvalidOperationException("PQC keys not loaded. Login first.");

            using var publicKey = MLDsa.ImportSubjectPublicKeyInfo(_pkDsaBytes);
            return publicKey.VerifyData(data, signature, null);
        }

        // Iznimno bitna redoslijed ZeroMemory pa Free
        public void ClearSensitiveData()
        {
            if (DerivedKey != null)
            {
                CryptographicOperations.ZeroMemory(DerivedKey);
                DerivedKey = null;
            }

            if (_skKemPinned && _skKemBytes != null)
            {
                CryptographicOperations.ZeroMemory(_skKemBytes);
                _skKemHandle.Free();
                _skKemPinned = false;
                _skKemBytes = null;
            }

            if (_skSigPinned && _skSigBytes != null)
            {
                CryptographicOperations.ZeroMemory(_skSigBytes);
                _skSigHandle.Free();
                _skSigPinned = false;
                _skSigBytes = null;
            }

            _kemDecapsulationKey?.Dispose();
            _kemDecapsulationKey = null;

            _dsaSigningKey?.Dispose();
            _dsaSigningKey = null;

            _pkKemBytes = null;
            _pkDsaBytes = null;

            Debug.WriteLine("ClearSensitiveData — all PQC keys zeroed, pins freed, instances disposed.");
        }
    }
}
