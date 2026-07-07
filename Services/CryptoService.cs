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
        // ── Konstante i staticka polja 
        private const int SALT_SIZE = 16;
        private const int NONCE_SIZE = 12;
        private const int TAG_SIZE = 16;

        private static readonly string DefaultKeyStoreFolder = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            "FileVaultKeys");

        private static readonly string DefaultKeyStorePath = Path.Combine(DefaultKeyStoreFolder, "vault.keystore");

        internal static string? _testKeyStoreFolder;
        internal static string? _testKeyStorePath;

        // vault.keystore format:
        // [4B magic "VKEY"]
        // [16B salt]
        // [12B nonce][16B tag][14B ciphertext]      verification
        // [12B nonce][16B tag][4B len][N B ciphertext]  sk_kem
        // [12B nonce][16B tag][4B len][M B ciphertext]  sk_sig
        // [4B len][P B pk_kem]
        // [4B len][Q B pk_dsa]
        private static readonly byte[] Magic = Encoding.ASCII.GetBytes("VKEY");
        private static readonly byte[] VerificationPlaintext = Encoding.UTF8.GetBytes("VAULT_VERIFIED");

        // ── Privatna polja (Sesijski kljucevi) 
        // Sk_kem i sk_sig se pinuju kako bi sprijecili GC da ih premjesti u memoriji,
        // sto bi ostavilo kopiju kljuca na staroj adresi koju ZeroMemory ne bi dohvatio.
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

        private static string KeyStoreFolder => _testKeyStoreFolder ?? DefaultKeyStoreFolder;
        private static string KeyStorePath => _testKeyStorePath ?? DefaultKeyStorePath;

        public byte[]? DerivedKey { get; private set; }

        public bool IsReady => _kemDecapsulationKey != null && _dsaSigningKey != null;

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

            return await argon2.GetBytesAsync(32).ConfigureAwait(false);
        }

        public static byte[] GenerateSalt()
        {
            byte[] salt = new byte[SALT_SIZE];
            RandomNumberGenerator.Fill(salt);
            return salt;
        }

        public static bool IsRegistered() => File.Exists(KeyStorePath);

        public async Task<bool> RegisterAsync(string password)
        {
            if (IsRegistered())
            {
                Debug.WriteLine("Existing user found — wiping old data before re-registration.");
                WipeOldUserData();
            }

            byte[] salt = GenerateSalt();
            byte[] kek = await DeriveKekAsync(password, salt).ConfigureAwait(false);

            byte[] nonceVerification = new byte[NONCE_SIZE];
            byte[] tagVerification = new byte[TAG_SIZE];
            byte[] ciphertextVerification = new byte[VerificationPlaintext.Length];
            RandomNumberGenerator.Fill(nonceVerification);

            using var aesForVerification = new AesGcm(kek, TAG_SIZE);
            aesForVerification.Encrypt(nonceVerification, VerificationPlaintext, ciphertextVerification, tagVerification);

            // MLKem/MLDsa generisanje kljuceva je CPU-bound, Task.Run ga prebacuje na thread pool
            var (kemKey, dsaKey) = await Task.Run(() =>
            {
                var kem = MLKem.GenerateKey(MLKemAlgorithm.MLKem768);
                var dsa = MLDsa.GenerateKey(MLDsaAlgorithm.MLDsa65);
                return (kem, dsa);
            }).ConfigureAwait(false);

            using (kemKey)
            using (dsaKey)
            {
                byte[] nonceKem = new byte[NONCE_SIZE];
                byte[] tagKem = new byte[TAG_SIZE];
                byte[] skKem = kemKey.ExportDecapsulationKey();
                byte[] encryptedSkKem = new byte[skKem.Length];
                RandomNumberGenerator.Fill(nonceKem);

                byte[] pkKem = kemKey.ExportEncapsulationKey();
                using (var aesForKem = new AesGcm(kek, TAG_SIZE))
                    aesForKem.Encrypt(nonceKem, skKem, encryptedSkKem, tagKem);
                CryptographicOperations.ZeroMemory(skKem);

                byte[] pkDsa = dsaKey.ExportSubjectPublicKeyInfo();

                byte[] nonceDsa = new byte[NONCE_SIZE];
                byte[] tagDsa = new byte[TAG_SIZE];
                byte[] skSig = dsaKey.ExportPkcs8PrivateKey();
                byte[] encryptedSkSig = new byte[skSig.Length];
                RandomNumberGenerator.Fill(nonceDsa);

                using (var aesForDsa = new AesGcm(kek, TAG_SIZE))
                    aesForDsa.Encrypt(nonceDsa, skSig, encryptedSkSig, tagDsa);
                CryptographicOperations.ZeroMemory(skSig);

                if (!Directory.Exists(KeyStoreFolder))
                    Directory.CreateDirectory(KeyStoreFolder);

                int totalSize = Magic.Length + SALT_SIZE
                    + NONCE_SIZE + TAG_SIZE + VerificationPlaintext.Length
                    + NONCE_SIZE + TAG_SIZE + 4 + encryptedSkKem.Length
                    + NONCE_SIZE + TAG_SIZE + 4 + encryptedSkSig.Length
                    + 4 + pkKem.Length
                    + 4 + pkDsa.Length;

                byte[] buf = new byte[totalSize];
                int pos = 0;

                void WriteBytes(byte[] data) { data.CopyTo(buf.AsSpan(pos)); pos += data.Length; }
                void WriteInt32(int value) { BinaryPrimitives.WriteInt32LittleEndian(buf.AsSpan(pos), value); pos += 4; }

                WriteBytes(Magic);
                WriteBytes(salt);
                WriteBytes(nonceVerification);
                WriteBytes(tagVerification);
                WriteBytes(ciphertextVerification);

                WriteBytes(nonceKem);
                WriteBytes(tagKem);
                WriteInt32(encryptedSkKem.Length);
                WriteBytes(encryptedSkKem);

                WriteBytes(nonceDsa);
                WriteBytes(tagDsa);
                WriteInt32(encryptedSkSig.Length);
                WriteBytes(encryptedSkSig);

                WriteInt32(pkKem.Length);
                WriteBytes(pkKem);
                WriteInt32(pkDsa.Length);
                WriteBytes(pkDsa);

                using var fs = new FileStream(KeyStorePath, FileMode.Create, FileAccess.Write,
                    FileShare.None, 4096, FileOptions.Asynchronous);
                await fs.WriteAsync(buf.AsMemory(0, totalSize), CancellationToken.None).ConfigureAwait(false);
                await fs.FlushAsync(CancellationToken.None).ConfigureAwait(false);
            }

            // KEK se zerira odmah, jer PQC tok obezbjedjuje DEK po fajlu iz ML-KEM
            CryptographicOperations.ZeroMemory(kek);
            DerivedKey = null;

            Debug.WriteLine("Registration successful — vault.keystore created with PQC keys.");
            return true;
        }

        public async Task<bool> LoginAsync(string password)
        {
            if (!IsRegistered())
            {
                Debug.WriteLine("No keystore found. User needs to register first.");
                return false;
            }

            byte[] data;
            using (var fs = new FileStream(KeyStorePath, FileMode.Open, FileAccess.Read,
                FileShare.Read, 4096, FileOptions.Asynchronous | FileOptions.SequentialScan))
            {
                data = new byte[(int)fs.Length];
                await ReadExactAsync(fs, data, data.Length, CancellationToken.None).ConfigureAwait(false);
            }

            int pos = 0;
            Span<byte> ReadSpan(int count) { var s = data.AsSpan(pos, count); pos += count; return s; }
            int ReadInt32() { int v = BinaryPrimitives.ReadInt32LittleEndian(data.AsSpan(pos)); pos += 4; return v; }

            if (!ReadSpan(4).SequenceEqual(Magic))
            {
                Debug.WriteLine("Invalid keystore format — magic bytes do not match.");
                return false;
            }

            byte[] salt = ReadSpan(SALT_SIZE).ToArray();
            byte[] nonceV = ReadSpan(NONCE_SIZE).ToArray();
            byte[] tagV = ReadSpan(TAG_SIZE).ToArray();
            byte[] ctV = ReadSpan(VerificationPlaintext.Length).ToArray();

            byte[] kek = await DeriveKekAsync(password, salt).ConfigureAwait(false);

            byte[] decrypted = new byte[ctV.Length];
            try
            {
                using var aes = new AesGcm(kek, TAG_SIZE);
                aes.Decrypt(nonceV, ctV, tagV, decrypted);
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

            byte[] nonceKem = ReadSpan(NONCE_SIZE).ToArray();
            byte[] tagKem = ReadSpan(TAG_SIZE).ToArray();
            int lenSkKem = ReadInt32();
            byte[] encSkKem = ReadSpan(lenSkKem).ToArray();

            byte[] nonceDsa = ReadSpan(NONCE_SIZE).ToArray();
            byte[] tagDsa = ReadSpan(TAG_SIZE).ToArray();
            int lenSkDsa = ReadInt32();
            byte[] encSkSig = ReadSpan(lenSkDsa).ToArray();

            int lenPkKem = ReadInt32();
            byte[] pkKem = ReadSpan(lenPkKem).ToArray();

            int lenPkDsa = ReadInt32();
            byte[] pkDsa = ReadSpan(lenPkDsa).ToArray();

            // Dekripcija se odvija kljuc po kljuc, uz trenutno pinovanje u memoriji
            byte[] skKemPlain = new byte[lenSkKem];
            using (var aesKem = new AesGcm(kek, TAG_SIZE))
                aesKem.Decrypt(nonceKem, encSkKem, tagKem, skKemPlain);

            _skKemBytes = skKemPlain;
            _skKemHandle = GCHandle.Alloc(_skKemBytes, GCHandleType.Pinned);
            Debug.WriteLine($"sk_kem adresa: 0x{_skKemHandle.AddrOfPinnedObject():X}");
            _skKemPinned = true;

            byte[] skSigPlain = new byte[lenSkDsa];
            using (var aesDsa = new AesGcm(kek, TAG_SIZE))
                aesDsa.Decrypt(nonceDsa, encSkSig, tagDsa, skSigPlain);

            _skSigBytes = skSigPlain;
            _skSigHandle = GCHandle.Alloc(_skSigBytes, GCHandleType.Pinned);
            _skSigPinned = true;

            _kemDecapsulationKey = MLKem.ImportDecapsulationKey(MLKemAlgorithm.MLKem768, _skKemBytes);
            _dsaSigningKey = MLDsa.ImportPkcs8PrivateKey(_skSigBytes);

            _pkKemBytes = pkKem;
            _pkDsaBytes = pkDsa;

            CryptographicOperations.ZeroMemory(kek);
            DerivedKey = null;

            Debug.WriteLine("Login successful — PQC keys loaded and pinned for session.");
            return true;
        }

        public (byte[] dekPlaintext, byte[] dekCiphertext, GCHandle dekHandle) EncapsulateForFile()
        {
            if (_pkKemBytes == null)
                throw new InvalidOperationException("PQC keys not loaded. Login first.");

            using var senderKeys = MLKem.ImportEncapsulationKey(MLKemAlgorithm.MLKem768, _pkKemBytes);
            senderKeys.Encapsulate(out byte[] dekCiphertext, out byte[] dekPlaintext);

            var handle = GCHandle.Alloc(dekPlaintext, GCHandleType.Pinned);
            return (dekPlaintext, dekCiphertext, handle);
        }

        public virtual (byte[] dekPlaintext, GCHandle dekHandle) DecapsulateForFile(byte[] dekCiphertext)
        {
            if (_kemDecapsulationKey == null)
                throw new InvalidOperationException("PQC keys not loaded. Login first.");

            byte[] dekPlaintext = _kemDecapsulationKey.Decapsulate(dekCiphertext);
            var handle = GCHandle.Alloc(dekPlaintext, GCHandleType.Pinned);

            return (dekPlaintext, handle);
        }

        public byte[] SignData(byte[] data)
        {
            if (_dsaSigningKey == null)
                throw new InvalidOperationException("PQC keys not loaded. Login first.");

            return _dsaSigningKey.SignData(data, null);
        }

        public bool VerifySignature(byte[] data, byte[] signature)
        {
            if (_pkDsaBytes == null)
                throw new InvalidOperationException("PQC keys not loaded. Login first.");

            using var publicKey = MLDsa.ImportSubjectPublicKeyInfo(_pkDsaBytes);
            return publicKey.VerifyData(data, signature, null);
        }

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

        // ── Privatne metode 

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

        private static async Task ReadExactAsync(Stream s, byte[] buf, int count, CancellationToken ct)
        {
            int read = await s.ReadAtLeastAsync(buf.AsMemory(0, count), count, false, ct)
                .ConfigureAwait(false);
            if (read < count)
                throw new InvalidDataException($"Corrupted keystore — expected {count}B, got {read}B.");
        }
    }
}
