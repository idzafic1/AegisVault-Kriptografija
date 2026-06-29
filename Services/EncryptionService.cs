#pragma warning disable SYSLIB5006 // ML-DSA is experimental in .NET 10

using System;
using System.Buffers;
using System.Buffers.Binary;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

namespace Zavrsni.Services
{
    public class EncryptionService
    {
        // ── Konstante ──────────────────────────────────────────────────
        private const int NONCE_SIZE = 12;
        private const int TAG_SIZE = 16;
        private const int CHUNK_SIZE = 4 * 1024 * 1024;
        private const int HEADER_SIZE = NONCE_SIZE + TAG_SIZE;
        private const int ML_DSA_65_SIG_SIZE = 3309;
        private const int HASH_BUF_SIZE = 81920;
        private const string FolderName = "FileVault";

        // ── Fieldi ─────────────────────────────────────────────────────
        private readonly IProgress<int>? _progress;
        private readonly CryptoService _cryptoService;

        internal static string? _testStorageFolder;

        // ── Konstruktor ────────────────────────────────────────────────
        public EncryptionService(IProgress<int> Progress, CryptoService cryptoService)
        {
            _progress = Progress;
            _cryptoService = cryptoService;
        }

        // ── Encrypt — Encrypt-then-Sign 
        // .enc format:
        //   [4B dekCt.Len][dekCt][4B sig.Len][sig][4B meta.Len][nonce|tag|metaCt][nonce|tag|chunkCt]...
        // Potpis pokriva SHA-256(dekCiphertext || svi enkriptovani bajtovi) → ML-DSA-65
        public async Task Encrypt(string filepath, CancellationToken ct)
        {
            if (!_cryptoService.IsReady)
                throw new InvalidOperationException("PQC keys not loaded. Login first.");

            // ArrayPool sprecava LOH fragmentaciju za velike fajlove
            byte[] chunkBuf = ArrayPool<byte>.Shared.Rent(CHUNK_SIZE);
            byte[] writeBuf = ArrayPool<byte>.Shared.Rent(HEADER_SIZE + CHUNK_SIZE);

            (byte[] dekPlaintext, byte[] dekCiphertext, GCHandle dekHandle) dekData = default;
            bool dekHandleFreed = false;
            try
            {
                byte[] nameBytes = Encoding.UTF8.GetBytes(Path.GetFileName(filepath));
                byte[] metadata = new byte[2 + nameBytes.Length];
                BinaryPrimitives.WriteUInt16LittleEndian(metadata, (ushort)nameBytes.Length);
                nameBytes.CopyTo(metadata.AsSpan(2));

                string output = GetNewEncryptionPath();

                dekData = _cryptoService.EncapsulateForFile();
                using var aes = new AesGcm(dekData.dekPlaintext, TAG_SIZE);

                // AesGcm konstruktor kopira kljuc u native CNG kontekst —
                // managed niz vise nije potreban, zeriramo ga odmah
                CryptographicOperations.ZeroMemory(dekData.dekPlaintext);
                dekData.dekHandle.Free();
                dekHandleFreed = true;

                using var fsIn = new FileStream(filepath, FileMode.Open, FileAccess.Read,
                    FileShare.None, CHUNK_SIZE, FileOptions.Asynchronous | FileOptions.SequentialScan);
                using var fsOut = new FileStream(output, FileMode.Create, FileAccess.ReadWrite,
                    FileShare.None, CHUNK_SIZE, FileOptions.Asynchronous);
                using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);

                hash.AppendData(dekData.dekCiphertext);

                BinaryPrimitives.WriteInt32LittleEndian(writeBuf, dekData.dekCiphertext.Length);
                await fsOut.WriteAsync(writeBuf.AsMemory(0, 4), ct).ConfigureAwait(false);
                await fsOut.WriteAsync(dekData.dekCiphertext, ct).ConfigureAwait(false);

                long sigLenPos = fsOut.Position;
                BinaryPrimitives.WriteInt32LittleEndian(writeBuf, ML_DSA_65_SIG_SIZE);
                await fsOut.WriteAsync(writeBuf.AsMemory(0, 4), ct).ConfigureAwait(false);
                Array.Clear(writeBuf, 0, ML_DSA_65_SIG_SIZE);
                await fsOut.WriteAsync(writeBuf.AsMemory(0, ML_DSA_65_SIG_SIZE), ct).ConfigureAwait(false);

                BinaryPrimitives.WriteInt32LittleEndian(writeBuf, metadata.Length);
                RandomNumberGenerator.Fill(writeBuf.AsSpan(4, NONCE_SIZE));
                aes.Encrypt(
                    writeBuf.AsSpan(4, NONCE_SIZE),
                    metadata,
                    writeBuf.AsSpan(4 + HEADER_SIZE, metadata.Length),
                    writeBuf.AsSpan(4 + NONCE_SIZE, TAG_SIZE));

                int metaTotal = 4 + HEADER_SIZE + metadata.Length;
                await fsOut.WriteAsync(writeBuf.AsMemory(0, metaTotal), ct).ConfigureAwait(false);
                hash.AppendData(writeBuf, 0, metaTotal);

                int read;
                while ((read = await fsIn.ReadAsync(chunkBuf.AsMemory(0, CHUNK_SIZE), ct)
                    .ConfigureAwait(false)) > 0)
                {
                    ct.ThrowIfCancellationRequested();

                    RandomNumberGenerator.Fill(writeBuf.AsSpan(0, NONCE_SIZE));
                    aes.Encrypt(
                        writeBuf.AsSpan(0, NONCE_SIZE),
                        chunkBuf.AsSpan(0, read),
                        writeBuf.AsSpan(HEADER_SIZE, read),
                        writeBuf.AsSpan(NONCE_SIZE, TAG_SIZE));

                    int total = HEADER_SIZE + read;
                    await fsOut.WriteAsync(writeBuf.AsMemory(0, total), ct).ConfigureAwait(false);
                    hash.AppendData(writeBuf, 0, total);

                    _progress?.Report((int)((double)fsIn.Position / fsIn.Length * 100));
                }

                byte[] signature = _cryptoService.SignData(hash.GetHashAndReset());

                fsOut.Seek(sigLenPos, SeekOrigin.Begin);
                BinaryPrimitives.WriteInt32LittleEndian(writeBuf, signature.Length);
                await fsOut.WriteAsync(writeBuf.AsMemory(0, 4), ct).ConfigureAwait(false);
                await fsOut.WriteAsync(signature, ct).ConfigureAwait(false);

                if (signature.Length < ML_DSA_65_SIG_SIZE)
                {
                    int pad = ML_DSA_65_SIG_SIZE - signature.Length;
                    Array.Clear(writeBuf, 0, pad);
                    await fsOut.WriteAsync(writeBuf.AsMemory(0, pad), ct).ConfigureAwait(false);
                }
            }
            finally
            {
                if (dekData.dekPlaintext != null && !dekHandleFreed)
                {
                    CryptographicOperations.ZeroMemory(dekData.dekPlaintext);
                    dekData.dekHandle.Free();
                }
                ArrayPool<byte>.Shared.Return(chunkBuf, clearArray: true);
                ArrayPool<byte>.Shared.Return(writeBuf, clearArray: true);
            }
        }

        // ── Decrypt — Verify-before-Decrypt (dva prolaza) 
        // 1. prolaz: SHA-256 hash svih enkriptovanih bajtova → VerifySignature
        // 2. prolaz: Seek nazad → AES-GCM streaming dekripcija
        // Privatni KEM kljuc se nikada ne koristi za fajlove sa nevalidnim potpisom.
        public async Task Decrypt(string filepath, CancellationToken ct)
        {
            if (!_cryptoService.IsReady)
                throw new InvalidOperationException("PQC keys not loaded. Login first.");

            using var fsIn = new FileStream(filepath, FileMode.Open, FileAccess.Read,
                FileShare.None, CHUNK_SIZE, FileOptions.Asynchronous | FileOptions.SequentialScan);

            byte[] i32 = new byte[4];

            await ReadExactAsync(fsIn, i32, 4, ct).ConfigureAwait(false);
            int dekCtLen = BinaryPrimitives.ReadInt32LittleEndian(i32);

            byte[] dekCiphertext = new byte[dekCtLen];
            await ReadExactAsync(fsIn, dekCiphertext, dekCtLen, ct).ConfigureAwait(false);

            await ReadExactAsync(fsIn, i32, 4, ct).ConfigureAwait(false);
            int sigLen = BinaryPrimitives.ReadInt32LittleEndian(i32);

            byte[] signature = new byte[sigLen];
            await ReadExactAsync(fsIn, signature, sigLen, ct).ConfigureAwait(false);

            if (sigLen < ML_DSA_65_SIG_SIZE)
                fsIn.Seek(ML_DSA_65_SIG_SIZE - sigLen, SeekOrigin.Current);

            long posAfterHeader = fsIn.Position;

            byte[] hashBuf = ArrayPool<byte>.Shared.Rent(HASH_BUF_SIZE);
            try
            {
                using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
                hash.AppendData(dekCiphertext);

                int read;
                while ((read = await fsIn.ReadAsync(hashBuf.AsMemory(0, HASH_BUF_SIZE), ct)
                    .ConfigureAwait(false)) > 0)
                    hash.AppendData(hashBuf, 0, read);

                // Verifikacija PRIJE dekapsulacije — privatni KEM kljuc
                // se nikada ne izlaze korumpiranom ciphertextu
                if (!_cryptoService.VerifySignature(hash.GetHashAndReset(), signature))
                    throw new CryptographicException(
                        "Signature verification failed — file tampered or not signed by this vault.");
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(hashBuf, clearArray: true);
            }

            var dekData = _cryptoService.DecapsulateForFile(dekCiphertext);
            bool dekHandleFreed = false;

            byte[] tmpBuf = ArrayPool<byte>.Shared.Rent(HEADER_SIZE + CHUNK_SIZE);
            try
            {
                fsIn.Seek(posAfterHeader, SeekOrigin.Begin);
                using var aes = new AesGcm(dekData.dekPlaintext, TAG_SIZE);

                // AesGcm konstruktor kopira kljuc u CNG managed niz zeriramo odmah
                CryptographicOperations.ZeroMemory(dekData.dekPlaintext);
                dekData.dekHandle.Free();
                dekHandleFreed = true;

                await ReadExactAsync(fsIn, i32, 4, ct).ConfigureAwait(false);
                int metaLen = BinaryPrimitives.ReadInt32LittleEndian(i32);

                await ReadExactAsync(fsIn, tmpBuf, HEADER_SIZE + metaLen, ct).ConfigureAwait(false);
                aes.Decrypt(
                    tmpBuf.AsSpan(0, NONCE_SIZE),
                    tmpBuf.AsSpan(HEADER_SIZE, metaLen),
                    tmpBuf.AsSpan(NONCE_SIZE, TAG_SIZE),
                    tmpBuf.AsSpan(HEADER_SIZE, metaLen));

                ushort nameLen = BinaryPrimitives.ReadUInt16LittleEndian(tmpBuf.AsSpan(HEADER_SIZE));
                string fileName = Encoding.UTF8.GetString(tmpBuf, HEADER_SIZE + 2, nameLen);
                string outputPath = Path.Combine(GetSecureStorageFolder(), fileName);

                using var fsOut = new FileStream(outputPath, FileMode.Create, FileAccess.Write,
                    FileShare.None, CHUNK_SIZE, FileOptions.Asynchronous);

                while (fsIn.Position < fsIn.Length)
                {
                    ct.ThrowIfCancellationRequested();

                    int read = await fsIn.ReadAsync(tmpBuf.AsMemory(0, HEADER_SIZE + CHUNK_SIZE), ct)
                        .ConfigureAwait(false);
                    if (read < HEADER_SIZE)
                        throw new InvalidDataException("Corrupted .enc — chunk too small.");

                    int payloadLen = read - HEADER_SIZE;
                    aes.Decrypt(
                        tmpBuf.AsSpan(0, NONCE_SIZE),
                        tmpBuf.AsSpan(HEADER_SIZE, payloadLen),
                        tmpBuf.AsSpan(NONCE_SIZE, TAG_SIZE),
                        tmpBuf.AsSpan(HEADER_SIZE, payloadLen));

                    await fsOut.WriteAsync(tmpBuf.AsMemory(HEADER_SIZE, payloadLen), ct)
                        .ConfigureAwait(false);
                    _progress?.Report((int)((double)fsIn.Position / fsIn.Length * 100));
                }
            }
            finally
            {
                if (!dekHandleFreed)
                {
                    CryptographicOperations.ZeroMemory(dekData.dekPlaintext);
                    dekData.dekHandle.Free();
                }
                ArrayPool<byte>.Shared.Return(tmpBuf, clearArray: true);
            }
        }

        // ── Privatne metode 
        private static async Task ReadExactAsync(Stream s, byte[] buf, int count, CancellationToken ct)
        {
            int read = await s.ReadAtLeastAsync(buf.AsMemory(0, count), count, false, ct)
                .ConfigureAwait(false);
            if (read < count)
                throw new InvalidDataException($"Corrupted .enc — expected {count}B, got {read}B.");
        }

        public static string GetSecureStorageFolder()
        {
            if (_testStorageFolder != null)
            {
                if (!Directory.Exists(_testStorageFolder)) Directory.CreateDirectory(_testStorageFolder);
                return _testStorageFolder;
            }

            string path = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), FolderName);
            if (!Directory.Exists(path)) Directory.CreateDirectory(path);
            return path;
        }

        public static string GetNewEncryptionPath()
            => Path.Combine(GetSecureStorageFolder(), Path.GetRandomFileName() + ".enc");
    }
}
