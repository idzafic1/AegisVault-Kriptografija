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
        private const int NONCE_SIZE = 12;
        private const int TAG_SIZE = 16;
        private const int CHUNK_SIZE = 4 * 1024 * 1024;
        private const int HEADER_SIZE = NONCE_SIZE + TAG_SIZE; // 28B per-chunk overhead (nonce + tag)
        private const int ML_DSA_65_SIG_SIZE = 3309;           // ML-DSA-65 fiksna velicina potpisa
        private const int HASH_BUF_SIZE = 81920;               // 80KB buffer za hash verification prolaz

        private readonly IProgress<int>? _progress;
        private readonly CryptoService _cryptoService;
        private byte[]? _key; // LEGACY — za ClearKey() kompatibilnost

        private const string FolderName = "FileVault";

        public EncryptionService(IProgress<int> Progress, CryptoService cryptoService)
        {
            _progress = Progress;
            _cryptoService = cryptoService;
        }

        public void SetKey(byte[] key) => _key = key;

        public void ClearKey()
        {
            if (_key != null)
            {
                CryptographicOperations.ZeroMemory(_key);
                _key = null;
            }
        }

        // ENCRYPT — Encrypt-then-Sign
        // .enc: [4B dekCt.Len][dekCt][4B sig.Len][sig][4B meta.Len][nonce|tag|metaCt][nonce|tag|chunkCt]
        // Potpis: SHA-256(dekCiphertext || svi enkriptovani bajtovi) -> ML-DSA-65
        public async Task Encrypt(string filepath, CancellationToken ct)
        {
            if (!_cryptoService.IsReady)
                throw new InvalidOperationException("PQC keys not loaded. Login first.");

            // Zero-allocation bufferi (ArrayPool) sprecavaju LOH fragmentaciju
            // zbog vecih fajlova, mora se vratiti u finally bloku
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

                // DEK nam tek sad treba, pa se tek sad i generise
                dekData = _cryptoService.EncapsulateForFile();
                using var aes = new AesGcm(dekData.dekPlaintext, TAG_SIZE);

                // AesGcm konstruktor KOPIRA kljuc u native CNG kontekst.
                // Managed plaintext niz nam vise ne treba, mozemo ga odmah zerirati i osloboditi.
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

                // Direktno pisanje AES izlaza u writeBuf izbjegava nepotrebne memorijske alokacije
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


        // DECRYPT — Verify-before-Decrypt (dva prolaza)
        // 1) SHA-256 hash svih enkriptovanih bajtova -> VerifySignature
        // 2) Seek nazad -> AES-GCM streaming dekripcija
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

                // Verifikacija se provodi eksplicitno prije dekapsulacije
                // kako se privatni KEM kljuc nikada ne bi izlozio korumpiranom ciphertextu
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

                // Isti princip kao Encrypt -- AesGcm konstruktor kopira kljuc u CNG,
                // managed niz vise nije potreban
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

        private static async Task ReadExactAsync(Stream s, byte[] buf, int count, CancellationToken ct)
        {
            int read = await s.ReadAtLeastAsync(buf.AsMemory(0, count), count, false, ct)
                .ConfigureAwait(false);
            if (read < count)
                throw new InvalidDataException($"Corrupted .enc — expected {count}B, got {read}B.");
        }

        // ============================================================
        // [LEGACY] Zakomentarisano dok se ne potvrdi da PQC flow radi.
        // Prethodni AES-GCM streaming bez ML-KEM/ML-DSA.
        // ============================================================

        /*
        public static async Task Encryption(byte[] Key, string filepath, IProgress<int> progress, CancellationToken ct)
        {
            byte[] filepathBytes = Encoding.UTF8.GetBytes(Path.GetFileName(filepath));
            byte[] filepathLength = BitConverter.GetBytes((ushort)filepathBytes.Length);
            string output = GetNewEncryptionPath();
            int NONCE_SIZE = 12;
            int TAG_SIZE = 16;
            int CHUNK_SIZE = 4 * 1024 * 1024;
            using AesGcm instance = new AesGcm(Key, TAG_SIZE);
            using FileStream fsRead = new FileStream(filepath, FileMode.Open, FileAccess.Read, FileShare.None, 4096, FileOptions.Asynchronous);
            using FileStream fsWrite = new FileStream(output, FileMode.Create, FileAccess.Write, FileShare.None, 4096, FileOptions.Asynchronous);
            byte[] buffer = new byte[CHUNK_SIZE];
            byte[] nonce = new byte[NONCE_SIZE];
            byte[] tag = new byte[TAG_SIZE];
            byte[] metadata = new byte[2 + filepathBytes.Length];
            int progressCalc = 0;
            int read;
            byte[] writeBuffer = new byte[TAG_SIZE + NONCE_SIZE + CHUNK_SIZE];
            RandomNumberGenerator.Fill(nonce);
            filepathLength.CopyTo(metadata, 0);
            filepathBytes.CopyTo(metadata, 2);
            instance.Encrypt(nonce, metadata, metadata, tag, null);
            BitConverter.GetBytes((int)metadata.Length).CopyTo(writeBuffer.AsSpan(0, sizeof(int)));
            nonce.CopyTo(writeBuffer.AsSpan(sizeof(int), NONCE_SIZE));
            tag.CopyTo(writeBuffer.AsSpan(NONCE_SIZE + sizeof(int), TAG_SIZE));
            metadata.CopyTo(writeBuffer.AsSpan(NONCE_SIZE + TAG_SIZE + sizeof(int), metadata.Length));
            await fsWrite.WriteAsync(writeBuffer.AsMemory(0, (int)(NONCE_SIZE + TAG_SIZE + sizeof(int) + metadata.Length)), ct);
            while ((read = await fsRead.ReadAsync(buffer, 0, buffer.Length, ct)) > 0)
            {
                ct.ThrowIfCancellationRequested();
                RandomNumberGenerator.Fill(nonce);
                var chunk = new Span<byte>(buffer, 0, (int)(read));
                instance.Encrypt(nonce, chunk, chunk, tag, null);
                nonce.CopyTo(writeBuffer.AsSpan(0, NONCE_SIZE));
                tag.CopyTo(writeBuffer.AsSpan(NONCE_SIZE, TAG_SIZE));
                chunk.CopyTo(writeBuffer.AsSpan(NONCE_SIZE + TAG_SIZE, (int)read));
                await fsWrite.WriteAsync(writeBuffer.AsMemory(0, (int)(NONCE_SIZE + TAG_SIZE + read)), ct);
                progressCalc = (int)(((double)fsRead.Position / fsRead.Length) * 100);
                progress.Report(progressCalc);
            }
        }

        public static async Task Decryption(byte[] key, string filepath, IProgress<int> progress, CancellationToken ct)
        {
            int read;
            int TAG_SIZE = 16, NONCE_SIZE = 12, CHUNK_SIZE = 4 * 1024 * 1024;
            string output = "";
            using FileStream fsRead = new FileStream(filepath, FileMode.Open, FileAccess.Read, FileShare.Read, 4096, FileOptions.Asynchronous);
            using AesGcm instance = new AesGcm(key, TAG_SIZE);
            byte[] tmpBuffer = new byte[CHUNK_SIZE + TAG_SIZE + NONCE_SIZE];
            byte[] metadaLen = new byte[sizeof(int)];
            read = await fsRead.ReadAtLeastAsync(metadaLen.AsMemory(0, sizeof(int)), sizeof(int), false, ct);
            if (read < sizeof(int)) throw new InvalidDataException("File is corrupted or not in the expected format.");
            int velicina = BitConverter.ToInt32(metadaLen, 0);
            read = await fsRead.ReadAtLeastAsync(tmpBuffer.AsMemory(0, velicina + NONCE_SIZE + TAG_SIZE), velicina + NONCE_SIZE + TAG_SIZE, false, ct);
            if (read < velicina + NONCE_SIZE + TAG_SIZE) throw new InvalidDataException("File is corrupted or not in the expected format.");
            var metadaCiphertext = tmpBuffer.AsSpan(NONCE_SIZE + TAG_SIZE, velicina);
            var nonce1 = tmpBuffer.AsSpan(0, NONCE_SIZE);
            var tag1 = tmpBuffer.AsSpan(NONCE_SIZE, TAG_SIZE);
            instance.Decrypt(nonce1, metadaCiphertext, tag1, metadaCiphertext, null);
            ushort filepathLength = BitConverter.ToUInt16(metadaCiphertext.Slice(0, 2));
            string extractedFileName = Encoding.UTF8.GetString(metadaCiphertext.Slice(2, filepathLength));
            output = Path.Combine(GetSecureStorageFolder(), extractedFileName);
            using FileStream fsWrite = new FileStream(output, FileMode.Create, FileAccess.Write, FileShare.None, 4096, FileOptions.Asynchronous);
            int progressCalc = 0;
            while (fsRead.Position < fsRead.Length)
            {
                ct.ThrowIfCancellationRequested();
                read = await fsRead.ReadAsync(tmpBuffer, 0, tmpBuffer.Length, ct);
                if (read < NONCE_SIZE + TAG_SIZE)
                    throw new InvalidDataException("File is corrupted or not in the expected format.");
                var readSpan = tmpBuffer.AsSpan(0, (int)read);
                var nonce = readSpan.Slice(0, NONCE_SIZE);
                var tag = readSpan.Slice(NONCE_SIZE, TAG_SIZE);
                var chunkSpan = readSpan.Slice(NONCE_SIZE + TAG_SIZE);
                instance.Decrypt(nonce, chunkSpan, tag, chunkSpan, null);
                await fsWrite.WriteAsync(tmpBuffer.AsMemory(NONCE_SIZE + TAG_SIZE, chunkSpan.Length), ct);
                progressCalc = (int)(((double)fsRead.Position / fsRead.Length) * 100);
                progress.Report(progressCalc);
            }
        }
        */

        public static string GetSecureStorageFolder()
        {
            string path = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), FolderName);
            if (!Directory.Exists(path)) Directory.CreateDirectory(path);
            return path;
        }

        public static string GetNewEncryptionPath()
            => Path.Combine(GetSecureStorageFolder(), Path.GetRandomFileName() + ".enc");
    }
}
