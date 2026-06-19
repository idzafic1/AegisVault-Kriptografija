using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace Zavrsni.Services
{
    // ovo se cini mi se moze skratitit uvodjenjem enuma jer je ovo sustinski ista stvar pa bi bilo manje ponavljajuceg koda jer apsoutno identicna stvar se skoro radi
    // mala jer razlika
    public class EncryptionService
    {
        IProgress<int>? progress;

        // kljuc koji se koristi za enkripciju/dekripciju — postavlja se nakon logina preko CryptoService
        private byte[]? _key;

        // putanja za spasavanje enkriptovanih fajlova
        public static readonly string EncryptedFilesFolder = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            "AES-GCM-Encryption");

        public EncryptionService(IProgress<int> Progress)
        {
            progress = Progress;
        }

        // postavljanje kljuca nakon sto CryptoService derivira kljuc iz lozinke
        public void SetKey(byte[] key)
        {
            _key = key;
        }

        // ciscenje kljuca iz memorije
        public void ClearKey()
        {
            if (_key != null)
            {
                CryptographicOperations.ZeroMemory(_key);
                _key = null;
            }
        }

        public async Task Encrypt(string filepath, CancellationToken ct)
        {
            if (_key == null) throw new InvalidOperationException("Encryption key is not set. Please login first.");
            await Encryption(_key, filepath, progress, ct);
        }

        public async Task Decrypt(string filepath, CancellationToken ct)
        {
            if (_key == null) throw new InvalidOperationException("Encryption key is not set. Please login first.");
            await Decryption(_key, filepath, progress, ct);
        }

        public static async Task Encryption(byte[] Key, string filepath, IProgress<int> progress, CancellationToken ct)
        {
            // PROSIRIVANJE NA 4MB BAFFER
            // mozda postaviti fiksni output ipak a ne ovako ali nek stoji
            byte[] filepathBytes = Encoding.UTF8.GetBytes(Path.GetFileName(filepath));
            byte[] filepathLength = BitConverter.GetBytes((ushort)filepathBytes.Length);

            string output = GetNewEncryptionPath();


            int NONCE_SIZE = 12; // 96 bita za AES-GCM
            int TAG_SIZE = 16; // 128 bita za AES-GCM tag
            int CHUNK_SIZE = 4 * 1024 * 1024; // 4MB chunk size
            using AesGcm instance = new AesGcm(Key, TAG_SIZE);
            using FileStream fsRead = new FileStream(filepath, FileMode.Open, FileAccess.Read, FileShare.None, 4096, FileOptions.Asynchronous);
            using FileStream fsWrite = new FileStream(output, FileMode.Create, FileAccess.Write, FileShare.None, 4096, FileOptions.Asynchronous);
            byte[] buffer = new byte[CHUNK_SIZE];
            byte[] nonce = new byte[NONCE_SIZE];
            byte[] tag = new byte[TAG_SIZE];
            byte[] metadata = new byte[2 + filepathBytes.Length]; // 2 bytes for length + actual filepath bytes
            int progressCalc = 0;
            int read;
            byte[] writeBuffer = new byte[TAG_SIZE + NONCE_SIZE + CHUNK_SIZE]; // buffer za upis chunkova u fajl koji sadrzi nonce + tag + ciphertext

            // potrebno je enkriptovati filepath prije pocetka ovih ostalih dijelova
            RandomNumberGenerator.Fill(nonce);
            filepathLength.CopyTo(metadata, 0); // copy length bytes at the start
            filepathBytes.CopyTo(metadata, 2); // copy filepath bytes after the length

            instance.Encrypt(nonce, metadata, metadata, tag, null);

            BitConverter.GetBytes((int)metadata.Length).CopyTo(writeBuffer.AsSpan(0, sizeof(int)));
            nonce.CopyTo(writeBuffer.AsSpan(sizeof(int), NONCE_SIZE));
            tag.CopyTo(writeBuffer.AsSpan(NONCE_SIZE + sizeof(int), TAG_SIZE));
            metadata.CopyTo(writeBuffer.AsSpan(NONCE_SIZE + TAG_SIZE + sizeof(int), metadata.Length));

            await fsWrite.WriteAsync(writeBuffer.AsMemory(0, (int)(NONCE_SIZE + TAG_SIZE + sizeof(int) + metadata.Length)), ct);
            // znaci ovim se upisuje prvi chunk ali nikako ne mozemo da znamo duzinu ovog metadata dijela

            while ((read = await fsRead.ReadAsync(buffer, 0, buffer.Length, ct)) > 0)
            {
                ct.ThrowIfCancellationRequested();

                RandomNumberGenerator.Fill(nonce); // generisemo random nonce za svaki chunk

                var chunk = new Span<byte>(buffer, 0, (int)(read)); // izvlacimo iz memorije direktno ovo radi na prinicpu pokazivaca u C++

                instance.Encrypt(nonce, chunk, chunk, tag, null);
                // noncude + tag + ciphertext MORA ZA SVAKI CHUNK
                // ovdje se desava Span implicitna konverzija nad nizovima a direktno konvertamo ove buffer vrijednosti u span
                nonce.CopyTo(writeBuffer.AsSpan(0, NONCE_SIZE));
                tag.CopyTo(writeBuffer.AsSpan(NONCE_SIZE, TAG_SIZE));
                chunk.CopyTo(writeBuffer.AsSpan(NONCE_SIZE + TAG_SIZE, (int)read));

                await fsWrite.WriteAsync(writeBuffer.AsMemory(0, (int)(NONCE_SIZE + TAG_SIZE + read)), ct);

                progressCalc = (int)(((double)fsRead.Position / fsRead.Length) * 100);
                progress.Report(progressCalc);
            }
            // dodati mozda logiku za brisanje fajla ali to mi ne djeluje da pripada bas enkripciji
        }

        public static async Task Decryption(byte[] key, string filepath, IProgress<int> progress, CancellationToken ct)
        {
            int read;
            // iduca verzija ce sadrzavati zapis ekstenzije fajla ali za sada neka bude txt da vidimo je li radi dekripcija
            //string output = System.IO.Path.ChangeExtension(System.IO.Path.GetFullPath(filepath), ".txt"); 
            int TAG_SIZE = 16, NONCE_SIZE = 12, CHUNK_SIZE = 4 * 1024 * 1024;
            string output = "";
            using FileStream fsRead = new FileStream(filepath, FileMode.Open, FileAccess.Read, FileShare.None, 4096, FileOptions.Asynchronous);
            using AesGcm instance = new AesGcm(key, TAG_SIZE);
            byte[] tmpBuffer = new byte[CHUNK_SIZE + TAG_SIZE + NONCE_SIZE]; // buffer za ucitavanje chunkova iz fajla koji sadrzi nonce + tag + ciphertext

            // metadataLength int | nonce | tag | encrypted metadata 
            byte[] metadaLen = new byte[sizeof(int)]; // jer je prvi dio velicina u int (4B) ali sto je sigurno sigurno je 
            // bitna provjera da li je stvarno ucitano koliko treba
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

            // prisjetimo se strukture chunkova nonce + tag + ciphertext
            // znaci prvih 12B je nonuce pa onda tag je iducih 16B pa onda je 4MB ciphertext osim mozda zadnjeg chunka pa se toga trebamo paziti
            while (fsRead.Position < fsRead.Length)
            {
                ct.ThrowIfCancellationRequested();

                read = await fsRead.ReadAsync(tmpBuffer, 0, tmpBuffer.Length, ct); // mora bit asinhrono jednosatvno

                if (read < NONCE_SIZE + TAG_SIZE)
                {
                    throw new InvalidDataException("File is corrupted or not in the expected format.");
                }

                var readSpan = tmpBuffer.AsSpan(0, (int)read);
                var nonce = readSpan.Slice(0, NONCE_SIZE);
                var tag = readSpan.Slice(NONCE_SIZE, TAG_SIZE);
                var chunkSpan = readSpan.Slice(NONCE_SIZE + TAG_SIZE);

                instance.Decrypt(nonce, chunkSpan, tag, chunkSpan, null);

                // eh fazon buffer mozda ne ucita sve al chunkSpan ucitava tacno kolko je ostalo od fajla i to se onda upisuje u fajl
                // chunkSpan je pointer ne zauzimamo dodatno memorije pa je iz tog razloga on potreban a ne direktno buffer
                await fsWrite.WriteAsync(tmpBuffer.AsMemory(NONCE_SIZE + TAG_SIZE, chunkSpan.Length), ct);

                progressCalc = (int)(((double)fsRead.Position / fsRead.Length) * 100);
                progress.Report(progressCalc);
            }
        }

        // Helper za folder gdje drzimo enkriptovane fajlove
        public static string GetSecureStorageFolder()
        {
            string path = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "AES-GCM-Encryption");
            if (!Directory.Exists(path)) Directory.CreateDirectory(path);
            return path;
        }

        // Helper za putanju enkriptovanog fajla (Encrypt metoda poziva ovo)
        public static string GetNewEncryptionPath()
        {
            return Path.Combine(GetSecureStorageFolder(), Path.GetRandomFileName() + ".enc");
        }
    }
}
