using Caliburn.Micro;
using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Text;

using Zavrsni.Services;

namespace Zavrsni.ViewModels
{
    public class VaultViewModel : Screen, IProgress<int>
    {
        private CancellationTokenSource _cts;

        private EncryptionService es;

        private IEventAggregator _eventAggregator;
        private CryptoService _cryptoService;

        public VaultViewModel(IEventAggregator eventaggregator, CryptoService cryptoService)
        {
            _cts = new CancellationTokenSource();
            es = new EncryptionService(this);
            ChosenFilepath = null;
            CanCancel = false;
            _eventAggregator = eventaggregator;
            _cryptoService = cryptoService;

            // postavi derivirani kljuc iz CryptoService na EncryptionService
            if (_cryptoService.DerivedKey != null)
            {
                es.SetKey(_cryptoService.DerivedKey);
            }
        }

        public string? ChosenFilepath
        {
            get => field;
            set
            {
                if (field != value)
                {
                    field = value;
                    NotifyOfPropertyChange(nameof(ChosenFilepath));
                    NotifyOfPropertyChange(nameof(CanEncryptBtn));
                    NotifyOfPropertyChange(nameof(CanDecryptBtn));
                }
            }
        }

        public int ProgressBarV { get; set; }
        public bool CanCancel
        {
            get;
            set
            {
                if (field != value)
                {
                    field = value;
                    NotifyOfPropertyChange(nameof(CanCancel));
                }
            }
        }

        public string Path()
        {
            OpenFileDialog fileDialog = new();
            fileDialog.Title = "Choose a file for encryption or decryption";
            if (fileDialog.ShowDialog() == true)
            {
                ChosenFilepath = fileDialog.FileName;
                return ChosenFilepath;
            }
            return null;
        }
        public string? Notification
        {
            get => field;
            set
            {
                if (field != value)
                {
                    field = value;
                    NotifyOfPropertyChange(nameof(Notification));
                }
            }
        }
        public void Cancel()
        {
            _cts?.Cancel();
        }

        public bool CanEncryptBtn => ChosenFilepath != null && !ChosenFilepath.EndsWith(".enc"); // mora biti ovaj property ne mere metoda iz nekog razloga
        public bool CanDecryptBtn => ChosenFilepath != null && ChosenFilepath.EndsWith(".enc");

        public async Task EncryptBtn()
        {
            _cts = new CancellationTokenSource();
            CanCancel = true;
            try
            {
                Notification = "Started Encryption...";
                await es.Encrypt(ChosenFilepath, _cts.Token);
                Notification = "Encryption completed successfully.";
            }
            catch (OperationCanceledException)
            {
                Debug.WriteLine("Encryption cancelled.");
                Notification = "Encryption cancelled by user.";
            }
            finally
            {
                _cts.Dispose();
                _cts = null;
                CanCancel = false;
            }
        }

        public async Task DecryptBtn()
        {
            _cts = new CancellationTokenSource();
            CanCancel = true;
            try
            {
                Notification = "Started Decryption...";
                await es.Decrypt(ChosenFilepath, _cts.Token);
                Notification = "Decryption completed successfully.";
            }
            catch (OperationCanceledException)
            {
                System.Diagnostics.Debug.WriteLine("Decryption cancelled by user.");
                Notification = "Decryption cancelled by user.";
            }
            finally
            {
                _cts.Dispose();
                _cts = null;
                CanCancel = false;
            }
        }

        public void Report(int value)
        {
            ProgressBarV = value;
            NotifyOfPropertyChange(nameof(ProgressBarV));
        }

        // ciscenje kljuceva iz RAM-a cim korisnik napusti Vault ekran
        // ne oslanjamo se na GC jer je spor i nepredvidiv
        protected override Task OnDeactivateAsync(bool close, CancellationToken cancellationToken)
        {
            // nuliranje AES-GCM kljuca u EncryptionService
            es.ClearKey();

            // nuliranje deriviranog kljuca u CryptoService
            _cryptoService.ClearSensitiveData();

            System.Diagnostics.Debug.WriteLine("VaultViewModel deactivated — all keys zeroed from RAM.");

            return base.OnDeactivateAsync(close, cancellationToken);
        }

    }
}
