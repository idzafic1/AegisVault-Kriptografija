using Caliburn.Micro;
using Microsoft.Win32;
using System;
using System.Diagnostics;
using System.Threading;
using System.Threading.Tasks;
using Zavrsni.Events;
using Zavrsni.Services;

namespace Zavrsni.ViewModels
{
    public class VaultViewModel : Screen, IProgress<int>
    {
        private CancellationTokenSource? _cts;
        private readonly EncryptionService _encryptionService;
        private readonly IEventAggregator _eventAggregator;
        private readonly CryptoService _cryptoService;

        public VaultViewModel(IEventAggregator eventAggregator, CryptoService cryptoService)
        {
            _eventAggregator = eventAggregator;
            _cryptoService = cryptoService;
            _encryptionService = new EncryptionService(this, _cryptoService);
            ChosenFilepath = null;
            CanCancel = false;
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

        public bool CanEncryptBtn => ChosenFilepath != null && !ChosenFilepath.EndsWith(".enc");
        public bool CanDecryptBtn => ChosenFilepath != null && ChosenFilepath.EndsWith(".enc");

        public string? Path()
        {
            OpenFileDialog fileDialog = new()
            {
                Title = "Choose a file for encryption or decryption"
            };

            if (fileDialog.ShowDialog() == true)
            {
                ChosenFilepath = fileDialog.FileName;
                return ChosenFilepath;
            }
            return null;
        }

        public void Cancel()
        {
            _cts?.Cancel();
        }

        public async Task EncryptBtn()
        {
            if (ChosenFilepath == null) return;

            _cts = new CancellationTokenSource();
            CanCancel = true;
            try
            {
                Notification = "Started Encryption...";
                await _encryptionService.Encrypt(ChosenFilepath, _cts.Token);
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
            if (ChosenFilepath == null) return;

            _cts = new CancellationTokenSource();
            CanCancel = true;
            try
            {
                Notification = "Started Decryption...";
                await _encryptionService.Decrypt(ChosenFilepath, _cts.Token);
                Notification = "Decryption completed successfully.";
            }
            catch (OperationCanceledException)
            {
                Debug.WriteLine("Decryption cancelled by user.");
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

        public async Task Logout()
        {
            _cryptoService.ClearSensitiveData();
            Debug.WriteLine("Logout — all PQC keys zeroed from RAM.");
            await _eventAggregator.PublishOnUIThreadAsync(new NavigateToLoginEvent());
        }

        protected override Task OnDeactivateAsync(bool close, CancellationToken cancellationToken)
        {
            _cryptoService.ClearSensitiveData();
            Debug.WriteLine("VaultViewModel deactivated — all keys zeroed from RAM.");
            return base.OnDeactivateAsync(close, cancellationToken);
        }
    }
}
