using Caliburn.Micro;
using System.Diagnostics;
using Zavrsni.Events;
using Zavrsni.Services;

namespace Zavrsni.ViewModels
{
    public class LoginViewModel : Screen
    {
        private readonly IEventAggregator _eventAggregator;
        private readonly CryptoService _cryptoService;
        private string _password = string.Empty;
        public string Password
        {
            get => _password;
            set
            {
                if (_password != value)
                {
                    _password = value;
                    NotifyOfPropertyChange(nameof(Password));
                }
            }
        }

        // IsBusy — true dok Argon2id derivacija traje (1-2 sekunde)
        // UI treba prikazati spinner ili indeterminate progress bar
        public bool IsBusy
        {
            get => field;
            private set
            {
                if (field != value)
                {
                    field = value;
                    NotifyOfPropertyChange(nameof(IsBusy));
                    NotifyOfPropertyChange(nameof(CanLogin));
                }
            }
        }

        // ErrorMessage — prikazuje se korisniku ako login ne uspije
        public string? ErrorMessage
        {
            get => field;
            private set
            {
                if (field != value)
                {
                    field = value;
                    NotifyOfPropertyChange(nameof(ErrorMessage));
                }
            }
        }

        // Caliburn.Micro guard — disable Login dugme dok traje derivacija
        public bool CanLogin => !IsBusy;

        public LoginViewModel(IEventAggregator eventAggregator, CryptoService cryptoService)
        {
            _eventAggregator = eventAggregator;
            _cryptoService = cryptoService;
        }

        public async Task Login()
        {
            ErrorMessage = null;
            IsBusy = true;

            try
            {
                Debug.WriteLine("Login attempted.");

                bool success = await _cryptoService.Login(Password);
                if (success)
                {
                    Debug.WriteLine("Login successful — publishing OpenVaultEvent.");
                    await _eventAggregator.PublishOnUIThreadAsync(new OpenVaultEvent());
                }
                else
                {
                    ErrorMessage = "Invalid password or no account found.";
                    Debug.WriteLine("Login failed — invalid password or no keystore found.");
                }
            }
            finally
            {
                IsBusy = false;
            }
        }

        public void GoToRegister()
        {
            Debug.WriteLine("Navigating to Register screen.");
            _eventAggregator.PublishOnUIThreadAsync(new NavigateToRegisterEvent());
        }
    }
}
