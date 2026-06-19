using Caliburn.Micro;
using System.Diagnostics;
using Zavrsni.Events;
using Zavrsni.Services;

namespace Zavrsni.ViewModels
{
    public class RegisterViewModel : Screen
    {
        private readonly IEventAggregator _eventAggregator;
        private readonly CryptoService _cryptoService;


        public string Password { get; set; } = string.Empty;
        public string ConfirmPassword { get; set; } = string.Empty;

        // IsBusy — true dok Argon2id derivacija traje (1-2 sekunde)
        public bool IsBusy
        {
            get => field;
            private set
            {
                if (field != value)
                {
                    field = value;
                    NotifyOfPropertyChange(nameof(IsBusy));
                    NotifyOfPropertyChange(nameof(CanRegister));
                }
            }
        }

        // ErrorMessage — prikazuje se korisniku ako registracija ne uspije
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

        // Caliburn.Micro guard — disable Register dugme dok traje derivacija
        public bool CanRegister => !IsBusy;

        public RegisterViewModel(IEventAggregator eventAggregator, CryptoService cryptoService)
        {
            _eventAggregator = eventAggregator;
            _cryptoService = cryptoService;
        }

        public async Task Register()
        {
            ErrorMessage = null;

            if (string.IsNullOrWhiteSpace(Password))
            {
                ErrorMessage = "Password cannot be empty!";
                Debug.WriteLine("Password cannot be empty!");
                return;
            }

            if (Password != ConfirmPassword)
            {
                ErrorMessage = "Passwords do not match!";
                Debug.WriteLine("Passwords do not match!");
                return;
            }

            IsBusy = true;

            try
            {
                Debug.WriteLine("Register attempted.");
                bool success = await _cryptoService.Register(Password);

                if (success)
                {
                    Debug.WriteLine("Registration successful — navigating to login.");
                    await _eventAggregator.PublishOnUIThreadAsync(new NavigateToLoginEvent());
                }
            }
            finally
            {
                IsBusy = false;
            }
        }

        public void GoToLogin()
        {
            Debug.WriteLine("Navigating back to Login screen.");
            _eventAggregator.PublishOnUIThreadAsync(new NavigateToLoginEvent());
        }
    }
}
