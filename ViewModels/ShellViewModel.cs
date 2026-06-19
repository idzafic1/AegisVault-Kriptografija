using Caliburn.Micro;
using Zavrsni.Events;
using System.Diagnostics;

namespace Zavrsni.ViewModels
{
    public class ShellViewModel : Conductor<object>,
        IHandle<OpenVaultEvent>,
        IHandle<NavigateToRegisterEvent>,
        IHandle<NavigateToLoginEvent>
    {
        private readonly IEventAggregator _eventAggregator;

        public ShellViewModel(IEventAggregator eventAggregator)
        {
            _eventAggregator = eventAggregator;
            _eventAggregator.SubscribeOnUIThread(this);
        }

        protected override async Task OnInitializeAsync(CancellationToken ct)
        {
            await ActivateItemAsync(IoC.Get<LoginViewModel>(), ct);
        }

        public async Task HandleAsync(OpenVaultEvent message, CancellationToken cancellationToken)
        {
            Debug.WriteLine("Login successful, switching to VaultViewModel.");
            await ActivateItemAsync(IoC.Get<VaultViewModel>(), cancellationToken);
        }

        public async Task HandleAsync(NavigateToRegisterEvent message, CancellationToken cancellationToken)
        {
            Debug.WriteLine("Navigating to RegisterView.");
            await ActivateItemAsync(IoC.Get<RegisterViewModel>(), cancellationToken);
        }

        public async Task HandleAsync(NavigateToLoginEvent message, CancellationToken cancellationToken)
        {
            Debug.WriteLine("Navigating back to LoginView.");
            await ActivateItemAsync(IoC.Get<LoginViewModel>(), cancellationToken);
        }
    }
}
