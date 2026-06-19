using System;
using System.Collections.Generic;
using System.Text;
using System.Windows;
using Caliburn.Micro;
using Zavrsni.Services;
using Zavrsni.ViewModels;

namespace Zavrsni
{
    public class Bootstrapper : BootstrapperBase
    {
        private readonly SimpleContainer _container = new SimpleContainer();
        protected override void Configure()
        {
            _container.Singleton<IEventAggregator, EventAggregator>();
            _container.Singleton<IWindowManager, WindowManager>(); // kako bi se prikazivao prozor    
            _container.Singleton<CryptoService>();
            _container.PerRequest<LoginViewModel>();
            _container.PerRequest<VaultViewModel>();
            _container.PerRequest<RegisterViewModel>();
            _container.Singleton<ShellViewModel>();
        }
        public Bootstrapper()
        {
            Initialize();
        }
        protected override object GetInstance(Type service, string key)
        {
            return _container.GetInstance(service, key);
        }

        protected override IEnumerable<object> GetAllInstances(Type service)
        {
            return _container.GetAllInstances(service);
        }

        protected override void BuildUp(object instance)
        {
            _container.BuildUp(instance);
        }
        protected override void OnStartup(object sender, StartupEventArgs e)
        {
            DisplayRootViewForAsync<ShellViewModel>();
        }
    }
}
