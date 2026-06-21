#pragma warning disable SYSLIB5006 // ML-DSA is experimental in .NET 10

using System;
using System.Collections.Generic;
using System.Security.Cryptography;
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
            // KORAK 1: Provjera da platforma podržava post-kvantnu kriptografiju
            // ML-KEM i ML-DSA zahtijevaju Windows Insiders Canary Channel Build 27852+
            if (!MLKem.IsSupported || !MLDsa.IsSupported)
            {
                throw new PlatformNotSupportedException(
                    "ML-KEM and ML-DSA are not supported on this platform. " +
                    "PQC capabilities require Windows Insiders Canary Channel Build 27852 or higher.");
            }

            DisplayRootViewForAsync<ShellViewModel>();
        }
    }
}
