using System.Windows;
using System.Windows.Controls;

namespace Zavrsni.Helpers
{
    /// <summary>
    /// Attached property helper za WPF PasswordBox binding.
    /// PasswordBox.Password nije DependencyProperty pa ne podrzava MVVM data binding.
    /// Ovaj helper registruje AttachedProperty koji hvata PasswordChanged event
    /// i sinhronizuje vrijednost sa ViewModelom putem TwoWay bindinga.
    /// </summary>
    public static class PasswordHelper
    {
        public static readonly DependencyProperty PasswordProperty =
            DependencyProperty.RegisterAttached("Password",
            typeof(string), typeof(PasswordHelper),
            new FrameworkPropertyMetadata(string.Empty, FrameworkPropertyMetadataOptions.BindsTwoWayByDefault, OnPasswordPropertyChanged));

        public static readonly DependencyProperty AttachProperty =
            DependencyProperty.RegisterAttached("Attach",
            typeof(bool), typeof(PasswordHelper), new PropertyMetadata(false, Attach));

        private static readonly DependencyProperty IsUpdatingProperty =
           DependencyProperty.RegisterAttached("IsUpdating", typeof(bool),
           typeof(PasswordHelper));

        public static void SetAttach(DependencyObject dp, bool value) => dp.SetValue(AttachProperty, value);
        public static bool GetAttach(DependencyObject dp) => (bool)dp.GetValue(AttachProperty);

        public static string GetPassword(DependencyObject dp) => (string)dp.GetValue(PasswordProperty);
        public static void SetPassword(DependencyObject dp, string value) => dp.SetValue(PasswordProperty, value);

        private static bool GetIsUpdating(DependencyObject dp) => (bool)dp.GetValue(IsUpdatingProperty);
        private static void SetIsUpdating(DependencyObject dp, bool value) => dp.SetValue(IsUpdatingProperty, value);

        private static void OnPasswordPropertyChanged(DependencyObject sender, DependencyPropertyChangedEventArgs e)
        {
            if (sender is PasswordBox passwordBox)
            {
                passwordBox.PasswordChanged -= PasswordChanged;

                if (!GetIsUpdating(passwordBox))
                {
                    passwordBox.Password = (string)e.NewValue ?? string.Empty;
                }
                passwordBox.PasswordChanged += PasswordChanged;
            }
        }

        private static void Attach(DependencyObject sender, DependencyPropertyChangedEventArgs e)
        {
            if (sender is PasswordBox passwordBox)
            {
                if ((bool)e.OldValue)
                    passwordBox.PasswordChanged -= PasswordChanged;

                if ((bool)e.NewValue)
                    passwordBox.PasswordChanged += PasswordChanged;
            }
        }

        private static void PasswordChanged(object sender, RoutedEventArgs e)
        {
            if (sender is PasswordBox passwordBox)
            {
                SetIsUpdating(passwordBox, true);
                SetPassword(passwordBox, passwordBox.Password);
                SetIsUpdating(passwordBox, false);
            }
        }
    }
}

