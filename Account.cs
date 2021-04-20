using System;
using System.Net;

namespace TokageVulnExample
{

    class Account
    {
        public string Email;
        public string Username;
        public string Password;

        private int twoFAToken;
        private DateTime twoFATokenExpiry;

        private Cookie cookie;

        public Account(string email, string username, string password)
        {
            Email = email;
            Username = username;
            Password = password;

            twoFATokenExpiry = DateTime.Now;
            cookie = new Cookie(Session.SESSION, "")
            {
                Expired = true
            };
        }

        public bool Authenticate(string usernameOrEmail, string password, Cookie cook)
        {
            var correct = (Username == usernameOrEmail || Email == usernameOrEmail) && Password == password;
            if (correct)
                cookie = cook;

            return correct;
        }

        public bool ValidCookie(Cookie cook)
        {
            return
                !cookie.Expired &&
                cook.Name == cookie.Name &&
                cook.Value == cookie.Value;
        }

        public string NewTwoFAToken()
        {
            twoFAToken = Generator.GenerateToken();
            twoFATokenExpiry = DateTime.Now.AddMinutes(5);
            return $"{twoFAToken:D6}";
        }

        public bool ResetPassword(string tokenStr, string newPassword)
        {
            var parsedSuccessfully = int.TryParse(tokenStr, out int tokenInt);
            var expired = DateTime.Now.CompareTo(twoFATokenExpiry) > 0;
            var tokenCorrect = tokenInt == twoFAToken;

            if (tokenCorrect && !expired && parsedSuccessfully)
            {
                Password = newPassword;
                return true;
            }
            return false;
        }

        public void Logout()
        {
            cookie.Expired = true;
        }
    }
}
