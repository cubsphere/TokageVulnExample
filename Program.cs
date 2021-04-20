using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Threading;
using TokageVulnExample.Properties;

namespace TokageVulnExample
{
    static class Session
    {
        public static readonly string SESSION = "SESSION";
    }

    class Program
    {
        private static readonly string ATTACKERMAIL = "attacker@evil.com";
        static readonly Account[] accounts = {
            new Account("target@victim.moe", "target", Generator.RandomString()),
            new Account(ATTACKERMAIL, "attacker", "123123")
        };

        private static Account GetAccount(Cookie cookie)
        {
            return accounts.FirstOrDefault(account => account.ValidCookie(cookie));
        }

        private static Cookie TreatCookies(HttpListenerRequest req, HttpListenerResponse res)
        {
            Cookie cookie = null;
            foreach (Cookie cook in req.Cookies)
            {
                if (!cook.Expired && cook.Name == Session.SESSION)
                    cookie = cook;
            }
            if (cookie == null)
            {
                cookie = new Cookie(Session.SESSION, Generator.RandomString())
                {
                    Expires = DateTime.Now.AddDays(1)
                };
                res.SetCookie(cookie);
            }
            return cookie;
        }

        private static Dictionary<string, string> ParseBody(HttpListenerRequest req)
        {
            var str = new StreamReader(req.InputStream).ReadToEnd();
            var dict = new Dictionary<string, string>();
            var parameters = str.Split('&');
            foreach (string param in parameters)
            {
                if (!param.Contains('='))
                    continue;

                var split = param.Split('=');
                var key = split[0];
                var val = Uri.UnescapeDataString(split[1]).Replace("+", " ");
                dict.Add(key, val);
            }
            return dict;
        }

        static void HandleRequest(HttpListenerContext context, double mean, double std)
        {
            var req = context.Request;
            var res = context.Response;
            var cookie = TreatCookies(req, res);
            var account = GetAccount(cookie);
            var authenticated = account != null;
            var parameters = ParseBody(req);

            if (ShouldSleep)
            {
                var delay = (int)Math.Round(Generator.LogNormal(mean, std));
                if (delay > 0)
                {
                    Thread.Sleep(delay);
                }
            }

            try
            {
                switch (req.Url.AbsolutePath)
                {
                    case "/me":
                        {
                            if (!authenticated)
                            {
                                res.Redirect("/login");
                                break;
                            }
                            var resource = account.Email == ATTACKERMAIL ? Resources.attackerPage : Resources.targetPage;
                            var writer = new StreamWriter(res.OutputStream);
                            writer.Write(resource);
                            writer.Flush();
                            break;
                        }
                    case "/login":
                        {
                            if (authenticated)
                                res.Redirect("/me");
                            var writer = new StreamWriter(res.OutputStream);
                            writer.Write(Resources.loginPage);
                            writer.Flush();
                            break;
                        }
                    case "/forgot":
                        {
                            if (authenticated)
                                res.Redirect("/me");
                            var writer = new StreamWriter(res.OutputStream);
                            writer.Write(Resources.forgotPage);
                            writer.Flush();
                            break;
                        }
                    case "/reset":
                        {
                            if (authenticated)
                                res.Redirect("/me");
                            var writer = new StreamWriter(res.OutputStream);
                            writer.Write(Resources.resetPage);
                            writer.Flush();
                            break;
                        }
                    case "/api/login":
                        {
                            if (req.HttpMethod.ToLower() != "post")
                            {
                                res.StatusCode = 404;
                                break;
                            }

                            var success = false;
                            parameters.TryGetValue("user", out var usernameOrEmail);
                            parameters.TryGetValue("password", out var password);
                            success = accounts.Any(acc => acc.Authenticate(usernameOrEmail, password, cookie));
                            if (success)
                            {
                                account?.Logout();
                                res.Redirect("/me");
                            }
                            else
                            {
                                res.StatusCode = 401;
                            }
                            break;
                        }
                    case "/api/request-reset-token":
                        {
                            parameters.TryGetValue("email", out var email);
                            account = accounts.FirstOrDefault(acc => acc.Email == email);
                            var token = account?.NewTwoFAToken() ?? "";
                            if (email == ATTACKERMAIL)
                            {
                                var writer = new StreamWriter(res.OutputStream);
                                writer.Write(token);
                                writer.Flush();
                            }
                            break;
                        }
                    case "/api/reset":
                        {
                            if (req.HttpMethod.ToLower() != "post")
                            {
                                res.StatusCode = 404;
                                break;
                            }

                            parameters.TryGetValue("email", out var emails);
                            parameters.TryGetValue("token", out var twoFAToken);
                            parameters.TryGetValue("newpass", out var newPassword);
                            account = accounts.FirstOrDefault(acc => acc.Email == emails);
                            var successs = account?.ResetPassword(twoFAToken, newPassword) ?? false;
                            res.StatusCode = successs ? 200 : 401;
                            break;
                        }
                    case "/favicon.ico":
                        res.StatusCode = 404;
                        break;
                    case "/logout":
                        account?.Logout();
                        res.Redirect("/login");
                        break;
                    case "/sample":
                        {
                            var writer = new StreamWriter(res.OutputStream);
                            writer.Write(Generator.GenerateToken());
                            writer.Flush();
                            break;
                        }
                    default:
                        if (authenticated)
                            res.Redirect("/me");
                        else
                            res.Redirect("/login");
                        break;
                }
                if (ShouldSleep)
                {
                    var delay = (int)Math.Round(Generator.LogNormal(mean, std));
                    if (delay > 0)
                    {
                        Thread.Sleep(delay);
                    }
                }
                res.OutputStream.Flush();
                res.Close();
            }
            catch (Exception e)
            { Console.WriteLine(e.Message); }
        }

        private static bool ShouldSleep;

        static void Main(string[] args)
        {
            var help = false;
            var newthread = false;
            var mean = 0.0;
            var std = 0.0;
            var options = new Mono.Options.OptionSet {
                { "h|help", "show this message and exit", h => help = h != null },
                { "m|mean=", "mean network delay", n => mean = double.Parse(n) },
                { "d|std=", "network delay standard deviation", n => std = double.Parse(n) },
                { "f|force", "force Environment.TickCount as seed", f => { if (f != null) Generator.UseTickCount(); } },
                { "s|single", "use single instance instead of new Random().Next()", c => { if (c != null) Generator.UseSingleInstance(); } },
                { "n|newthread", "use a new thread for each request (default is single-thread)", n => newthread = n != null },
            };

            options.Parse(args);
            if (help)
            {
                Console.WriteLine("TokageVulnExample - an example HTTP server vulnerable to tokage's prediction attack");
                options.WriteOptionDescriptions(Console.Out);
                return;
            }

            if (mean < 0)
            {
                throw new Exception("mean network delay cannot be negative!");
            }
            if (std < 0)
            {
                throw new Exception("network delay standard deviation cannot be negative!");
            }

            void f(HttpListenerContext c) => HandleRequest(c, mean, std);

            ShouldSleep = mean != 0 || std != 0;
            var listener = new HttpListener();
            listener.Prefixes.Add("http://localhost:8080/");
            listener.Start();
            Console.WriteLine("Listening on http://localhost:8080");
            Console.CancelKeyPress += new ConsoleCancelEventHandler((_,_) => listener.Close());
            while (true)
            {
                var context = listener.GetContext();
                if (newthread)
                {
                    new Thread(_ => f(context)).Start();
                } 
                else f(context);
            }
        }
    }
}
