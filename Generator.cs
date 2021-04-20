using System;

namespace TokageVulnExample
{
    static class Generator
    {
        private enum Mode
        {
            TickCount,
            Default,
            SingleInstance
        }
        
        private static Mode mode = Mode.Default;
        private static Random instance;

        public static void UseTickCount()
        {
            mode = Mode.TickCount;
        }

        public static void UseDefault()
        {
            mode = Mode.Default;
        }

        public static void UseSingleInstance()
        {
            mode = Mode.SingleInstance;
            instance = new Random();
        }

        public static int GenerateToken()
        {
            return mode switch
            {
                Mode.TickCount => new Random(Environment.TickCount).Next(),
                Mode.SingleInstance => instance.Next(),
                Mode.Default => new Random().Next(),
                _ => throw new ArgumentOutOfRangeException("This should never happen!"),
            };
        }

        private static readonly Random rand = new Random();

        public static double Normal(double mean, double stdev)
        {
            var u1 = 1.0 - rand.NextDouble();
            var u2 = 1.0 - rand.NextDouble();
            var randStdNormal = Math.Sqrt(-2.0 * Math.Log(u1)) * Math.Sin(2.0 * Math.PI * u2);
            var randNormal = mean + stdev * randStdNormal;
            return randNormal;
        }

        public static double LogNormal(double mean, double stdev)
        {
            var x = (stdev / mean) * (stdev / mean);
            var mu = Math.Log(mean) - 1 / 2 * Math.Log(x + 1);
            var sigma = Math.Sqrt(Math.Log(x + 1));
            return Math.Exp(Normal(mu, sigma));
        }

        public static string RandomString()
        {
            var rn = rand.Next();
            return rn.ToString();
        }
    }
}