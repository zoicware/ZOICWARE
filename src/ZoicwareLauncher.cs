using System;
using System.IO;
using System.Diagnostics;

namespace ZoicwareLauncher
{
    class Program
    {
        static int Main(string[] args)
        {
            string baseDirectory = AppDomain.CurrentDomain.BaseDirectory;
            string scriptPath = ResolveScriptPath(baseDirectory);

            if (scriptPath == null)
            {
                Console.Error.WriteLine("ERROR: ZOICWARE.ps1 was not found at the expected release path:");
                Console.Error.WriteLine(GetExpectedScriptPath(baseDirectory));
                Console.Error.WriteLine("Extract the complete zoicwareOS release and keep the launcher beside _FOLDERMUSTBEONCDRIVE.");
                Console.Write("Press any key to exit...");
                Console.ReadKey(true);
                return 1;
            }

            return LaunchScript(scriptPath);
        }

        internal static string ResolveScriptPath(string baseDirectory)
        {
            string scriptPath = GetExpectedScriptPath(baseDirectory);
            return File.Exists(scriptPath) ? scriptPath : null;
        }

        internal static string GetExpectedScriptPath(string baseDirectory)
        {
            return Path.Combine(baseDirectory, "_FOLDERMUSTBEONCDRIVE", "ZOICWARE.ps1");
        }

        static int LaunchScript(string scriptPath)
        {
            UnblockFile(scriptPath);

            string psArgs = string.Format(
                "-NoProfile -ExecutionPolicy Bypass -File \"{0}\"",
                scriptPath
            );

            var psi = new ProcessStartInfo
            {
                FileName = "powershell.exe",
                Arguments = psArgs,
                UseShellExecute = false,
                RedirectStandardOutput = false,
                RedirectStandardError = false,
                CreateNoWindow = false,
            };

            using (Process ps = Process.Start(psi))
            {
                ps.WaitForExit();
                return ps.ExitCode;
            }
        }

        // Removes the Zone.Identifier from the file same as Unblock-File in powershell
        static void UnblockFile(string path)
        {
            string adsPath = path + ":Zone.Identifier";
            try
            {
                if (File.Exists(adsPath))
                    File.Delete(adsPath);
            }
            catch
            { /* ignore */ }
        }
    }
}
