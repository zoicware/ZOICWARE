using System;
using System.IO;
using System.Diagnostics;

namespace ZoicwareLauncher
{
    class Program
    {
        static readonly string LocationCache = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
            "zLocation.tmp"
        );

        static int Main(string[] args)
        {
            string scriptPath = ResolveScriptPath();

            if (scriptPath == null)
            {
                Console.Error.WriteLine("ERROR: ZOICWARE.ps1 not found.");
                Console.Write("Press any key to exit...");
                Console.ReadKey(true);
                return 1;
            }

            return LaunchScript(scriptPath);
        }

        static string ResolveScriptPath()
        {
            //check for cached path
            if (File.Exists(LocationCache))
            {
                string cached = File.ReadAllText(LocationCache).Trim();
                if (File.Exists(cached))
                {
                    //Console.WriteLine("Using cached path: " + cached);
                    return cached;
                }
                //delete cached file that has old path
                try { File.Delete(LocationCache); } catch { }
                //Console.WriteLine("Cached path invalid, searching...");
            }

            //check relative to the exe's own location first
            string exeDir = AppDomain.CurrentDomain.BaseDirectory;
            string relative = Path.Combine(exeDir, "_FOLDERMUSTBEONCDRIVE", "ZOICWARE.ps1");
            if (File.Exists(relative))
            {
                CacheAndReturn(relative);
                return relative;
            }

            //recursive search across all fixed drives
            foreach (DriveInfo drive in DriveInfo.GetDrives())
            {
                if (drive.DriveType != DriveType.Fixed) continue;
                string found = RecursiveSearch(drive.RootDirectory.FullName, "ZOICWARE.ps1");
                if (found != null)
                {
                    CacheAndReturn(found);
                    return found;
                }
            }

            return null;
        }


        static string RecursiveSearch(string root, string fileName)
        {
            try
            {
                foreach (string file in Directory.EnumerateFiles(root, fileName,
                    SearchOption.AllDirectories))
                {
                    // Skip recycle bin entries
                    if (file.IndexOf("$Recycle.Bin", StringComparison.OrdinalIgnoreCase) >= 0)
                        continue;
                    return file;
                }
            }
            catch { }
            return null;
        }

        static void CacheAndReturn(string path)
        {
            try { File.WriteAllText(LocationCache, path); }
            catch { /* ignore if cache write fails */ }
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
