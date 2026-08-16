using System;
using System.IO;

namespace ZoicwareLauncher
{
    class LauncherResolverTests
    {
        static int failures;

        static int Main()
        {
            string tempRoot = Path.Combine(
                Path.GetTempPath(),
                "ZoicwareLauncherTests-" + Guid.NewGuid().ToString("N")
            );

            try
            {
                string adjacentDirectory = Path.Combine(tempRoot, "adjacent release");
                string adjacentScript = Program.GetExpectedScriptPath(adjacentDirectory);
                WriteTestScript(adjacentScript);

                AssertPath(
                    adjacentScript,
                    Program.ResolveScriptPath(adjacentDirectory),
                    "resolves the script in the adjacent release directory"
                );

                string isolatedDirectory = Path.Combine(tempRoot, "missing");
                string offTreeScript = Path.Combine(tempRoot, "elsewhere", "ZOICWARE.ps1");
                Directory.CreateDirectory(isolatedDirectory);
                WriteTestScript(offTreeScript);

                AssertPath(
                    null,
                    Program.ResolveScriptPath(isolatedDirectory),
                    "does not search outside the adjacent release directory"
                );

                File.Delete(adjacentScript);

                AssertPath(
                    null,
                    Program.ResolveScriptPath(adjacentDirectory),
                    "does not retain a cached path after the adjacent script is removed"
                );
            }
            catch (Exception exception)
            {
                Fail("Unexpected exception: " + exception);
            }
            finally
            {
                try
                {
                    if (Directory.Exists(tempRoot))
                        Directory.Delete(tempRoot, true);
                }
                catch (Exception exception)
                {
                    Fail("Could not remove temporary test directory: " + exception.Message);
                }
            }

            if (failures == 0)
            {
                Console.WriteLine("All launcher resolver tests passed.");
                return 0;
            }

            Console.Error.WriteLine(failures + " launcher resolver test(s) failed.");
            return 1;
        }

        static void WriteTestScript(string path)
        {
            Directory.CreateDirectory(Path.GetDirectoryName(path));
            File.WriteAllText(path, "# synthetic test script");
        }

        static void AssertPath(string expected, string actual, string description)
        {
            bool pathsMatch = expected == null
                ? actual == null
                : string.Equals(expected, actual, StringComparison.OrdinalIgnoreCase);

            if (pathsMatch)
                return;

            Fail(description + ": expected '" + (expected ?? "<null>")
                + "', got '" + (actual ?? "<null>") + "'.");
        }

        static void Fail(string message)
        {
            failures++;
            Console.Error.WriteLine("FAIL: " + message);
        }
    }
}
