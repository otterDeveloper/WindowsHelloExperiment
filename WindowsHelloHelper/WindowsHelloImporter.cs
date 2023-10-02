using CppSharp;
using CppSharp.AST;
using CppSharp.AST.Extensions;
using CppSharp.Passes;
using CppSharp.Types;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Xml.Linq;

namespace WindowsHelloHelper
{
    public class WindowsHelloImporter : ILibrary
    {
        public void Postprocess(Driver driver, ASTContext ctx)
        {

            
        }

        public void Preprocess(Driver driver, ASTContext ctx)
        {
            var hwndTypeMap = new TypeMap();
            // hwnd to intptr
            hwndTypeMap.Type = new CustomType("IntPtr");
            driver.Context.TypeMaps.TypeMaps.Add("HWND", hwndTypeMap);
 
            foreach (var typemap in driver.Context.TypeMaps.TypeMaps)
            {
                Console.WriteLine($"{typemap.Key}: {typemap.Value}");
            }
        }

        public void Setup(Driver driver)
        {
            var options = driver.Options;
            
            
            options.OutputDir = GetWorkingDirectory();
            
          
            var parserOptions = driver.ParserOptions;
            parserOptions.ClearSystemIncludeDirs();
            parserOptions.AddIncludeDirs(GetWorkingDirectory());
           

            /*var windowsSDKPaths = Directory.EnumerateDirectories($"{Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86)}\\Windows Kits\\10\\Include\\10.0.17134.0");
            foreach (var path in windowsSDKPaths)
            {
                Console.WriteLine(path);
                parserOptions.AddSourceFiles(path);
            }
            //var vcPaths = Directory.EnumerateDirectories($"{Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86)}\\Microsoft Visual Studio\\2022\\Community\\VC\\Tools\\MSVC\\14.36.32532");
           
            parserOptions.AddSourceFiles($"{Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86)}\\Microsoft Visual Studio\\2022\\Community\\VC\\Tools\\MSVC\\14.36.32532\\include");
            */
            parserOptions.ClearSupportedStdTypes();
            parserOptions.Verbose = true;
            var module = options.AddModule("WindowsWebauthn");
         
            module.SharedLibraryName = "webauthn.dll";
            module.Headers.Add("webauthn.h");
            
            
        }


        public static string GetWorkingDirectory()
        {
            var directory = Directory.GetParent(Directory.GetCurrentDirectory());
            while (directory != null)
            {
                var path = Path.Combine(directory.FullName, "WindowsHelloAPI");

                if (Directory.Exists(path))
                    return path;

                directory = directory.Parent;
            }

            throw new Exception(string.Format(
                "Examples directory for project '{0}' was not found", "webauthn"));
        }

        public void SetupPasses(Driver driver)
        {
            driver.Context.TranslationUnitPasses.RenameDeclsUpperCase(RenameTargets.Any);

           

        }



        static class Program
        {
            public static void Main(string[] args)
            {
                ConsoleDriver.Run(new WindowsHelloImporter());
            }
        }

    }
}
