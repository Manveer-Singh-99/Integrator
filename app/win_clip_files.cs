using System;
using System.Collections.Specialized;
using System.Text;
using System.Threading;
using System.Windows.Forms;

class Program {
    [STAThread]
    static int Main(string[] args) {
        Console.OutputEncoding = new UTF8Encoding(false);
        Console.InputEncoding = new UTF8Encoding(false);

        if (args.Length == 0) return 0;

        for (int attempt = 0; attempt < 6; attempt++) {
            try {
                if (args[0] == "read") {
                    if (Clipboard.ContainsFileDropList()) {
                        StringCollection files = Clipboard.GetFileDropList();
                        foreach (string f in files) {
                            Console.WriteLine(f);
                        }
                    }
                    return 0;
                } else if (args[0] == "write") {
                    StringCollection files = new StringCollection();
                    for (int i = 1; i < args.Length; i++) {
                        if (System.IO.File.Exists(args[i]) || System.IO.Directory.Exists(args[i])) {
                            files.Add(args[i]);
                        }
                    }
                    if (files.Count > 0) {
                        Clipboard.SetFileDropList(files);
                    }
                    return 0;
                } else if (args[0] == "clear") {
                    Clipboard.Clear();
                    return 0;
                }
                return 0;
            } catch (Exception) {
                Thread.Sleep(20);
            }
        }
        return 1;
    }
}
