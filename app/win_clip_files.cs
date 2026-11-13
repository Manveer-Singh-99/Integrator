using System;
using System.IO;
using System.Windows.Forms;
using System.Collections.Specialized;

class Program {
    [STAThread]
    static void Main(string[] args) {
        if (args.Length > 1 && args[0] == "write") {
            StringCollection sc = new StringCollection();
            for (int i = 1; i < args.Length; i++) {
                if (File.Exists(args[i]) || Directory.Exists(args[i])) {
                    sc.Add(Path.GetFullPath(args[i]));
                }
            }
            if (sc.Count > 0) {
                Clipboard.Clear();
                Clipboard.SetFileDropList(sc);
            }
        } else if (args.Length > 0 && args[0] == "read") {
            if (Clipboard.ContainsFileDropList()) {
                foreach (string f in Clipboard.GetFileDropList()) {
                    Console.WriteLine(f);
                }
            }
        } else if (args.Length > 0 && args[0] == "clear") {
            Clipboard.Clear();
        }
    }
}
