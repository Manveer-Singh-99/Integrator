using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.IO;
using System.Text;
using System.Threading;
using System.Windows.Forms;

class WinClipFiles {
    static bool IsSafeExistingPath(string path) {
        if (string.IsNullOrEmpty(path) || path.IndexOf('\0') >= 0) return false;
        try {
            if (!File.Exists(path) && !Directory.Exists(path)) {
                return false;
            }
            var attrs = File.GetAttributes(path);
            if ((attrs & FileAttributes.ReparsePoint) != 0) {
                Console.Error.WriteLine("win_clip_files: skipping reparse point: " + path);
                return false;
            }
            return true;
        } catch (Exception ex) {
            Console.Error.WriteLine("win_clip_files: failed to inspect '" + path + "': " + ex.Message);
            return false;
        }
    }

    static List<string> ReadNulPathsFromStdin() {
        var result = new List<string>();
        using (var stdin = Console.OpenStandardInput())
        using (var ms = new MemoryStream()) {
            stdin.CopyTo(ms);
            byte[] data = ms.ToArray();
            int start = 0;
            for (int i = 0; i <= data.Length; i++) {
                if (i == data.Length || data[i] == 0) {
                    int len = i - start;
                    if (len > 0) {
                        result.Add(Encoding.UTF8.GetString(data, start, len));
                    }
                    start = i + 1;
                }
            }
        }
        return result;
    }

    [STAThread]
    static int Main(string[] args) {
        Console.OutputEncoding = Encoding.UTF8;
        if (args.Length == 0) {
            Console.Error.WriteLine("Usage: win_clip_files <read [--nul] | write [--nul | <path> ...]>");
            return 2;
        }

        string mode = args[0];
        if (mode == "read") {
            bool useNul = args.Length >= 2 && (args[1] == "--nul" || args[1] == "-0");
            Exception lastErr = null;
            for (int attempt = 0; attempt < 5; attempt++) {
                try {
                    if (!Clipboard.ContainsFileDropList()) {
                        return 0;
                    }
                    var files = Clipboard.GetFileDropList();
                    var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                    var ordered = new List<string>();
                    foreach (string f in files) {
                        if (IsSafeExistingPath(f) && seen.Add(f)) {
                            ordered.Add(f);
                        }
                    }
                    if (useNul) {
                        using (var stdout = Console.OpenStandardOutput()) {
                            for (int i = 0; i < ordered.Count; i++) {
                                if (i > 0) stdout.WriteByte(0);
                                byte[] bytes = Encoding.UTF8.GetBytes(ordered[i]);
                                stdout.Write(bytes, 0, bytes.Length);
                            }
                        }
                    } else {
                        foreach (string f in ordered) {
                            Console.WriteLine(f);
                        }
                    }
                    return 0;
                } catch (Exception ex) {
                    lastErr = ex;
                    Thread.Sleep(20);
                }
            }
            Console.Error.WriteLine("win_clip_files read failed: " + (lastErr != null ? lastErr.Message : "unknown error"));
            return 1;
        } else if (mode == "write") {
            List<string> rawPaths;
            if (args.Length == 2 && args[1] == "--nul") {
                rawPaths = ReadNulPathsFromStdin();
            } else {
                rawPaths = new List<string>();
                for (int i = 1; i < args.Length; i++) {
                    rawPaths.Add(args[i]);
                }
            }

            var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            var sc = new StringCollection();
            foreach (string p in rawPaths) {
                if (IsSafeExistingPath(p) && seen.Add(p)) {
                    sc.Add(p);
                }
            }
            if (sc.Count == 0) {
                Console.Error.WriteLine("win_clip_files write: no safe existing file paths provided");
                return 2;
            }

            Exception lastErr = null;
            for (int attempt = 0; attempt < 5; attempt++) {
                try {
                    Clipboard.SetFileDropList(sc);
                    return 0;
                } catch (Exception ex) {
                    lastErr = ex;
                    Thread.Sleep(25);
                }
            }
            Console.Error.WriteLine("win_clip_files write failed: " + (lastErr != null ? lastErr.Message : "unknown error"));
            return 1;
        }

        Console.Error.WriteLine("Unknown command: " + mode);
        return 2;
    }
}
