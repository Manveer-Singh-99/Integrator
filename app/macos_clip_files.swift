import Cocoa
import Foundation

private func printErr(_ msg: String) {
    if let data = (msg + "\n").data(using: .utf8) {
        FileHandle.standardError.write(data)
    }
}

private func readNulPathsFromStdin() -> [String] {
    let data = FileHandle.standardInput.readDataToEndOfFile()
    guard !data.isEmpty else { return [] }
    return data.split(separator: 0, omittingEmptySubsequences: true).compactMap { slice in
        let s = String(decoding: slice, as: UTF8.self)
        return s.isEmpty ? nil : s
    }
}

let args = CommandLine.arguments
guard args.count >= 2 else {
    printErr("Usage: macos_clip_files <read [--nul] | write [--nul | <path> ...]>")
    exit(2)
}

let mode = args[1]
let pb = NSPasteboard.general

switch mode {
case "read":
    let useNul = args.dropFirst(2).contains("--nul") || args.dropFirst(2).contains("-0")
    let options: [NSPasteboard.ReadingOptionKey: Any] = [
        .urlReadingFileURLsOnly: true
    ]
    guard let urls = pb.readObjects(forClasses: [NSURL.self], options: options) as? [URL], !urls.isEmpty else {
        exit(0)
    }
    var seen = Set<String>()
    var ordered: [String] = []
    for url in urls {
        guard url.isFileURL else { continue }
        let path = url.path
        guard !path.isEmpty, !path.contains("\0") else { continue }
        if seen.insert(path).inserted {
            ordered.append(path)
        }
    }
    guard !ordered.isEmpty else { exit(0) }
    if useNul {
        var out = Data()
        for (idx, p) in ordered.enumerated() {
            if idx > 0 { out.append(0) }
            out.append(contentsOf: p.utf8)
        }
        FileHandle.standardOutput.write(out)
    } else {
        for p in ordered {
            print(p)
        }
    }
    exit(0)

case "write":
    let rawPaths: [String]
    if args.count == 3 && args[2] == "--nul" {
        rawPaths = readNulPathsFromStdin()
    } else {
        rawPaths = Array(args.dropFirst(2))
    }
    var seen = Set<String>()
    var urls: [NSURL] = []
    for p in rawPaths {
        guard !p.isEmpty, !p.contains("\0") else { continue }
        if seen.insert(p).inserted {
            urls.append(URL(fileURLWithPath: p) as NSURL)
        }
    }
    guard !urls.isEmpty else {
        printErr("macos_clip_files write: no valid file paths provided")
        exit(2)
    }
    pb.clearContents()
    guard pb.writeObjects(urls) else {
        printErr("macos_clip_files write: NSPasteboard.writeObjects failed")
        exit(1)
    }
    exit(0)

default:
    printErr("Unknown command '\(mode)'")
    exit(2)
}
