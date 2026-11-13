import AppKit
import Foundation

let args = CommandLine.arguments
let pb = NSPasteboard.general

if args.count > 2 && args[1] == "write" {
    let filePaths = Array(args.dropFirst(2)).map { NSString(string: $0).expandingTildeInPath }
    let urls = filePaths.compactMap { NSURL(fileURLWithPath: $0) }
    if !urls.isEmpty {
        pb.clearContents()
        pb.writeObjects(urls)
    }
    exit(0)
} else if args.count > 1 && args[1] == "read" {
    var seen = Set<String>()
    if let urls = pb.readObjects(forClasses: [NSURL.self], options: nil) as? [NSURL], !urls.isEmpty {
        for u in urls {
            if let path = u.path, !seen.contains(path) {
                seen.insert(path)
                print(path)
            }
        }
        exit(0)
    }
    let fileType = NSPasteboard.PasteboardType("NSFilenamesPboardType")
    if let files = pb.propertyList(forType: fileType) as? [String] {
        for f in files {
            if !seen.contains(f) {
                seen.insert(f)
                print(f)
            }
        }
        exit(0)
    }
    exit(0)
}
