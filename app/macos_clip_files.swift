import AppKit
import Foundation

let args = CommandLine.arguments
if args.count > 2 && args[1] == "write" {
    let filePaths = Array(args.dropFirst(2))
    let pb = NSPasteboard.general
    pb.clearContents()
    let urls = filePaths.map { NSURL(fileURLWithPath: $0) }
    let _ = pb.writeObjects(urls)
    exit(0)
} else if args.count > 1 && args[1] == "read" {
    let pb = NSPasteboard.general
    if let files = pb.propertyList(forType: NSPasteboard.PasteboardType("NSFilenamesPboardType")) as? [String] {
        for f in files {
            print(f)
        }
    } else if let urls = pb.readObjects(forClasses: [NSURL.self], options: nil) as? [NSURL] {
        for u in urls {
            if let path = u.path {
                print(path)
            }
        }
    }
    exit(0)
}
