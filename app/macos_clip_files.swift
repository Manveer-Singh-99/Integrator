import AppKit
import Foundation

let args = CommandLine.arguments
let pb = NSPasteboard.general
let fileType = NSPasteboard.PasteboardType("NSFilenamesPboardType")

if args.count > 2 && args[1] == "write" {
    let filePaths = Array(args.dropFirst(2)).map { NSString(string: $0).expandingTildeInPath }
    let urls = filePaths.map { NSURL(fileURLWithPath: $0) }
    pb.clearContents()
    pb.writeObjects(urls)
    pb.addTypes([fileType], owner: nil)
    pb.setPropertyList(filePaths, forType: fileType)
    exit(0)
} else if args.count > 1 && args[1] == "clear" {
    pb.clearContents()
    exit(0)
} else if args.count > 1 && args[1] == "read" {
    var found = Set<String>()
    if let urls = pb.readObjects(forClasses: [NSURL.self], options: nil) as? [NSURL] {
        for u in urls {
            if let path = u.path {
                found.insert(path)
            }
        }
    }
    if let files = pb.propertyList(forType: fileType) as? [String] {
        for f in files {
            found.insert(f)
        }
    }
    for p in found {
        print(p)
    }
    exit(0)
}
