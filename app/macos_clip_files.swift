import AppKit
import Foundation

let args = CommandLine.arguments
let pb = NSPasteboard.general
let fileType = NSPasteboard.PasteboardType("NSFilenamesPboardType")

if args.count > 2 && args[1] == "write" {
    let filePaths = Array(args.dropFirst(2)).map { NSString(string: $0).expandingTildeInPath }
    pb.clearContents()
    pb.declareTypes([fileType], owner: nil)
    pb.setPropertyList(filePaths, forType: fileType)
    exit(0)
} else if args.count > 1 && args[1] == "read" {
    if let files = pb.propertyList(forType: fileType) as? [String] {
        for f in files {
            print(f)
        }
        exit(0)
    }
    if let urls = pb.readObjects(forClasses: [NSURL.self], options: nil) as? [NSURL] {
        for u in urls {
            if let path = u.path {
                print(path)
            }
        }
        exit(0)
    }
    exit(0)
}
