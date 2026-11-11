import Foundation
import CoreGraphics

var count: UInt32 = 0
CGGetOnlineDisplayList(0, nil, &count)
var displays = [CGDirectDisplayID](repeating: 0, count: Int(count))
CGGetOnlineDisplayList(count, &displays, &count)

var targetId: CGDirectDisplayID? = nil
for d in displays {
    if CGDisplayIsBuiltin(d) == 0 {
        targetId = d
        break
    }
}

if let displayId = targetId {
    let confPath = NSString(string: "~/.config/sunshine/sunshine.conf").expandingTildeInPath
    var conf = (try? String(contentsOfFile: confPath, encoding: .utf8)) ?? ""
    if let range = conf.range(of: #"(?m)^output_name\s*=.*$"#, options: .regularExpression) {
        conf.replaceSubrange(range, with: "output_name = \(displayId)")
    } else {
        conf.append("\noutput_name = \(displayId)\n")
    }
    try? conf.write(toFile: confPath, atomically: true, encoding: .utf8)
    print("Configured Sunshine output_name = \(displayId)")
}
