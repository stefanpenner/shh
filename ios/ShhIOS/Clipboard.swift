import Foundation
import UIKit
import UniformTypeIdentifiers

func publicPasteboard(key: String) -> (items: [[String: Any]], options: [UIPasteboard.OptionsKey: Any]) {
    (
        [[UTType.utf8PlainText.identifier: key]],
        [UIPasteboard.OptionsKey.localOnly: true]
    )
}

func secretPasteboard(secret: String, now: Date) -> (items: [[String: Any]], options: [UIPasteboard.OptionsKey: Any]) {
    (
        [[UTType.utf8PlainText.identifier: secret]],
        [
            UIPasteboard.OptionsKey.localOnly: true,
            UIPasteboard.OptionsKey.expirationDate: now.addingTimeInterval(ClipHold.seconds),
        ]
    )
}

struct ClipHold {
    static let seconds: TimeInterval = 30

    private(set) var generation = 0
    private(set) var value: String?

    mutating func stage(_ secret: String) -> Int {
        generation += 1
        value = secret
        return generation
    }

    mutating func expire(generation g: Int, pasteboard: String) -> Bool {
        guard g == generation, let value, pasteboard == value else {
            return false
        }
        self.value = nil
        return true
    }

    mutating func drop(generation g: Int) {
        guard g == generation else {
            return
        }
        value = nil
    }
}
