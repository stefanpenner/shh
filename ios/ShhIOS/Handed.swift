import Foundation
import UniformTypeIdentifiers

let maxVaultBytes = 2 * 1024 * 1024

extension UTType {
    static let shhVault = UTType(exportedAs: "com.example.shh.env")
}

func isVaultFile(_ url: URL) -> Bool {
    url.lastPathComponent.lowercased().hasSuffix(".env.enc")
}

func readerFailure(_ message: String) -> String {
    let text = message.lowercased()
    if text.contains("not in the recipients") {
        return "Your key is not on this file."
    }
    if text.contains("mac verification") {
        return "This file failed its check."
    }
    if text.contains("vault file is empty") {
        return "This file is empty."
    }
    if text.contains("no such secret") {
        return "That name is not in this file."
    }
    return "Shh cannot open this file."
}
