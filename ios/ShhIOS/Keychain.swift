import Foundation
import Security

enum KeyError: Error, Equatable {
    case missing
    case unreadable
}

extension KeyError: LocalizedError {
    var errorDescription: String? {
        switch self {
        case .missing:
            return "No iCloud key. On a Mac, run signed shh login."
        case .unreadable:
            return "The iCloud key could not be read."
        }
    }
}

enum CloudKey {
    static let service = "shh-age-key"
    static let account = "shh"
    // The Mac writer uses this group. A Team ID prefix cannot read the item.
    static let group = "7E2J46XA8A.shh"

    static func query() -> [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecAttrAccessGroup as String: group,
            kSecAttrSynchronizable as String: kCFBooleanTrue as Any,
            kSecReturnData as String: kCFBooleanTrue as Any,
            kSecMatchLimit as String: kSecMatchLimitOne,
        ]
    }

    static func identity() throws -> String {
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query() as CFDictionary, &item)
        if status == errSecItemNotFound {
            throw KeyError.missing
        }
        if status != errSecSuccess {
            throw KeyError.unreadable
        }
        guard let data = item as? Data, let text = String(data: data, encoding: .utf8) else {
            throw KeyError.unreadable
        }
        let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
        if trimmed == "revoked" || !trimmed.hasPrefix("AGE-SECRET-KEY-1") {
            throw KeyError.missing
        }
        return trimmed
    }
}
