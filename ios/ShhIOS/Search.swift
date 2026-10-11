import Foundation

func matchingNames(_ names: [String], query: String) -> [String] {
    let needle = query.trimmingCharacters(in: .whitespacesAndNewlines)
    if needle.isEmpty {
        return names
    }
    return names.filter {
        $0.range(of: needle, options: [.caseInsensitive, .diacriticInsensitive]) != nil
    }
}
