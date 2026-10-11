import Foundation

// Person is one recipient on screen. A GitHub name has a profile URL. An age key does not.
struct Person: Equatable {
    var title: String
    var detail: String
    var url: URL?
    var you: Bool
    var key: String
}

struct Roster: Equatable {
    var person: Person
    var onFile: Bool
}

func roster(file: [Party], known: [Party], youKey: String) -> [Roster] {
    let source = known.isEmpty ? file : known
    let names = Set(file.map(\.name))
    let rows = source.map { party in
        Roster(
            person: present(name: party.name, key: party.key, youKey: youKey),
            onFile: names.contains(party.name)
        )
    }
    return rows.sorted { lhs, rhs in
        if lhs.onFile != rhs.onFile {
            return lhs.onFile
        }
        return lhs.person.title.localizedCaseInsensitiveCompare(rhs.person.title) == .orderedAscending
    }
}

func statusLine(you: Bool, onFile: Bool, showMembership: Bool) -> String? {
    if !showMembership {
        return you ? "you" : nil
    }
    if you && onFile {
        return "Your key · On this file"
    }
    if you {
        return "Your key"
    }
    if onFile {
        return "On this file"
    }
    return "Not on this file"
}

#if DEBUG
func sampleRecipients(file: [Party]) -> [Party] {
    file + [
        Party(name: "https://github.com/alice", key: demoAge("b")),
        Party(name: "stef-yubikey", key: demoAge("c")),
    ]
}
private func demoAge(_ mark: Character) -> String {
    "age1" + String(repeating: String(mark), count: 58)
}
#endif

func present(name: String, key: String, youKey: String) -> Person {
    let you = !youKey.isEmpty && key == youKey
    if let user = githubUser(from: name) {
        return Person(
            title: user,
            detail: "GitHub",
            url: URL(string: "https://github.com/\(user)"),
            you: you,
            key: key
        )
    }
    if let label = shhUser(from: name) {
        return Person(title: label, detail: "user", url: nil, you: you, key: key)
    }
    if name.wholeMatch(of: ageKey) != nil {
        return Person(title: shortKey(name), detail: "Age key", url: nil, you: you, key: key)
    }
    return Person(title: name, detail: "Age key", url: nil, you: you, key: key)
}

private let githubUser = /^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,37}[a-zA-Z0-9])?$/
private let ageKey = /^age1[a-z0-9]{58}$/
private let githubPrefix = "https://github.com/"
private let shhUserPrefix = "shh-user://"
private let shhUserLabel = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/

private func shhUser(from name: String) -> String? {
    guard name.hasPrefix(shhUserPrefix) else {
        return nil
    }
    let label = String(name.dropFirst(shhUserPrefix.count))
    guard label.wholeMatch(of: shhUserLabel) != nil else {
        return nil
    }
    return label
}

private func githubUser(from name: String) -> String? {
    guard name.hasPrefix(githubPrefix) else {
        return nil
    }
    let user = String(name.dropFirst(githubPrefix.count))
    guard user.wholeMatch(of: githubUser) != nil else {
        return nil
    }
    return user
}

private func shortKey(_ key: String) -> String {
    guard key.count > 18 else {
        return key
    }
    return "\(key.prefix(10))…\(key.suffix(4))"
}
