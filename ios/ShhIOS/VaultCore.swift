import Foundation
import ShhCore

struct Party: Equatable {
    var name: String
    var key: String
}

struct SampleFile {
    var identity: String
    var file: Data
}

func publicRecipient(for identity: String) throws -> String {
    try goString { ShhcorePublicRecipient(identity, &$0) }
}

func openVault(identity: String, file: Data) throws -> ShhcoreVault {
    var error: NSError?
    let vault = ShhcoreOpen(identity, file, &error)
    if let error {
        throw error
    }
    guard let vault else {
        throw KeyError.unreadable
    }
    return vault
}

func sampleVault() throws -> SampleFile {
    var error: NSError?
    let sample = ShhcoreSample(&error)
    if let error {
        throw error
    }
    guard let sample, let file = sample.file else {
        throw KeyError.unreadable
    }
    return SampleFile(identity: sample.identity, file: file)
}

func readNames(_ vault: ShhcoreVault) throws -> [String] {
    var list: [String] = []
    let count = Int(vault.count())
    list.reserveCapacity(count)
    for index in 0..<count {
        list.append(try secretName(vault, index: index))
    }
    return list
}

func readParties(_ vault: ShhcoreVault) throws -> [Party] {
    var list: [Party] = []
    let count = Int(vault.recipientCount())
    list.reserveCapacity(count)
    for index in 0..<count {
        list.append(Party(
            name: try recipientName(vault, index: index),
            key: try recipientKey(vault, index: index)
        ))
    }
    return list
}

func secretName(_ vault: ShhcoreVault, index: Int) throws -> String {
    try goString { vault.name(index, error: &$0) }
}

func secretValue(_ vault: ShhcoreVault, name: String) throws -> String {
    try goString { vault.secret(name, error: &$0) }
}

func recipientName(_ vault: ShhcoreVault, index: Int) throws -> String {
    try goString { vault.recipientName(index, error: &$0) }
}

func recipientKey(_ vault: ShhcoreVault, index: Int) throws -> String {
    try goString { vault.recipientKey(index, error: &$0) }
}

private func goString(_ body: (inout NSError?) -> String) throws -> String {
    var error: NSError?
    let value = body(&error)
    if let error {
        throw error
    }
    return value
}
