import Foundation
import ShhCore
import UIKit

// VaultModel is the reader. Unlock, open one file, reveal one secret.
@MainActor
final class VaultModel: ObservableObject {
    @Published private(set) var recipient = ""
    @Published private(set) var fileName = ""
    @Published private(set) var handedName = ""
    @Published private(set) var names: [String] = []
    @Published private(set) var parties: [Party] = []
    @Published private(set) var knownRecipients: [Party] = []
    @Published private(set) var revealedName = ""
    @Published private(set) var revealedValue = ""
    @Published private(set) var unlocked = false
    @Published private(set) var copied = false
    @Published var query = ""
    @Published var failure = ""
    @Published var picking = false

    private var identity = ""
    private var pending: PendingFile?
    private var vault: ShhcoreVault?
    private var clip = ClipHold()
    private var clearTask: Task<Void, Never>?

    var shown: [String] {
        matchingNames(names, query: query)
    }

    func unlock() async {
        failure = ""
        do {
            try await OwnerGate.unlock()
            try acceptKey(try CloudKey.identity())
        } catch {
            cancelUnlock(error.localizedDescription)
        }
    }

    func cancelUnlock(_ message: String) {
        seal()
        failure = message
    }

    func acceptKey(_ key: String) throws {
        recipient = try publicRecipient(for: key)
        identity = key
        unlocked = true
        failure = ""
        openPending()
    }

    #if DEBUG
    func openSample() {
        clearPending()
        do {
            let sample = try sampleVault()
            try acceptKey(sample.identity)
            openData(sample.file)
            if failure.isEmpty {
                fileName = "Sample"
                knownRecipients = sampleRecipients(file: parties)
            }
        } catch {
            lock()
            failure = error.localizedDescription
        }
    }
    #endif

    func lock() {
        clearPending()
        seal()
    }

    func openFile(_ url: URL) {
        readAndStage(url)
    }

    func openHanded(_ url: URL) {
        guard isVaultFile(url) else {
            failure = "Open an .env.enc file."
            return
        }
        readAndStage(url)
    }

    func stage(name: String, data: Data) {
        if data.isEmpty {
            failure = "This file is empty."
            return
        }
        if data.count > maxVaultBytes {
            failure = "This file is too large."
            return
        }
        guard !identity.isEmpty else {
            pending = PendingFile(name: name, data: data)
            handedName = name
            failure = ""
            return
        }
        clearPending()
        openData(data)
        if failure.isEmpty {
            fileName = name
        }
    }

    func openData(_ data: Data) {
        dropOpen()
        guard !identity.isEmpty else {
            failure = "Unlock before you open a file."
            return
        }
        do {
            try hold(try openVault(identity: identity, file: data))
        } catch {
            failure = readerFailure(error.localizedDescription)
        }
    }

    func reveal(_ name: String) {
        failure = ""
        copied = false
        guard let vault else {
            return
        }
        do {
            revealedName = name
            revealedValue = try secretValue(vault, name: name)
        } catch {
            hideValue()
            failure = readerFailure(error.localizedDescription)
        }
    }

    func hide() {
        copied = false
        hideValue()
    }

    func copyRevealed() {
        guard !revealedValue.isEmpty else {
            return
        }
        let generation = clip.stage(revealedValue)
        let staged = secretPasteboard(secret: revealedValue, now: Date())
        UIPasteboard.general.setItems(staged.items, options: staged.options)
        copied = true
        clearTask?.cancel()
        clearTask = Task { @MainActor in
            try? await Task.sleep(nanoseconds: UInt64(ClipHold.seconds * 1_000_000_000))
            guard !Task.isCancelled else {
                return
            }
            self.expireCopy(generation)
        }
    }

    private func hold(_ opened: ShhcoreVault) throws {
        let listed: [String]
        let people: [Party]
        do {
            listed = try readNames(opened)
            people = try readParties(opened)
        } catch {
            opened.close()
            throw error
        }
        names = listed
        parties = people
        vault = opened
    }

    private func seal() {
        clearClipboard()
        closeVault()
        identity = ""
        query = ""
        hideValue()
        recipient = ""
        fileName = ""
        knownRecipients = []
        unlocked = false
        picking = false
        copied = false
        failure = ""
    }

    private func readAndStage(_ url: URL) {
        let access = url.startAccessingSecurityScopedResource()
        defer {
            if access {
                url.stopAccessingSecurityScopedResource()
            }
        }
        do {
            let data = try Data(contentsOf: url)
            stage(name: url.lastPathComponent, data: data)
        } catch {
            failure = "Shh cannot read this file."
        }
    }

    private func openPending() {
        guard let pending else { return }
        let file = pending
        clearPending()
        openData(file.data)
        if failure.isEmpty {
            fileName = file.name
        }
    }

    private func clearPending() {
        pending = nil
        handedName = ""
    }

    private func dropOpen() {
        failure = ""
        copied = false
        query = ""
        fileName = ""
        knownRecipients = []
        hideValue()
        closeVault()
    }

    private func closeVault() {
        vault?.close()
        vault = nil
        names = []
        parties = []
    }

    private func hideValue() {
        revealedName = ""
        revealedValue = ""
    }

    private func expireCopy(_ generation: Int) {
        guard clip.value != nil, generation == clip.generation else {
            return
        }
        let board = UIPasteboard.general.string ?? ""
        if clip.expire(generation: generation, pasteboard: board) {
            UIPasteboard.general.items = []
        } else {
            clip.drop(generation: generation)
        }
        copied = false
    }

    private struct PendingFile {
        var name: String
        var data: Data
    }

    private func clearClipboard() {
        clearTask?.cancel()
        expireCopy(clip.generation)
    }
}
