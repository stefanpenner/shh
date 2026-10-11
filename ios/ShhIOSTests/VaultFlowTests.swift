import XCTest
@testable import ShhIOS

@MainActor
final class VaultFlowTests: XCTestCase {
    func testSampleListsNamesAndRecipients() {
        let model = VaultModel()
        model.openSample()
        XCTAssertEqual(model.failure, "")
        XCTAssertTrue(model.unlocked)
        XCTAssertEqual(model.names, ["A_KEY", "B_KEY"])
        XCTAssertEqual(model.fileName, "Sample")
        XCTAssertTrue(model.knownRecipients.contains { $0.name == "https://github.com/alice" })
        XCTAssertTrue(model.knownRecipients.contains { $0.name == "yubikey" })
        XCTAssertEqual(model.parties.map(\.name), [
            "https://github.com/example",
            "https://github.com/octocat",
        ])
        XCTAssertEqual(
            model.parties.first { $0.name == "https://github.com/example" }?.key,
            model.recipient
        )
        XCTAssertFalse(model.recipient.isEmpty)
        model.reveal("B_KEY")
        XCTAssertEqual(model.revealedName, "B_KEY")
        XCTAssertEqual(model.revealedValue, "beta")
        model.hide()
        XCTAssertEqual(model.revealedValue, "")
        XCTAssertEqual(model.revealedName, "")
        XCTAssertEqual(model.names, ["A_KEY", "B_KEY"])
    }

    func testSearchKeepsOneName() {
        let model = VaultModel()
        model.openSample()
        model.query = "a_"
        XCTAssertEqual(model.shown, ["A_KEY"])
    }

    func testOpenWithoutKeyFails() {
        let model = VaultModel()
        model.openData(Data("nope".utf8))
        XCTAssertEqual(model.failure, "Unlock before you open a file.")
        XCTAssertTrue(model.names.isEmpty)
        XCTAssertFalse(model.unlocked)
    }

    func testBadFileKeepsTheKeyAndDropsNames() throws {
        let model = VaultModel()
        let sample = try sampleVault()
        try model.acceptKey(sample.identity)
        model.openData(Data("not a vault".utf8))
        XCTAssertTrue(model.unlocked)
        XCTAssertFalse(model.recipient.isEmpty)
        XCTAssertTrue(model.names.isEmpty)
        XCTAssertTrue(model.parties.isEmpty)
        XCTAssertFalse(model.failure.isEmpty)
    }

    func testLockClearsTheCopiedSecret() {
        let model = VaultModel()
        model.openSample()
        model.reveal("A_KEY")
        model.copyRevealed()
        XCTAssertEqual(UIPasteboard.general.string, "alpha")
        XCTAssertTrue(model.copied)
        model.lock()
        XCTAssertEqual(UIPasteboard.general.string ?? "", "")
        XCTAssertFalse(model.unlocked)
        XCTAssertTrue(model.names.isEmpty)
        XCTAssertTrue(model.parties.isEmpty)
        XCTAssertEqual(model.revealedValue, "")
        XCTAssertEqual(model.recipient, "")
    }

    func testHandedFileWaitsForTheKey() throws {
        let sample = try sampleVault()
        let model = VaultModel()
        model.stage(name: "Demo.env.enc", data: sample.file)
        XCTAssertFalse(model.unlocked)
        XCTAssertEqual(model.handedName, "Demo.env.enc")
        XCTAssertEqual(model.fileName, "")
        XCTAssertTrue(model.names.isEmpty)
        try model.acceptKey(sample.identity)
        XCTAssertEqual(model.failure, "")
        XCTAssertEqual(model.fileName, "Demo.env.enc")
        XCTAssertEqual(model.handedName, "")
        XCTAssertEqual(model.names, ["A_KEY", "B_KEY"])
    }

    func testLockDropsTheHandedFile() throws {
        let sample = try sampleVault()
        let model = VaultModel()
        model.stage(name: "Demo.env.enc", data: sample.file)
        model.lock()
        XCTAssertEqual(model.handedName, "")
        try model.acceptKey(sample.identity)
        XCTAssertEqual(model.fileName, "")
        XCTAssertTrue(model.names.isEmpty)
    }

    func testCancelUnlockKeepsTheHandedFile() throws {
        let sample = try sampleVault()
        let model = VaultModel()
        model.stage(name: "Demo.env.enc", data: sample.file)
        model.cancelUnlock("Face ID was canceled.")
        XCTAssertEqual(model.handedName, "Demo.env.enc")
        XCTAssertEqual(model.failure, "Face ID was canceled.")
        XCTAssertFalse(model.unlocked)
        try model.acceptKey(sample.identity)
        XCTAssertEqual(model.fileName, "Demo.env.enc")
        XCTAssertEqual(model.names, ["A_KEY", "B_KEY"])
    }

    func testWrongKeyHidesTheRecipientList() throws {
        let mine = try sampleVault()
        let other = try sampleVault()
        let model = VaultModel()
        try model.acceptKey(mine.identity)
        model.openData(other.file)
        XCTAssertEqual(model.failure, "Your key is not on this file.")
        XCTAssertFalse(model.failure.contains("age1"))
        XCTAssertTrue(model.unlocked)
        XCTAssertTrue(model.names.isEmpty)
        XCTAssertFalse(model.recipient.isEmpty)
    }

    func testEmptyHandedFileDoesNotWait() {
        let model = VaultModel()
        model.stage(name: "Demo.env.enc", data: Data())
        XCTAssertEqual(model.failure, "This file is empty.")
        XCTAssertEqual(model.handedName, "")
        model.stage(name: "Demo.env.enc", data: Data(count: maxVaultBytes + 1))
        XCTAssertEqual(model.failure, "This file is too large.")
        XCTAssertEqual(model.handedName, "")
    }

    func testSecondOpenDropsTheRevealedValue() throws {
        let model = VaultModel()
        model.openSample()
        model.reveal("A_KEY")
        model.query = "a_"
        model.openData(Data("not a vault".utf8))
        XCTAssertEqual(model.revealedValue, "")
        XCTAssertEqual(model.query, "")
        XCTAssertTrue(model.names.isEmpty)
        XCTAssertFalse(model.failure.isEmpty)
    }
}
