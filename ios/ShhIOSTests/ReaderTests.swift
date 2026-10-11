import UIKit
import UniformTypeIdentifiers
import XCTest
@testable import ShhIOS

final class ReaderTests: XCTestCase {
    func testEmptyQueryKeepsEveryName() {
        XCTAssertEqual(matchingNames(["B", "A"], query: "  "), ["B", "A"])
    }

    func testQueryMatchesOneName() {
        XCTAssertEqual(matchingNames(["API_KEY", "seed_user"], query: "seed"), ["seed_user"])
    }

    func testCopyClearsOnlyTheSameValue() {
        var clip = ClipHold()
        let first = clip.stage("alpha")
        let second = clip.stage("beta")
        XCTAssertFalse(clip.expire(generation: first, pasteboard: "alpha"))
        XCTAssertFalse(clip.expire(generation: second, pasteboard: "other"))
        XCTAssertTrue(clip.expire(generation: second, pasteboard: "beta"))
        XCTAssertFalse(clip.expire(generation: second, pasteboard: "beta"))
    }

    func testSecretCopyStaysOnThisDevice() {
        let now = Date(timeIntervalSince1970: 1_000)
        let staged = secretPasteboard(secret: "alpha", now: now)
        XCTAssertEqual(staged.items.first?[UTType.utf8PlainText.identifier] as? String, "alpha")
        XCTAssertEqual(staged.options[UIPasteboard.OptionsKey.localOnly] as? Bool, true)
        XCTAssertEqual(
            staged.options[UIPasteboard.OptionsKey.expirationDate] as? Date,
            now.addingTimeInterval(30)
        )
    }

    func testVaultNameAcceptsEnvEnc() {
        XCTAssertTrue(isVaultFile(URL(fileURLWithPath: "/tmp/App.env.enc")))
        XCTAssertTrue(isVaultFile(URL(fileURLWithPath: "/tmp/APP.ENV.ENC")))
        XCTAssertTrue(isVaultFile(URL(fileURLWithPath: "/tmp/.env.enc")))
        XCTAssertFalse(isVaultFile(URL(fileURLWithPath: "/tmp/file.enc")))
        XCTAssertFalse(isVaultFile(URL(fileURLWithPath: "/tmp/notes.txt")))
        XCTAssertFalse(isVaultFile(URL(fileURLWithPath: "/tmp/file.env.enc.bak")))
    }

    func testOpenErrorHidesTheKey() {
        let listed = "your key (age1secretsecretsecretsecretsecretsecretsecretsecretsecretsecr) is not in the recipients list\n  authorized: https://github.com/alice"
        let hidden = readerFailure(listed)
        XCTAssertEqual(hidden, "Your key is not on this file.")
        XCTAssertFalse(hidden.contains("age1"))
        XCTAssertFalse(hidden.contains("github.com"))
        XCTAssertEqual(readerFailure("MAC verification failed — file may be tampered"), "This file failed its check.")
        XCTAssertEqual(readerFailure("vault file is empty"), "This file is empty.")
        XCTAssertEqual(readerFailure("no such secret"), "That name is not in this file.")
        XCTAssertEqual(readerFailure("parse encrypted file: AGE-SECRET-KEY-1leak"), "Shh cannot open this file.")
        XCTAssertFalse(readerFailure("AGE-SECRET-KEY-1leak").contains("AGE-SECRET"))
    }

    func testPublicCopyStaysOnThisDevice() {
        let staged = publicPasteboard(key: "age1public")
        XCTAssertEqual(staged.items.first?[UTType.utf8PlainText.identifier] as? String, "age1public")
        XCTAssertEqual(staged.options[UIPasteboard.OptionsKey.localOnly] as? Bool, true)
        XCTAssertNil(staged.options[UIPasteboard.OptionsKey.expirationDate])
    }

    func testCloudQueryUsesTheSharedGroup() {
        let query = CloudKey.query()
        XCTAssertEqual(query[kSecAttrService as String] as? String, "shh-age-key")
        XCTAssertEqual(query[kSecAttrAccount as String] as? String, "shh")
        XCTAssertEqual(query[kSecAttrAccessGroup as String] as? String, "YOUR_PREFIX.shh")
        XCTAssertEqual(query[kSecClass as String] as? String, kSecClassGenericPassword as String)
        XCTAssertTrue(query[kSecAttrSynchronizable as String] as? Bool == true)
    }
}
